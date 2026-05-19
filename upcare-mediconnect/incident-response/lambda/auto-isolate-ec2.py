#!/usr/bin/env python3
"""
UpCare MediConnect — Auto-Isolate Compromised EC2 Instance
============================================================
Lambda function triggered by GuardDuty/Security Hub findings.
Automatically isolates compromised EC2 instances to prevent
PHI data exfiltration or lateral movement.

Compliance: HIPAA § 164.308(a)(6) | NIST SP 800-61 | SOC 2 CC7.3
Author: Oluwafemi Alabi Okunlola | Fmbravoglobal Holdings Inc.
"""

import json
import boto3
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2")
sns = boto3.client("sns")
ssm = boto3.client("ssm")
cloudwatch = boto3.client("cloudwatch")

ALERT_TOPIC_ARN  = os.environ.get("ALERT_TOPIC_ARN", "")
ISOLATION_SG_ID  = os.environ.get("ISOLATION_SG_ID", "")   # Pre-created deny-all SG
FORENSIC_BUCKET  = os.environ.get("FORENSIC_BUCKET", "")
ENVIRONMENT      = os.environ.get("ENVIRONMENT", "prod")
HIPAA_OFFICER    = os.environ.get("HIPAA_OFFICER_EMAIL", "")


def handler(event, context):
    """
    Main Lambda handler — processes GuardDuty/Security Hub findings
    and automatically isolates the affected EC2 instance.

    Triggered by:
    - GuardDuty: UnauthorizedAccess:EC2/MaliciousIPCaller
    - GuardDuty: Backdoor:EC2/C&CActivity
    - GuardDuty: Trojan:EC2/BlackholeTraffic
    - Security Hub: Critical findings on EC2 instances
    """
    logger.info(f"Incident response triggered: {json.dumps(event, default=str)}")

    instance_id = None
    finding_id  = None
    severity    = "HIGH"
    finding_type = "Unknown"

    # ── Parse GuardDuty finding ────────────────────────────
    if "detail" in event and event.get("source") == "aws.guardduty":
        finding = event["detail"]["findings"][0]
        finding_id   = finding.get("Id", "unknown")
        finding_type = finding.get("Type", "Unknown")
        severity     = finding.get("Severity", {}).get("Label", "HIGH")

        resource = finding.get("Resource", {})
        if resource.get("ResourceType") == "Instance":
            instance_id = resource.get("InstanceDetails", {}).get("InstanceId")

    # ── Parse Security Hub finding ─────────────────────────
    elif "detail" in event and "findings" in event.get("detail", {}):
        finding = event["detail"]["findings"][0]
        finding_id   = finding.get("Id", "unknown")
        finding_type = finding.get("Types", ["Unknown"])[0]
        severity     = finding.get("Severity", {}).get("Label", "HIGH")

        resources = finding.get("Resources", [])
        for r in resources:
            if r.get("Type") == "AwsEc2Instance":
                instance_id = r.get("Id", "").split("/")[-1]
                break

    if not instance_id:
        logger.error("No EC2 instance ID found in event — skipping isolation")
        return {"statusCode": 400, "body": "No instance ID found"}

    logger.info(f"Isolating EC2 instance: {instance_id}")
    logger.info(f"Finding: {finding_type} | Severity: {severity}")

    results = {
        "instance_id":  instance_id,
        "finding_id":   finding_id,
        "finding_type": finding_type,
        "severity":     severity,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "actions":      []
    }

    # ── STEP 1: Get instance details ───────────────────────
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]
        original_sgs = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
        instance_state = instance["State"]["Name"]
        private_ip = instance.get("PrivateIpAddress", "unknown")
        az = instance.get("Placement", {}).get("AvailabilityZone", "unknown")

        logger.info(f"Instance state: {instance_state} | IP: {private_ip} | AZ: {az}")
        logger.info(f"Original Security Groups: {original_sgs}")

        results["instance_details"] = {
            "state": instance_state,
            "private_ip": private_ip,
            "az": az,
            "original_security_groups": original_sgs
        }
    except Exception as e:
        logger.error(f"Failed to describe instance {instance_id}: {e}")
        _send_alert(
            subject=f"⚠️ INCIDENT RESPONSE FAILED — {instance_id}",
            message=f"Unable to retrieve instance details for isolation.\nError: {e}\nManual intervention required.",
            severity="CRITICAL"
        )
        return {"statusCode": 500, "body": f"Failed to describe instance: {e}"}

    if instance_state == "terminated":
        logger.warning(f"Instance {instance_id} already terminated — no isolation needed")
        return {"statusCode": 200, "body": "Instance already terminated"}

    # ── STEP 2: Tag instance as COMPROMISED ────────────────
    try:
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "SecurityStatus",        "Value": "COMPROMISED"},
                {"Key": "IsolationTimestamp",    "Value": datetime.now(timezone.utc).isoformat()},
                {"Key": "FindingId",             "Value": finding_id or "manual"},
                {"Key": "FindingType",           "Value": finding_type},
                {"Key": "IsolatedBy",            "Value": "UpCare-AutoIR-Lambda"},
                {"Key": "OriginalSecurityGroups","Value": ",".join(original_sgs)},
                {"Key": "Compliance",            "Value": "HIPAA-IR"},
                {"Key": "DoNotDelete",           "Value": "true"}
            ]
        )
        results["actions"].append("✅ Instance tagged as COMPROMISED")
        logger.info("Instance tagged successfully")
    except Exception as e:
        logger.warning(f"Failed to tag instance: {e}")

    # ── STEP 3: Apply isolation Security Group (deny-all) ──
    if ISOLATION_SG_ID:
        try:
            ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[ISOLATION_SG_ID]
            )
            results["actions"].append(f"✅ Security Groups replaced with isolation SG: {ISOLATION_SG_ID}")
            logger.info(f"Applied isolation SG: {ISOLATION_SG_ID}")
        except Exception as e:
            logger.error(f"Failed to apply isolation SG: {e}")
            results["actions"].append(f"❌ Failed to apply isolation SG: {e}")
    else:
        # Fallback: revoke all ingress/egress rules from current SGs
        logger.warning("ISOLATION_SG_ID not configured — revoking all SG rules as fallback")
        for sg_id in original_sgs:
            try:
                sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
                if sg.get("IpPermissions"):
                    ec2.revoke_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=sg["IpPermissions"]
                    )
                if sg.get("IpPermissionsEgress"):
                    ec2.revoke_security_group_egress(
                        GroupId=sg_id,
                        IpPermissions=sg["IpPermissionsEgress"]
                    )
                results["actions"].append(f"✅ Revoked all rules from SG: {sg_id}")
            except Exception as e:
                logger.error(f"Failed to modify SG {sg_id}: {e}")

    # ── STEP 4: Disable instance metadata service (IMDS) ──
    try:
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpEndpoint="disabled",
            HttpTokens="required"
        )
        results["actions"].append("✅ IMDS disabled to prevent credential theft")
        logger.info("IMDS disabled on isolated instance")
    except Exception as e:
        logger.warning(f"Failed to disable IMDS: {e}")

    # ── STEP 5: Create EBS snapshot for forensics ──────────
    try:
        describe_resp = ec2.describe_instances(InstanceIds=[instance_id])
        volumes = describe_resp["Reservations"][0]["Instances"][0].get("BlockDeviceMappings", [])
        snapshot_ids = []

        for volume_mapping in volumes:
            vol_id = volume_mapping.get("Ebs", {}).get("VolumeId")
            if vol_id:
                snap = ec2.create_snapshot(
                    VolumeId=vol_id,
                    Description=f"FORENSIC-SNAPSHOT-{instance_id}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
                    TagSpecifications=[{
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "Purpose",    "Value": "ForensicCapture"},
                            {"Key": "InstanceId", "Value": instance_id},
                            {"Key": "FindingId",  "Value": finding_id or "unknown"},
                            {"Key": "Compliance", "Value": "HIPAA-IR"},
                            {"Key": "DoNotDelete","Value": "true"}
                        ]
                    }]
                )
                snapshot_ids.append(snap["SnapshotId"])
                logger.info(f"Snapshot created: {snap['SnapshotId']} for volume {vol_id}")

        results["forensic_snapshots"] = snapshot_ids
        results["actions"].append(f"✅ Forensic snapshots created: {snapshot_ids}")
    except Exception as e:
        logger.error(f"Failed to create forensic snapshots: {e}")
        results["actions"].append(f"⚠️ Snapshot creation failed: {e} — manual forensics required")

    # ── STEP 6: Run forensic SSM commands ──────────────────
    try:
        ssm_resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={
                "commands": [
                    "#!/bin/bash",
                    "echo '=== FORENSIC DATA COLLECTION ==='",
                    f"TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)",
                    f"BUCKET={FORENSIC_BUCKET}",
                    f"PREFIX=forensics/{instance_id}/$TIMESTAMP",
                    "",
                    "# Active network connections",
                    "ss -tulpan > /tmp/network_connections.txt 2>&1",
                    "# Running processes",
                    "ps aux --forest > /tmp/processes.txt 2>&1",
                    "# Recent login history",
                    "last -n 50 > /tmp/login_history.txt 2>&1",
                    "# Crontabs",
                    "crontab -l > /tmp/crontab.txt 2>&1; ls /etc/cron* >> /tmp/crontab.txt 2>&1",
                    "# Auth logs",
                    "tail -500 /var/log/auth.log > /tmp/auth.log 2>&1 || tail -500 /var/log/secure >> /tmp/auth.log 2>&1",
                    "# Unusual SUID files",
                    "find / -perm -4000 -type f 2>/dev/null > /tmp/suid_files.txt",
                    "",
                    "# Upload to S3 forensics bucket",
                    "if [ -n \"$BUCKET\" ]; then",
                    "  aws s3 cp /tmp/network_connections.txt s3://$BUCKET/$PREFIX/network_connections.txt",
                    "  aws s3 cp /tmp/processes.txt s3://$BUCKET/$PREFIX/processes.txt",
                    "  aws s3 cp /tmp/login_history.txt s3://$BUCKET/$PREFIX/login_history.txt",
                    "  aws s3 cp /tmp/crontab.txt s3://$BUCKET/$PREFIX/crontab.txt",
                    "  aws s3 cp /tmp/auth.log s3://$BUCKET/$PREFIX/auth.log",
                    "  aws s3 cp /tmp/suid_files.txt s3://$BUCKET/$PREFIX/suid_files.txt",
                    "  echo 'Forensic collection uploaded to S3'",
                    "fi"
                ]
            },
            TimeoutSeconds=300,
            Comment=f"Forensic collection for HIPAA IR: {instance_id}"
        )
        cmd_id = ssm_resp["Command"]["CommandId"]
        results["forensic_ssm_command_id"] = cmd_id
        results["actions"].append(f"✅ Forensic SSM command dispatched: {cmd_id}")
        logger.info(f"Forensic SSM command sent: {cmd_id}")
    except Exception as e:
        logger.warning(f"SSM forensic collection failed: {e}")
        results["actions"].append(f"⚠️ SSM forensic collection failed: {e}")

    # ── STEP 7: Publish CloudWatch metric ──────────────────
    try:
        cloudwatch.put_metric_data(
            Namespace="UpCare/IncidentResponse",
            MetricData=[{
                "MetricName": "AutoIsolationTriggered",
                "Value": 1,
                "Unit": "Count",
                "Dimensions": [
                    {"Name": "Environment", "Value": ENVIRONMENT},
                    {"Name": "Severity",    "Value": severity}
                ]
            }]
        )
    except Exception as e:
        logger.warning(f"Failed to publish CloudWatch metric: {e}")

    # ── STEP 8: Send HIPAA Security Incident Alert ─────────
    alert_message = f"""
🚨 HIPAA SECURITY INCIDENT — AUTOMATED ISOLATION EXECUTED
{"="*60}

Instance ID   : {instance_id}
Private IP    : {private_ip}
AZ            : {az}
Finding Type  : {finding_type}
Severity      : {severity}
Finding ID    : {finding_id}
Timestamp     : {results['timestamp']}
Environment   : {ENVIRONMENT}

ACTIONS TAKEN:
{chr(10).join(results['actions'])}

FORENSIC SNAPSHOTS:
{json.dumps(results.get('forensic_snapshots', []))}

ORIGINAL SECURITY GROUPS (for rollback):
{json.dumps(original_sgs)}

REQUIRED NEXT STEPS (HIPAA § 164.308(a)(6)):
1. Review GuardDuty finding in AWS Console
2. Analyze forensic snapshots and SSM-collected artifacts
3. Determine if PHI was accessed or exfiltrated
4. If PHI breach suspected — notify HIPAA Privacy Officer within 60 days
5. Complete incident report in ServiceNow IR ticket
6. After investigation — either terminate or rebuild instance from clean AMI

HIPAA BREACH NOTIFICATION OBLIGATIONS:
- Internal report: within 24 hours
- If PHI exposed: notify HHS OCR within 60 days
- If >500 individuals: notify prominent media

DO NOT DELETE FORENSIC SNAPSHOTS — Tagged DoNotDelete=true

Automated by: UpCare MediConnect Security Automation
Compliance: HIPAA § 164.308(a)(6)(ii) | NIST SP 800-61
"""

    _send_alert(
        subject=f"🚨 HIPAA INCIDENT: EC2 Isolated — {instance_id} ({severity})",
        message=alert_message,
        severity=severity
    )

    logger.info(f"Incident response complete for {instance_id}")
    logger.info(f"Actions taken: {results['actions']}")

    return {
        "statusCode": 200,
        "body": json.dumps(results, default=str)
    }


def _send_alert(subject: str, message: str, severity: str = "HIGH"):
    """Send alert via SNS."""
    if not ALERT_TOPIC_ARN:
        logger.warning("ALERT_TOPIC_ARN not configured — alert not sent")
        return
    try:
        sns.publish(
            TopicArn=ALERT_TOPIC_ARN,
            Subject=subject[:100],
            Message=message,
            MessageAttributes={
                "Severity": {
                    "DataType": "String",
                    "StringValue": severity
                }
            }
        )
        logger.info(f"Alert sent: {subject}")
    except Exception as e:
        logger.error(f"Failed to send SNS alert: {e}")
