# 🚨 PHI Data Breach Incident Response Playbook
## UpCare MediConnect — HIPAA Incident Response
**Classification:** RESTRICTED — Security Operations Only  
**Compliance:** HIPAA § 164.308(a)(6) | NIST SP 800-61 Rev.2 | HHS Breach Notification Rule  
**Version:** 1.0 | Owner: Cloud Security Team | Fmbravoglobal Holdings Inc.

---

## 📋 Overview

This playbook defines the step-by-step response procedure for a suspected or confirmed Protected Health Information (PHI) data breach on the UpCare MediConnect platform. All steps are time-boxed per HIPAA Breach Notification Rule requirements.

**Mandatory Escalation:** Any suspected PHI breach must be escalated to the HIPAA Privacy Officer within **1 hour** of detection.

---

## ⏱️ Response Timeline (HIPAA Requirements)

| Timeline | Requirement | Owner |
|----------|-------------|-------|
| T+0 | Detection & triage begin | SOC Analyst |
| T+1hr | Escalate to HIPAA Privacy Officer | SOC Lead |
| T+4hr | Initial scope assessment complete | IR Team |
| T+24hr | Internal incident report filed | CISO |
| T+72hr | Law enforcement notified (if applicable) | Legal/CISO |
| T+60 days | HHS OCR notification (if breach confirmed) | Privacy Officer |
| T+60 days | Individual notification (if >500 affected) | Privacy Officer + Legal |

---

## 🔍 Phase 1: Detection & Identification (T+0 to T+1hr)

### 1.1 Potential Detection Sources
- Amazon Macie PHI detection alert
- GuardDuty: `Exfiltration:S3/ObjectRead.Unusual`
- CloudTrail: Bulk S3 GetObject from unknown IP
- Azure Sentinel: DLP policy violation
- GCP Security Command Center: BigQuery PHI dataset anomaly
- User report / Help desk ticket

### 1.2 Initial Triage Checklist
```bash
# Step 1: Identify affected resources
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=ResourceName,AttributeValue=<BUCKET_NAME> \
  --start-time $(date -d '-24 hours' --iso-8601=seconds) \
  --query 'Events[*].{User:Username,Action:EventName,Time:EventTime,Source:SourceIPAddress}'

# Step 2: Check for unusual S3 access patterns
aws s3api list-objects-v2 \
  --bucket <EHR_BUCKET> \
  --query 'Contents[?LastModified>=`<TIMESTAMP>`]'

# Step 3: Check Macie findings
aws macie2 list-findings \
  --finding-criteria '{"criterion":{"severity.description":{"eq":["High","Critical"]}}}' \
  --query 'findingIds'

# Step 4: Review GuardDuty findings
aws guardduty list-findings \
  --detector-id <DETECTOR_ID> \
  --finding-criteria '{"Criterion":{"service.action.actionType":{"Eq":["AWS_API_CALL"]}}}' 

# Step 5: Identify source IP and user
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=SourceIPAddress,AttributeValue=<SUSPICIOUS_IP> \
  --start-time <TIMESTAMP>
```

### 1.3 Severity Classification

| Severity | Criteria | Response SLA |
|----------|----------|--------------|
| **P1 — Critical** | Confirmed mass PHI exfiltration (>500 records) | Immediate — 15 min |
| **P2 — High** | Suspected PHI access by unauthorized user | 1 hour |
| **P3 — Medium** | Anomalous PHI access (authorized user, unusual pattern) | 4 hours |
| **P4 — Low** | Policy violation with no PHI confirmed accessed | 24 hours |

---

## 🔒 Phase 2: Containment (T+1hr to T+4hr)

### 2.1 Immediate Containment Actions

```bash
# ── CONTAIN: Block compromised IAM user/role ──────────────
# Revoke all active sessions
aws iam create-policy-version \
  --policy-arn <USER_POLICY_ARN> \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}' \
  --set-as-default

# Deactivate access keys
aws iam update-access-key \
  --access-key-id <KEY_ID> \
  --status Inactive \
  --user-name <USERNAME>

# Revoke all active console sessions
aws iam delete-login-profile --user-name <USERNAME>

# ── CONTAIN: Block source IP at WAF ──────────────────────
aws wafv2 update-ip-set \
  --scope REGIONAL \
  --id <BLOCK_LIST_ID> \
  --addresses '["<SUSPICIOUS_IP>/32"]' \
  --lock-token <LOCK_TOKEN>

# ── CONTAIN: Block S3 bucket access ──────────────────────
# Apply bucket policy to block all except incident response role
cat > /tmp/lockdown-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllExceptIR",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::<BUCKET>", "arn:aws:s3:::<BUCKET>/*"],
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::<ACCOUNT>:role/upcare-prod-ir-role"
        }
      }
    }
  ]
}
EOF

aws s3api put-bucket-policy \
  --bucket <EHR_BUCKET> \
  --policy file:///tmp/lockdown-policy.json

# ── CONTAIN: Enable S3 Object Lock (prevent deletion of evidence)
aws s3api put-object-lock-configuration \
  --bucket <EHR_BUCKET> \
  --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"GOVERNANCE","Days":2555}}}'
```

### 2.2 Azure Containment

```bash
# Disable compromised Azure AD user
az ad user update --id <USER_UPN> --account-enabled false

# Revoke all refresh tokens
az ad user revoke-sessions --id <USER_UPN>

# Apply Conditional Access block policy
az rest --method POST \
  --uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  --body '{"displayName":"INCIDENT-BLOCK-<USER>","state":"enabled","conditions":{"users":{"includeUsers":["<USER_ID>"]}},"grantControls":{"operator":"OR","builtInControls":["block"]}}'
```

### 2.3 GCP Containment

```bash
# Disable GCP service account
gcloud iam service-accounts disable <SA_EMAIL>

# Revoke OAuth tokens
gcloud auth revoke <USER_EMAIL>

# Apply org policy to restrict BigQuery access
gcloud resource-manager org-policies set-policy \
  --organization=<ORG_ID> \
  emergency-bq-restriction.yaml
```

---

## 🔬 Phase 3: Eradication & Evidence Preservation (T+4hr to T+24hr)

### 3.1 Evidence Collection

```bash
# Preserve CloudTrail logs
aws cloudtrail get-trail-status --name <TRAIL_NAME>
aws s3 sync s3://<CLOUDTRAIL_BUCKET>/AWSLogs/ /tmp/evidence/cloudtrail/

# Collect VPC flow logs
aws logs get-log-events \
  --log-group-name /aws/vpc/flowlogs \
  --log-stream-name <STREAM> \
  --start-time <EPOCH_MS> \
  --end-time <EPOCH_MS> \
  > /tmp/evidence/vpc_flow_logs.json

# Document all S3 access to affected objects
aws s3api list-object-versions \
  --bucket <EHR_BUCKET> \
  --prefix <PHI_PREFIX> \
  > /tmp/evidence/object_versions.json

# Create evidence manifest
sha256sum /tmp/evidence/* > /tmp/evidence/MANIFEST.sha256
```

### 3.2 PHI Scope Determination

```bash
# Identify which PHI objects were accessed
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time <BREACH_START> \
  --end-time <BREACH_END> \
  --query 'Events[*].{User:Username,Resource:Resources[0].ResourceName,Time:EventTime,IP:CloudTrailEvent}' \
  > /tmp/phi_access_log.json

# Count potentially affected individuals
python3 << 'EOF'
import json

with open('/tmp/phi_access_log.json') as f:
    events = json.load(f)

# Extract patient identifiers from accessed object paths
# Assumes naming convention: ehr/patient-<MRN>/record.json
affected_mrns = set()
for event in events:
    resource = event.get('Resource', '')
    if '/patient-' in resource:
        mrn = resource.split('/patient-')[1].split('/')[0]
        affected_mrns.add(mrn)

print(f"Potentially affected patients: {len(affected_mrns)}")
print(f"Patient MRNs: {list(affected_mrns)[:10]}...")  # First 10 for report
EOF
```

---

## 📣 Phase 4: HIPAA Breach Notification (T+24hr to T+60 days)

### 4.1 Internal Notification Checklist

- [ ] HIPAA Privacy Officer notified within 1 hour
- [ ] CISO briefed within 4 hours
- [ ] Legal counsel engaged
- [ ] Executive leadership notified (P1/P2 severity)
- [ ] Business Associate Agreement (BAA) partners notified if applicable
- [ ] Internal incident report filed in GRC system

### 4.2 HHS OCR Notification (if breach confirmed)

**Required within 60 days if PHI of 500+ individuals exposed:**

Submit via: https://ocrportal.hhs.gov/ocr/breach/wizard_breach.jsf

Required information:
- Nature of breach and PHI types involved
- Number of affected individuals
- Description of what happened
- PHI categories involved (name, SSN, DOB, diagnosis, etc.)
- Steps taken to investigate
- Mitigation actions taken
- Future prevention measures

### 4.3 Individual Notification Template

```
Subject: Notice of Data Security Incident — UpCare MediConnect

Dear [Patient Name],

We are writing to inform you of a data security incident that may have 
involved your protected health information (PHI).

WHAT HAPPENED: [Brief, plain-language description]

WHEN IT OCCURRED: [Date range]

WHAT INFORMATION WAS INVOLVED: [List of PHI types]

WHAT WE ARE DOING: [Mitigation steps taken]

WHAT YOU CAN DO: [Steps individual can take]

For questions, contact our HIPAA Privacy Officer:
Email: privacy@upcare-mediconnect.com
Phone: 1-800-XXX-XXXX

We sincerely apologize for this incident.

[HIPAA Privacy Officer Name]
UpCare MediConnect
```

---

## 🔄 Phase 5: Recovery & Post-Incident Review

### 5.1 Recovery Steps

```bash
# Restore from clean backup (verify backup integrity first)
aws backup start-restore-job \
  --recovery-point-arn <BACKUP_ARN> \
  --iam-role-arn <IR_ROLE_ARN> \
  --metadata '{"targetInstanceId":"<NEW_INSTANCE_ID>"}'

# Re-enable S3 bucket with clean policy
aws s3api delete-bucket-policy --bucket <EHR_BUCKET>
# Re-apply original policy from Terraform

# Re-enable IAM user after password reset + MFA re-enrollment
aws iam update-login-profile --user-name <USERNAME> --password-reset-required

# Verify GuardDuty and Macie are scanning
aws guardduty list-detectors
aws macie2 get-macie-session
```

### 5.2 Post-Incident Review Checklist (Within 14 days)

- [ ] Root cause analysis completed
- [ ] Attack vector documented and closed
- [ ] Detection timeline reviewed (MTTD/MTTR measured)
- [ ] HIPAA risk assessment updated
- [ ] Security controls updated in Terraform/CloudFormation
- [ ] Incident playbook updated with lessons learned
- [ ] Staff security awareness training updated if applicable
- [ ] Pen test scheduled if new attack vector discovered

---

## 📊 Incident Metrics to Track

| Metric | Target | HIPAA Requirement |
|--------|--------|-------------------|
| MTTD (Mean Time to Detect) | < 1 hour | Reasonable safeguards |
| MTTI (Mean Time to Isolate) | < 2 hours | Incident response plan |
| MTTR (Mean Time to Remediate) | < 24 hours | Business continuity |
| Notification to Privacy Officer | < 1 hour | Internal policy |
| HHS OCR Notification | < 60 days | 45 CFR § 164.408 |

---

## 📞 Emergency Contacts

| Role | Contact | Escalation Trigger |
|------|---------|--------------------|
| SOC Lead | security@upcare-mediconnect.com | Any P1/P2 |
| HIPAA Privacy Officer | privacy@upcare-mediconnect.com | Any suspected PHI breach |
| CISO | ciso@upcare-mediconnect.com | P1 only |
| Legal Counsel | legal@upcare-mediconnect.com | Any confirmed breach |
| AWS Support | Enterprise TAM | AWS infrastructure issues |
| FBI Cyber Division | 1-800-CALL-FBI | Ransomware/nation-state |

---

*Last Updated: 2026 | Version 1.0 | Fmbravoglobal Holdings Inc. — Cloud Security Practice*
