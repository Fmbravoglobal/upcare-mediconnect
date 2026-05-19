# ============================================================
# UpCare MediConnect — AWS Multi-Cloud Security Baseline
# Compliance: HIPAA | NIST SP 800-207 | SOC 2 | FedRAMP
# Author: Oluwafemi Alabi Okunlola | Fmbravoglobal Holdings Inc.
# ============================================================

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket         = "upcare-terraform-state"
    key            = "aws/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "upcare-terraform-lock"
    kms_key_id     = "alias/upcare-terraform-state-key"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project        = "UpCare-MediConnect"
      Environment    = var.environment
      Compliance     = "HIPAA-NIST-SOC2-FedRAMP"
      ManagedBy      = "Terraform"
      Owner          = "Fmbravoglobal-CloudSecurity"
      DataClass      = "PHI"
      CostCenter     = "CloudSecurity"
    }
  }
}

# ─────────────────────────────────────────────
# LOCAL VARIABLES
# ─────────────────────────────────────────────
locals {
  name_prefix = "upcare-${var.environment}"
  account_id  = data.aws_caller_identity.current.account_id
  region      = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ─────────────────────────────────────────────
# MODULE: VPC & ZERO TRUST NETWORK
# ─────────────────────────────────────────────
module "network" {
  source = "./modules/network"

  name_prefix        = local.name_prefix
  vpc_cidr           = var.vpc_cidr
  private_subnets    = var.private_subnets
  public_subnets     = var.public_subnets
  availability_zones = var.availability_zones
  enable_flow_logs   = true
  flow_log_bucket    = module.logging.flow_log_bucket_arn
}

# ─────────────────────────────────────────────
# MODULE: IAM & ZERO TRUST ACCESS CONTROL
# ─────────────────────────────────────────────
module "iam" {
  source = "./modules/iam"

  name_prefix        = local.name_prefix
  account_id         = local.account_id
  kms_key_arn        = module.encryption.kms_key_arn
  enable_scp         = var.enable_scp
  allowed_regions    = var.allowed_regions
}

# ─────────────────────────────────────────────
# MODULE: ENCRYPTION (KMS + Secrets Manager + Macie)
# ─────────────────────────────────────────────
module "encryption" {
  source = "./modules/encryption"

  name_prefix           = local.name_prefix
  account_id            = local.account_id
  enable_macie          = true
  macie_finding_bucket  = module.logging.security_findings_bucket
  enable_secrets_manager = true
}

# ─────────────────────────────────────────────
# MODULE: LOGGING & AUDIT (CloudTrail + Config + Security Hub)
# ─────────────────────────────────────────────
module "logging" {
  source = "./modules/logging"

  name_prefix          = local.name_prefix
  account_id           = local.account_id
  region               = local.region
  kms_key_arn          = module.encryption.kms_key_arn
  enable_cloudtrail    = true
  enable_config        = true
  enable_security_hub  = true
  enable_guardduty     = true
  security_hub_standards = [
    "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0",
    "arn:aws:securityhub:${local.region}::standards/aws-foundational-security-best-practices/v/1.0.0",
    "arn:aws:securityhub:${local.region}::standards/nist-800-53/v/5.0.0",
    "arn:aws:securityhub:${local.region}::standards/pci-dss/v/3.2.1"
  ]
}

# ─────────────────────────────────────────────
# AWS GUARDDUTY — Threat Detection
# ─────────────────────────────────────────────
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Name       = "${local.name_prefix}-guardduty"
    Compliance = "HIPAA-SOC2"
  }
}

# GuardDuty -> SNS -> Incident Response
resource "aws_guardduty_publishing_destination" "findings" {
  detector_id     = aws_guardduty_detector.main.id
  destination_arn = aws_s3_bucket.security_findings.arn
  kms_key_arn     = module.encryption.kms_key_arn
}

# ─────────────────────────────────────────────
# AWS SECURITY HUB — Centralized Security Posture
# ─────────────────────────────────────────────
resource "aws_securityhub_account" "main" {
  enable_default_standards = false
  auto_enable_controls     = true
  control_finding_generator = "SECURITY_CONTROL"
}

resource "aws_securityhub_standards_subscription" "hipaa_nist" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:${local.region}::standards/nist-800-53/v/5.0.0"
}

resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.main]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.4.0"
}

# ─────────────────────────────────────────────
# AMAZON MACIE — PHI Data Discovery
# ─────────────────────────────────────────────
resource "aws_macie2_account" "main" {
  finding_publishing_frequency = "FIFTEEN_MINUTES"
  status                       = "ENABLED"
}

resource "aws_macie2_classification_job" "phi_discovery" {
  depends_on = [aws_macie2_account.main]
  job_type   = "SCHEDULED_JOB"
  name       = "${local.name_prefix}-phi-discovery"

  schedule_frequency {
    daily_schedule = {}
  }

  s3_job_definition {
    bucket_definitions {
      account_id = local.account_id
      buckets    = [aws_s3_bucket.ehr_data.bucket]
    }
    scoping {
      includes {
        and {
          simple_scope_term {
            comparator = "STARTS_WITH"
            key        = "OBJECT_EXTENSION"
            values     = ["json", "csv", "xml", "hl7", "fhir"]
          }
        }
      }
    }
  }

  tags = {
    Name       = "${local.name_prefix}-macie-phi-job"
    Compliance = "HIPAA"
  }
}

# ─────────────────────────────────────────────
# S3 BUCKETS — HIPAA-Compliant EHR Storage
# ─────────────────────────────────────────────
resource "aws_s3_bucket" "ehr_data" {
  bucket        = "${local.name_prefix}-ehr-data-${local.account_id}"
  force_destroy = false

  tags = {
    Name        = "${local.name_prefix}-ehr-data"
    DataClass   = "PHI"
    Compliance  = "HIPAA"
  }
}

resource "aws_s3_bucket_versioning" "ehr_data" {
  bucket = aws_s3_bucket.ehr_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ehr_data" {
  bucket = aws_s3_bucket.ehr_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = module.encryption.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "ehr_data" {
  bucket                  = aws_s3_bucket.ehr_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_logging" "ehr_data" {
  bucket        = aws_s3_bucket.ehr_data.id
  target_bucket = module.logging.access_log_bucket_id
  target_prefix = "ehr-data-access-logs/"
}

resource "aws_s3_bucket_replication_configuration" "ehr_data" {
  depends_on = [aws_s3_bucket_versioning.ehr_data]
  bucket = aws_s3_bucket.ehr_data.id
  role   = module.iam.s3_replication_role_arn

  rule {
    id     = "ehr-dr-replication"
    status = "Enabled"
    destination {
      bucket        = aws_s3_bucket.ehr_data_dr.arn
      storage_class = "STANDARD_IA"
      encryption_configuration {
        replica_kms_key_id = module.encryption.kms_key_arn
      }
    }
    source_selection_criteria {
      sse_kms_encrypted_objects {
        status = "Enabled"
      }
    }
  }
}

resource "aws_s3_bucket" "ehr_data_dr" {
  bucket   = "${local.name_prefix}-ehr-data-dr-${local.account_id}"
  provider = aws.dr_region
}

resource "aws_s3_bucket" "security_findings" {
  bucket = "${local.name_prefix}-security-findings-${local.account_id}"
}

resource "aws_s3_bucket_public_access_block" "security_findings" {
  bucket                  = aws_s3_bucket.security_findings.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ─────────────────────────────────────────────
# AWS CONFIG — Continuous Compliance Monitoring
# ─────────────────────────────────────────────
resource "aws_config_configuration_recorder" "main" {
  name     = "${local.name_prefix}-config-recorder"
  role_arn = module.iam.config_role_arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_config_rule" "hipaa_encryption" {
  name        = "${local.name_prefix}-s3-encryption-required"
  description = "HIPAA: Ensure S3 buckets have server-side encryption enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "mfa_enabled_root" {
  name        = "${local.name_prefix}-mfa-root-account"
  description = "NIST 800-207: MFA must be enabled for root account"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "no_unrestricted_ssh" {
  name        = "${local.name_prefix}-no-unrestricted-ssh"
  description = "SOC2: Restrict SSH access from 0.0.0.0/0"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = jsonencode({
    blockedPort1 = "22"
    blockedPort2 = "3389"
  })

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name        = "${local.name_prefix}-cloudtrail-enabled"
  description = "FedRAMP: CloudTrail must be enabled in all regions"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# ─────────────────────────────────────────────
# CLOUDWATCH ALARMS — Security Metrics
# ─────────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "${local.name_prefix}-root-login-alert"
  alarm_description   = "HIPAA/FedRAMP: Alert on root account console login"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RootAccountUsage"
  namespace           = "CloudTrailMetrics"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
  alarm_name          = "${local.name_prefix}-unauthorized-api-calls"
  alarm_description   = "SOC2: Alert on unauthorized API calls"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "CloudTrailMetrics"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "mfa_disabled" {
  alarm_name          = "${local.name_prefix}-mfa-disabled-alert"
  alarm_description   = "NIST 800-207: Alert when IAM user MFA is disabled"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "MFADisabled"
  namespace           = "CloudTrailMetrics"
  period              = "60"
  statistic           = "Sum"
  threshold           = "1"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# ─────────────────────────────────────────────
# SNS — Security Alert Notifications
# ─────────────────────────────────────────────
resource "aws_sns_topic" "security_alerts" {
  name              = "${local.name_prefix}-security-alerts"
  kms_master_key_id = module.encryption.kms_key_arn

  tags = {
    Name = "${local.name_prefix}-security-alerts"
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn = aws_sns_topic.security_alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.security_alerts.arn
      }
    ]
  })
}

# ─────────────────────────────────────────────
# OUTPUTS
# ─────────────────────────────────────────────
output "vpc_id" {
  description = "VPC ID for UpCare MediConnect"
  value       = module.network.vpc_id
}

output "kms_key_arn" {
  description = "KMS key ARN for PHI encryption"
  value       = module.encryption.kms_key_arn
  sensitive   = true
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.main.id
}

output "security_hub_arn" {
  description = "Security Hub ARN"
  value       = aws_securityhub_account.main.id
}

output "ehr_bucket_name" {
  description = "HIPAA-compliant EHR S3 bucket name"
  value       = aws_s3_bucket.ehr_data.bucket
  sensitive   = true
}
