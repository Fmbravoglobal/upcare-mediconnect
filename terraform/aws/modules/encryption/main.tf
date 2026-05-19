# ============================================================
# AWS ENCRYPTION MODULE
# KMS (BYOK) | Secrets Manager | Macie PHI Detection
# HIPAA | NIST SP 800-207 | FedRAMP
# ============================================================

# ─────────────────────────────────────────────
# KMS CUSTOMER MANAGED KEY — PHI Encryption
# ─────────────────────────────────────────────
resource "aws_kms_key" "phi_encryption" {
  description              = "UpCare MediConnect — HIPAA PHI encryption key (BYOK)"
  deletion_window_in_days  = 30           # FedRAMP: 30-day deletion window
  enable_key_rotation      = true         # HIPAA/SOC2: automatic annual rotation
  multi_region             = true         # DR support across regions
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RootAccountAccess"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "CloudServicesAccess"
        Effect = "Allow"
        Principal = {
          Service = [
            "s3.amazonaws.com",
            "logs.amazonaws.com",
            "cloudtrail.amazonaws.com",
            "config.amazonaws.com",
            "sns.amazonaws.com",
            "secretsmanager.amazonaws.com"
          ]
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyKeyDeletionWithoutMFA"
        Effect = "Deny"
        Principal = { AWS = "*" }
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DeleteImportedKeyMaterial"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })

  tags = {
    Name       = "${var.name_prefix}-phi-kms-key"
    Compliance = "HIPAA-FedRAMP"
    KeyType    = "PHI-Encryption"
  }
}

resource "aws_kms_alias" "phi_encryption" {
  name          = "alias/${var.name_prefix}-phi-encryption"
  target_key_id = aws_kms_key.phi_encryption.key_id
}

# KMS Key for CloudTrail logs
resource "aws_kms_key" "cloudtrail" {
  description             = "UpCare MediConnect — CloudTrail log encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RootAccess"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "CloudTrailAccess"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name       = "${var.name_prefix}-cloudtrail-kms"
    Compliance = "HIPAA-SOC2"
  }
}

resource "aws_kms_alias" "cloudtrail" {
  name          = "alias/${var.name_prefix}-cloudtrail"
  target_key_id = aws_kms_key.cloudtrail.key_id
}

# ─────────────────────────────────────────────
# SECRETS MANAGER — PHI Credentials Vault
# ─────────────────────────────────────────────
resource "aws_secretsmanager_secret" "ehr_db_credentials" {
  name                    = "${var.name_prefix}/ehr/database-credentials"
  description             = "HIPAA: EHR database credentials — auto-rotated every 30 days"
  kms_key_id              = aws_kms_key.phi_encryption.arn
  recovery_window_in_days = 30

  tags = {
    Name       = "${var.name_prefix}-ehr-db-creds"
    Compliance = "HIPAA"
    DataClass  = "PHI-Credentials"
  }
}

resource "aws_secretsmanager_secret_rotation" "ehr_db_credentials" {
  secret_id           = aws_secretsmanager_secret.ehr_db_credentials.id
  rotation_lambda_arn = var.rotation_lambda_arn

  rotation_rules {
    automatically_after_days = 30  # HIPAA: rotate every 30 days
  }
}

resource "aws_secretsmanager_secret" "api_keys" {
  name                    = "${var.name_prefix}/api/integration-keys"
  description             = "UpCare MediConnect API integration keys"
  kms_key_id              = aws_kms_key.phi_encryption.arn
  recovery_window_in_days = 30

  tags = {
    Name       = "${var.name_prefix}-api-keys"
    Compliance = "SOC2"
  }
}

# ─────────────────────────────────────────────
# ACM — TLS Certificate Management
# ─────────────────────────────────────────────
resource "aws_acm_certificate" "main" {
  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name       = "${var.name_prefix}-tls-cert"
    Compliance = "HIPAA-SOC2"
  }
}

# ─────────────────────────────────────────────
# VARIABLES & OUTPUTS
# ─────────────────────────────────────────────
variable "name_prefix" { type = string }
variable "account_id" { type = string }
variable "enable_macie" { type = bool; default = true }
variable "macie_finding_bucket" { type = string; default = "" }
variable "enable_secrets_manager" { type = bool; default = true }
variable "rotation_lambda_arn" { type = string; default = "" }
variable "domain_name" { type = string; default = "upcare-mediconnect.com" }

output "kms_key_arn" { value = aws_kms_key.phi_encryption.arn; sensitive = true }
output "kms_key_id" { value = aws_kms_key.phi_encryption.key_id }
output "cloudtrail_kms_arn" { value = aws_kms_key.cloudtrail.arn; sensitive = true }
output "ehr_db_secret_arn" { value = aws_secretsmanager_secret.ehr_db_credentials.arn }
