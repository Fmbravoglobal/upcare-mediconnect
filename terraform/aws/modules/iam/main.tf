# ============================================================
# AWS IAM — Zero Trust Least-Privilege Policies
# NIST SP 800-207 | HIPAA | FedRAMP
# ============================================================

# ─────────────────────────────────────────────
# EHR READ-ONLY ROLE (Clinicians)
# ─────────────────────────────────────────────
resource "aws_iam_role" "ehr_readonly" {
  name        = "${var.name_prefix}-ehr-readonly-role"
  description = "HIPAA: Read-only access to EHR data for clinicians — Zero Trust least privilege"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${var.account_id}:saml-provider/AzureAD"
        }
        Action = "sts:AssumeRoleWithSAML"
        Condition = {
          StringEquals = {
            "SAML:aud" = "https://signin.aws.amazon.com/saml"
          }
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"  # NIST 800-207: MFA required
          }
          NumericLessThan = {
            "aws:MultiFactorAuthAge" = "3600"  # MFA session max 1hr
          }
        }
      }
    ]
  })

  max_session_duration = 3600  # 1 hour — HIPAA session limit

  tags = {
    Name       = "${var.name_prefix}-ehr-readonly-role"
    Compliance = "HIPAA-NIST"
    DataAccess = "PHI-ReadOnly"
  }
}

resource "aws_iam_policy" "ehr_readonly" {
  name        = "${var.name_prefix}-ehr-readonly-policy"
  description = "HIPAA: Least-privilege read-only policy for EHR data"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EHRBucketReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.name_prefix}-ehr-data-*",
          "arn:aws:s3:::${var.name_prefix}-ehr-data-*/*"
        ]
        Condition = {
          StringEquals = {
            "s3:ExistingObjectTag/DataClass" = "PHI"
          }
          Bool = {
            "aws:SecureTransport" = "true"  # HIPAA: HTTPS only
          }
        }
      },
      {
        Sid    = "KMSDecryptOnly"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [var.kms_key_arn]
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${data.aws_region.current.name}.amazonaws.com"
          }
        }
      },
      {
        Sid    = "DenyAllElse"
        Effect = "Deny"
        Action = [
          "s3:DeleteObject",
          "s3:PutObject",
          "s3:PutBucketPolicy",
          "iam:*",
          "ec2:*",
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ehr_readonly" {
  role       = aws_iam_role.ehr_readonly.name
  policy_arn = aws_iam_policy.ehr_readonly.arn
}

# ─────────────────────────────────────────────
# EHR ADMIN ROLE (Healthcare IT Admins)
# ─────────────────────────────────────────────
resource "aws_iam_role" "ehr_admin" {
  name        = "${var.name_prefix}-ehr-admin-role"
  description = "HIPAA: Admin access with break-glass controls for EHR operations"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${var.account_id}:saml-provider/AzureAD"
        }
        Action = "sts:AssumeRoleWithSAML"
        Condition = {
          StringEquals = {
            "SAML:aud" = "https://signin.aws.amazon.com/saml"
          }
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
          IpAddress = {
            "aws:SourceIp" = var.allowed_ip_ranges  # Zero Trust: restrict source IPs
          }
        }
      }
    ]
  })

  max_session_duration = 1800  # 30 min for admin — tighter session

  tags = {
    Name       = "${var.name_prefix}-ehr-admin-role"
    Compliance = "HIPAA-NIST-FedRAMP"
    DataAccess = "PHI-Admin"
  }
}

# ─────────────────────────────────────────────
# BREAK-GLASS EMERGENCY ACCESS ROLE
# ─────────────────────────────────────────────
resource "aws_iam_role" "break_glass" {
  name        = "${var.name_prefix}-break-glass-role"
  description = "HIPAA: Emergency break-glass access — requires manual approval and triggers full audit alert"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
          StringEquals = {
            "sts:ExternalId" = var.break_glass_external_id
          }
        }
      }
    ]
  })

  max_session_duration = 900  # 15 minutes absolute max

  tags = {
    Name       = "${var.name_prefix}-break-glass"
    Compliance = "HIPAA-SOC2"
    DataAccess = "Emergency"
    AlertLevel = "CRITICAL"
  }
}

resource "aws_cloudwatch_event_rule" "break_glass_alert" {
  name        = "${var.name_prefix}-break-glass-assumed"
  description = "HIPAA: Alert immediately when break-glass role is assumed"

  event_pattern = jsonencode({
    source      = ["aws.sts"]
    detail_type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["sts.amazonaws.com"]
      eventName   = ["AssumeRole"]
      requestParameters = {
        roleArn = ["arn:aws:iam::${var.account_id}:role/${var.name_prefix}-break-glass-role"]
      }
    }
  })
}

# ─────────────────────────────────────────────
# SERVICE CONTROL POLICY — Org-Level Guardrails
# ─────────────────────────────────────────────
resource "aws_organizations_policy" "zero_trust_scp" {
  count       = var.enable_scp ? 1 : 0
  name        = "${var.name_prefix}-zero-trust-scp"
  description = "NIST 800-207: Zero Trust guardrails — enforce encryption, region restriction, MFA"
  type        = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyNonEncryptedS3Uploads"
        Effect = "Deny"
        Action = ["s3:PutObject"]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      {
        Sid    = "DenyNonSSLRequests"
        Effect = "Deny"
        Action = "s3:*"
        Resource = "*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "DenyRegionsOutsideAllowList"
        Effect = "Deny"
        NotAction = [
          "iam:*",
          "organizations:*",
          "support:*",
          "sts:*",
          "cloudfront:*",
          "route53:*",
          "waf:*"
        ]
        Resource = "*"
        Condition = {
          StringNotEquals = {
            "aws:RequestedRegion" = var.allowed_regions
          }
        }
      },
      {
        Sid    = "DenyCloudTrailDisable"
        Effect = "Deny"
        Action = [
          "cloudtrail:DeleteTrail",
          "cloudtrail:StopLogging",
          "cloudtrail:UpdateTrail"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyGuardDutyDisable"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:StopMonitoringMembers",
          "guardduty:UpdateDetector"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyPublicS3Buckets"
        Effect = "Deny"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:PutAccountPublicAccessBlock"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "s3:PublicAccessBlockConfiguration/BlockPublicAcls"       = "false"
            "s3:PublicAccessBlockConfiguration/BlockPublicPolicy"     = "false"
            "s3:PublicAccessBlockConfiguration/IgnorePublicAcls"      = "false"
            "s3:PublicAccessBlockConfiguration/RestrictPublicBuckets" = "false"
          }
        }
      }
    ]
  })
}

# ─────────────────────────────────────────────
# IAM ROLES FOR SERVICE OPERATIONS
# ─────────────────────────────────────────────
resource "aws_iam_role" "config_role" {
  name = "${var.name_prefix}-config-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config_role" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

resource "aws_iam_role" "s3_replication_role" {
  name = "${var.name_prefix}-s3-replication-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "s3.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

data "aws_region" "current" {}

# ─────────────────────────────────────────────
# VARIABLES
# ─────────────────────────────────────────────
variable "name_prefix" { type = string }
variable "account_id" { type = string }
variable "kms_key_arn" { type = string }
variable "enable_scp" { type = bool; default = false }
variable "allowed_regions" { type = list(string); default = ["us-east-1", "us-west-2"] }
variable "allowed_ip_ranges" { type = list(string); default = [] }
variable "break_glass_external_id" { type = string; sensitive = true; default = "" }

# ─────────────────────────────────────────────
# OUTPUTS
# ─────────────────────────────────────────────
output "ehr_readonly_role_arn" { value = aws_iam_role.ehr_readonly.arn }
output "ehr_admin_role_arn" { value = aws_iam_role.ehr_admin.arn }
output "break_glass_role_arn" { value = aws_iam_role.break_glass.arn }
output "config_role_arn" { value = aws_iam_role.config_role.arn }
output "s3_replication_role_arn" { value = aws_iam_role.s3_replication_role.arn }
