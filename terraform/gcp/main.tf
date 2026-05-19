# ============================================================
# UpCare MediConnect — GCP Security Baseline
# Security Command Center | VPC SC | Cloud KMS | Cloud Armor
# HIPAA | NIST SP 800-207 | SOC 2 | FedRAMP
# ============================================================

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
  backend "gcs" {
    bucket = "upcare-terraform-state-gcp"
    prefix = "gcp/terraform.tfstate"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

# ─────────────────────────────────────────────
# LOCAL VARIABLES
# ─────────────────────────────────────────────
locals {
  name_prefix = "upcare-${var.environment}"
  common_labels = {
    project     = "upcare-mediconnect"
    environment = var.environment
    compliance  = "hipaa-nist-soc2-fedramp"
    managed_by  = "terraform"
    owner       = "fmbravoglobal-cloudsecurity"
    data_class  = "phi"
  }
}

data "google_project" "current" {}

# ─────────────────────────────────────────────
# MODULE: IAM & ORG POLICY
# ─────────────────────────────────────────────
module "iam" {
  source = "./modules/iam"

  project_id  = var.project_id
  name_prefix = local.name_prefix
  org_id      = var.org_id
}

# ─────────────────────────────────────────────
# MODULE: CLOUD KMS (CMEK)
# ─────────────────────────────────────────────
module "encryption" {
  source = "./modules/encryption"

  project_id  = var.project_id
  name_prefix = local.name_prefix
  region      = var.region
  labels      = local.common_labels
}

# ─────────────────────────────────────────────
# MODULE: VPC SERVICE CONTROLS
# ─────────────────────────────────────────────
module "network" {
  source = "./modules/network"

  project_id    = var.project_id
  name_prefix   = local.name_prefix
  region        = var.region
  network_cidr  = var.network_cidr
  org_id        = var.org_id
}

# ─────────────────────────────────────────────
# MODULE: LOGGING & SIEM
# ─────────────────────────────────────────────
module "logging" {
  source = "./modules/logging"

  project_id        = var.project_id
  name_prefix       = local.name_prefix
  region            = var.region
  kms_key_id        = module.encryption.kms_key_id
  log_bucket_name   = "${local.name_prefix}-audit-logs"
  retention_days    = 365
}

# ─────────────────────────────────────────────
# SECURITY COMMAND CENTER
# ─────────────────────────────────────────────
resource "google_scc_source" "upcare_findings" {
  provider     = google-beta
  display_name = "UpCare MediConnect Security"
  organization = var.org_id
  description  = "Custom security findings for UpCare MediConnect healthcare platform"
}

resource "google_scc_notification_config" "phi_alerts" {
  provider        = google-beta
  config_id       = "${local.name_prefix}-phi-alerts"
  organization    = var.org_id
  description     = "HIPAA: Notify on all critical and high severity PHI-related findings"
  pubsub_topic    = google_pubsub_topic.security_alerts.id

  streaming_config {
    filter = "state = \"ACTIVE\" AND severity = \"CRITICAL\" OR severity = \"HIGH\""
  }
}

# ─────────────────────────────────────────────
# GCP ORG POLICY CONSTRAINTS — Zero Trust
# ─────────────────────────────────────────────
resource "google_org_policy_policy" "restrict_public_ip" {
  name   = "organizations/${var.org_id}/policies/compute.restrictCloudSQLInstances"
  parent = "organizations/${var.org_id}"

  spec {
    rules {
      deny_all = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "require_os_login" {
  name   = "organizations/${var.org_id}/policies/compute.requireOsLogin"
  parent = "organizations/${var.org_id}"

  spec {
    rules {
      enforce = "TRUE"
    }
  }
}

resource "google_org_policy_policy" "restrict_vm_external_ip" {
  name   = "organizations/${var.org_id}/policies/compute.vmExternalIpAccess"
  parent = "organizations/${var.org_id}"

  spec {
    rules {
      deny_all = "TRUE"  # NIST 800-207: No external IPs on VMs
    }
  }
}

resource "google_org_policy_policy" "restrict_service_account_creation" {
  name   = "organizations/${var.org_id}/policies/iam.disableServiceAccountCreation"
  parent = "organizations/${var.org_id}"

  spec {
    rules {
      enforce = "TRUE"  # Centralize SA creation
    }
  }
}

resource "google_org_policy_policy" "restrict_domain" {
  name   = "organizations/${var.org_id}/policies/iam.allowedPolicyMemberDomains"
  parent = "organizations/${var.org_id}"

  spec {
    rules {
      values {
        allowed_values = [var.allowed_domain]  # Zero Trust: restrict to org domain
      }
    }
  }
}

resource "google_org_policy_policy" "require_cmek" {
  name   = "organizations/${var.org_id}/policies/gcp.restrictNonCmekServices"
  parent = "organizations/${var.org_id}"

  spec {
    rules {
      deny_all = "TRUE"  # HIPAA: All services must use CMEK
    }
  }
}

# ─────────────────────────────────────────────
# CLOUD ARMOR WAF — Telehealth API Protection
# ─────────────────────────────────────────────
resource "google_compute_security_policy" "telehealth_waf" {
  name        = "${local.name_prefix}-telehealth-waf"
  description = "WAF policy for UpCare telehealth APIs — OWASP Top 10 + Healthcare rules"
  project     = var.project_id

  # OWASP Core Rule Set
  rule {
    action   = "deny(403)"
    priority = 1000
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
      }
    }
    description = "Block XSS attacks"
  }

  rule {
    action   = "deny(403)"
    priority = 1001
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }
    description = "Block SQL injection"
  }

  rule {
    action   = "deny(403)"
    priority = 1002
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('lfi-v33-stable')"
      }
    }
    description = "Block local file inclusion"
  }

  rule {
    action   = "deny(403)"
    priority = 1003
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rfi-v33-stable')"
      }
    }
    description = "Block remote file inclusion"
  }

  # Rate Limiting — PHI API endpoints
  rule {
    action   = "throttle"
    priority = 2000
    match {
      expr {
        expression = "request.path.matches('/api/v1/ehr/*')"
      }
    }
    description = "Rate limit EHR API — prevent data exfiltration"
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      rate_limit_threshold {
        count        = 100
        interval_sec = 60
      }
    }
  }

  # Geo-restriction — US only for PHI access
  rule {
    action   = "deny(403)"
    priority = 3000
    match {
      expr {
        expression = "origin.region_code != 'US'"
      }
    }
    description = "HIPAA: Restrict PHI access to US only"
  }

  # Allow all other traffic
  rule {
    action   = "allow"
    priority = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default allow rule"
  }

  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable          = true
      rule_visibility = "STANDARD"
    }
  }
}

# ─────────────────────────────────────────────
# BIGQUERY — PHI Analytics with CMEK
# ─────────────────────────────────────────────
resource "google_bigquery_dataset" "phi_analytics" {
  dataset_id                  = "${replace(local.name_prefix, "-", "_")}_phi_analytics"
  friendly_name               = "UpCare PHI Analytics"
  description                 = "HIPAA: Encrypted predictive analytics dataset for PHI processing"
  location                    = var.region
  delete_contents_on_destroy  = false

  default_encryption_configuration {
    kms_key_name = module.encryption.kms_key_id
  }

  access {
    role          = "OWNER"
    special_group = "projectOwners"
  }

  access {
    role          = "READER"
    iam_member    = "serviceAccount:${module.iam.analytics_sa_email}"
  }

  labels = local.common_labels
}

# ─────────────────────────────────────────────
# PUBSUB — Security Alert Pipeline
# ─────────────────────────────────────────────
resource "google_pubsub_topic" "security_alerts" {
  name    = "${local.name_prefix}-security-alerts"
  project = var.project_id

  kms_key_name = module.encryption.kms_key_id

  labels = local.common_labels
}

resource "google_pubsub_topic_iam_binding" "scc_publish" {
  project = var.project_id
  topic   = google_pubsub_topic.security_alerts.name
  role    = "roles/pubsub.publisher"
  members = ["serviceAccount:security-center-notifications@system.gserviceaccount.com"]
}

# ─────────────────────────────────────────────
# VARIABLES
# ─────────────────────────────────────────────
variable "project_id" { type = string }
variable "org_id" { type = string }
variable "region" { type = string; default = "us-central1" }
variable "environment" { type = string; default = "prod" }
variable "network_cidr" { type = string; default = "10.2.0.0/16" }
variable "allowed_domain" { type = string; default = "upcare-mediconnect.com" }

# ─────────────────────────────────────────────
# OUTPUTS
# ─────────────────────────────────────────────
output "kms_key_id" { value = module.encryption.kms_key_id; sensitive = true }
output "scc_source_name" { value = google_scc_source.upcare_findings.name }
output "phi_dataset_id" { value = google_bigquery_dataset.phi_analytics.dataset_id }
output "waf_policy_id" { value = google_compute_security_policy.telehealth_waf.id }
