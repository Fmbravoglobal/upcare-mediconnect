# ============================================================
# UpCare MediConnect — Azure Security Baseline
# Azure AD | Sentinel SIEM | Defender for Cloud | Key Vault
# HIPAA | NIST SP 800-207 | SOC 2 | FedRAMP
# ============================================================

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
  }
  backend "azurerm" {
    resource_group_name  = "upcare-terraform-state-rg"
    storage_account_name = "upcaretfstate"
    container_name       = "tfstate"
    key                  = "azure/terraform.tfstate"
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy               = false  # HIPAA: retain for 90 days
      recover_soft_deleted_key_vaults            = true
      purge_soft_deleted_secrets_on_destroy      = false
      purge_soft_deleted_certificates_on_destroy = false
    }
    resource_group {
      prevent_deletion_if_contains_resources = true  # SOC2: prevent accidental deletion
    }
  }
  subscription_id = var.subscription_id
  tenant_id       = var.tenant_id
}

provider "azuread" {
  tenant_id = var.tenant_id
}

# ─────────────────────────────────────────────
# DATA SOURCES
# ─────────────────────────────────────────────
data "azurerm_client_config" "current" {}
data "azurerm_subscription" "current" {}

locals {
  name_prefix = "upcare-${var.environment}"
  common_tags = {
    Project     = "UpCare-MediConnect"
    Environment = var.environment
    Compliance  = "HIPAA-NIST-SOC2-FedRAMP"
    ManagedBy   = "Terraform"
    Owner       = "Fmbravoglobal-CloudSecurity"
    DataClass   = "PHI"
  }
}

# ─────────────────────────────────────────────
# RESOURCE GROUPS
# ─────────────────────────────────────────────
resource "azurerm_resource_group" "security" {
  name     = "${local.name_prefix}-security-rg"
  location = var.location
  tags     = local.common_tags
}

resource "azurerm_resource_group" "identity" {
  name     = "${local.name_prefix}-identity-rg"
  location = var.location
  tags     = local.common_tags
}

resource "azurerm_resource_group" "network" {
  name     = "${local.name_prefix}-network-rg"
  location = var.location
  tags     = local.common_tags
}

# ─────────────────────────────────────────────
# MODULE: IAM (Azure AD + PIM + RBAC)
# ─────────────────────────────────────────────
module "iam" {
  source = "./modules/iam"

  name_prefix          = local.name_prefix
  tenant_id            = var.tenant_id
  subscription_id      = var.subscription_id
  resource_group_name  = azurerm_resource_group.identity.name
  location             = var.location
  enable_pim           = var.enable_pim
  ehr_admin_group_name = var.ehr_admin_group_name
}

# ─────────────────────────────────────────────
# MODULE: AZURE KEY VAULT
# ─────────────────────────────────────────────
module "encryption" {
  source = "./modules/encryption"

  name_prefix         = local.name_prefix
  resource_group_name = azurerm_resource_group.security.name
  location            = var.location
  tenant_id           = var.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
  sku_name            = "premium"  # HSM-backed keys for FedRAMP
}

# ─────────────────────────────────────────────
# MODULE: NETWORKING (VNet + NSG + Private Endpoints)
# ─────────────────────────────────────────────
module "network" {
  source = "./modules/network"

  name_prefix         = local.name_prefix
  resource_group_name = azurerm_resource_group.network.name
  location            = var.location
  address_space       = var.vnet_address_space
  private_subnets     = var.private_subnets
}

# ─────────────────────────────────────────────
# MODULE: AZURE SENTINEL & LOG ANALYTICS
# ─────────────────────────────────────────────
module "logging" {
  source = "./modules/logging"

  name_prefix              = local.name_prefix
  resource_group_name      = azurerm_resource_group.security.name
  location                 = var.location
  enable_sentinel          = true
  enable_defender          = true
  log_retention_days       = 365  # HIPAA: 1-year minimum log retention
  key_vault_id             = module.encryption.key_vault_id
}

# ─────────────────────────────────────────────
# AZURE DEFENDER FOR CLOUD
# ─────────────────────────────────────────────
resource "azurerm_security_center_subscription_pricing" "virtual_machines" {
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "sql_servers" {
  tier          = "Standard"
  resource_type = "SqlServers"
}

resource "azurerm_security_center_subscription_pricing" "storage_accounts" {
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "key_vaults" {
  tier          = "Standard"
  resource_type = "KeyVaults"
}

resource "azurerm_security_center_subscription_pricing" "kubernetes_service" {
  tier          = "Standard"
  resource_type = "KubernetesService"
}

resource "azurerm_security_center_subscription_pricing" "containers" {
  tier          = "Standard"
  resource_type = "Containers"
}

# ─────────────────────────────────────────────
# AZURE POLICY — HIPAA/NIST Compliance Policies
# ─────────────────────────────────────────────
resource "azurerm_policy_assignment" "hipaa_hitrust" {
  name                 = "${local.name_prefix}-hipaa-hitrust"
  scope                = data.azurerm_subscription.current.id
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/a169a624-5599-4385-a696-c8d643089fab"
  description          = "HIPAA HITRUST 9.2 compliance policy assignment"
  display_name         = "UpCare HIPAA HITRUST Policy"

  identity {
    type = "SystemAssigned"
  }

  location = var.location
}

resource "azurerm_policy_assignment" "nist_sp_800_53" {
  name                 = "${local.name_prefix}-nist-800-53"
  scope                = data.azurerm_subscription.current.id
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/cf25b9c1-bd23-4eb6-bd2c-f4f3ac644a5f"
  description          = "NIST SP 800-53 Rev. 5 compliance policy assignment"
  display_name         = "UpCare NIST SP 800-53 Policy"

  identity {
    type = "SystemAssigned"
  }

  location = var.location
}

resource "azurerm_policy_assignment" "fedramp_moderate" {
  name                 = "${local.name_prefix}-fedramp-moderate"
  scope                = data.azurerm_subscription.current.id
  policy_definition_id = "/providers/Microsoft.Authorization/policySetDefinitions/e95f5a9f-57ad-4d03-bb0b-b1d16db93693"
  description          = "FedRAMP Moderate compliance policy assignment"
  display_name         = "UpCare FedRAMP Moderate Policy"

  identity {
    type = "SystemAssigned"
  }

  location = var.location
}

# Deny public IP creation on resources
resource "azurerm_policy_definition" "deny_public_ip" {
  name         = "${local.name_prefix}-deny-public-ip"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Deny creation of Public IP Addresses — Zero Trust"
  description  = "NIST 800-207: Denies creation of public IPs to enforce Zero Trust network perimeter"

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Network/publicIPAddresses"
        },
        {
          not = {
            field  = "Microsoft.Network/publicIPAddresses/sku.name"
            equals = "Basic"
          }
        }
      ]
    }
    then = {
      effect = "Deny"
    }
  })
}

# ─────────────────────────────────────────────
# AZURE STORAGE — HIPAA EHR Data
# ─────────────────────────────────────────────
resource "azurerm_storage_account" "ehr_data" {
  name                     = "${replace(local.name_prefix, "-", "")}ehrdata"
  resource_group_name      = azurerm_resource_group.security.name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "GZRS"        # Geo-zone redundancy for HIPAA DR
  account_kind             = "StorageV2"

  # HIPAA: Enforce HTTPS-only, TLS 1.2+
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false  # AAD-only auth (Zero Trust)

  blob_properties {
    versioning_enabled       = true
    change_feed_enabled      = true
    last_access_time_enabled = true
    delete_retention_policy {
      days = 365  # HIPAA: retain deleted blobs for 1 year
    }
    container_delete_retention_policy {
      days = 365
    }
  }

  identity {
    type = "SystemAssigned"
  }

  customer_managed_key {
    key_vault_key_id          = module.encryption.phi_key_id
    user_assigned_identity_id = module.iam.storage_identity_id
  }

  network_rules {
    default_action             = "Deny"  # Zero Trust: deny all by default
    bypass                     = ["AzureServices"]
    virtual_network_subnet_ids = module.network.private_subnet_ids
    ip_rules                   = var.allowed_ip_ranges
  }

  tags = merge(local.common_tags, {
    DataClass = "PHI"
    Name      = "${local.name_prefix}-ehr-storage"
  })
}

# Advanced Threat Protection for storage
resource "azurerm_advanced_threat_protection" "ehr_data" {
  target_resource_id = azurerm_storage_account.ehr_data.id
  enabled            = true
}

# ─────────────────────────────────────────────
# VARIABLES
# ─────────────────────────────────────────────
variable "subscription_id" { type = string; sensitive = true }
variable "tenant_id" { type = string }
variable "location" { type = string; default = "eastus" }
variable "environment" { type = string; default = "prod" }
variable "vnet_address_space" { type = list(string); default = ["10.1.0.0/16"] }
variable "private_subnets" { type = list(string); default = ["10.1.1.0/24", "10.1.2.0/24"] }
variable "enable_pim" { type = bool; default = true }
variable "ehr_admin_group_name" { type = string; default = "EHR-Admins" }
variable "allowed_ip_ranges" { type = list(string); default = [] }

# ─────────────────────────────────────────────
# OUTPUTS
# ─────────────────────────────────────────────
output "key_vault_uri" { value = module.encryption.key_vault_uri; sensitive = true }
output "sentinel_workspace_id" { value = module.logging.sentinel_workspace_id }
output "ehr_storage_account_id" { value = azurerm_storage_account.ehr_data.id }
