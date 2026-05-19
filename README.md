# 🏥 UpCare MediConnect — Multi-Cloud Healthcare Security Platform

> **A production-grade cloud security implementation for AI-driven healthcare platforms, covering Zero Trust architecture, HIPAA/NIST/SOC2/FedRAMP compliance, and automated DevSecOps pipelines across AWS, Azure, and GCP.**

---

## 📌 Project Overview

UpCare MediConnect is a reference architecture and implementation project for securing a multi-cloud healthcare platform that supports:

- **Telehealth services** — secure patient-provider video and data exchange
- **Predictive analytics** — ML pipelines with encrypted PHI data flows
- **Electronic Health Records (EHR)** — HIPAA-compliant storage, access control, and audit logging

This repository contains all Infrastructure-as-Code (IaC), CI/CD pipeline configurations, IAM policies, compliance automation scripts, and incident response playbooks needed to deploy and operate a secure healthcare cloud environment.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    UpCare MediConnect Platform                   │
├──────────────┬──────────────────┬───────────────────────────────┤
│     AWS      │      Azure       │             GCP               │
│  (Primary)   │   (Identity &    │    (Analytics & ML)           │
│              │    Governance)   │                               │
├──────────────┼──────────────────┼───────────────────────────────┤
│ EHR Storage  │ Azure AD / PIM   │ BigQuery PHI Analytics        │
│ GuardDuty    │ Sentinel SIEM    │ Security Command Center       │
│ Macie (PHI)  │ Defender for     │ VPC Service Controls          │
│ Security Hub │   Cloud          │ Cloud Armor WAF               │
│ KMS (BYOK)   │ Key Vault        │ Cloud KMS + HSM               │
│ Config Rules │ Policy           │ Org Policy Constraints        │
│ CloudTrail   │ Activity Logs    │ Cloud Audit Logs              │
└──────────────┴──────────────────┴───────────────────────────────┘
                         │
              ┌──────────▼──────────┐
              │   Zero Trust Layer   │
              │  NIST SP 800-207    │
              │  - Never trust,     │
              │    always verify    │
              │  - Least privilege  │
              │  - Micro-segment    │
              └─────────────────────┘
```

---

## 📁 Repository Structure

```
upcare-mediconnect/
├── .github/
│   └── workflows/
│       ├── devsecops-pipeline.yml       # Main CI/CD security pipeline
│       ├── compliance-scan.yml          # Scheduled compliance checks
│       └── incident-response.yml        # Automated IR triggers
├── terraform/
│   ├── aws/
│   │   ├── modules/
│   │   │   ├── iam/                     # AWS IAM Zero Trust policies
│   │   │   ├── network/                 # VPC, Security Groups, NACLs
│   │   │   ├── logging/                 # CloudTrail, Config, Security Hub
│   │   │   └── encryption/              # KMS, Macie, Secrets Manager
│   │   └── main.tf
│   ├── azure/
│   │   ├── modules/
│   │   │   ├── iam/                     # Azure AD, PIM, RBAC
│   │   │   ├── network/                 # VNet, NSG, Private Endpoints
│   │   │   ├── logging/                 # Sentinel, Log Analytics
│   │   │   └── encryption/              # Key Vault, Disk Encryption
│   │   └── main.tf
│   └── gcp/
│       ├── modules/
│       │   ├── iam/                     # GCP IAM, Org Policies
│       │   ├── network/                 # VPC SC, Cloud Armor
│       │   ├── logging/                 # Cloud Audit, SIEM export
│       │   └── encryption/              # Cloud KMS, CMEK
│       └── main.tf
├── cloudformation/
│   ├── ehr/
│   │   └── hipaa-ehr-stack.yaml         # HIPAA-compliant EHR infrastructure
│   ├── network/
│   │   └── zero-trust-network.yaml      # Zero Trust network stack
│   └── logging/
│       └── audit-logging-stack.yaml     # Centralized audit logging
├── iam/
│   ├── aws/
│   │   ├── ehr-read-only-policy.json    # EHR read-only role
│   │   ├── ehr-admin-policy.json        # EHR admin role
│   │   └── zero-trust-scp.json          # Service Control Policies
│   ├── azure/
│   │   ├── custom-ehr-reader-role.json  # Azure custom RBAC role
│   │   └── pim-config.json              # Privileged Identity Management
│   └── gcp/
│       └── org-policy-constraints.yaml  # GCP Org Policy definitions
├── compliance/
│   ├── hipaa/
│   │   └── hipaa-audit.py               # HIPAA control audit script
│   ├── nist/
│   │   └── nist-800-207-validator.py    # Zero Trust posture validator
│   ├── soc2/
│   │   └── soc2-evidence-collector.py  # SOC 2 evidence automation
│   └── fedramp/
│       └── fedramp-ato-checklist.py     # FedRAMP ATO readiness script
├── incident-response/
│   ├── playbooks/
│   │   ├── phi-breach-playbook.md       # PHI data breach response
│   │   ├── ransomware-playbook.md       # Ransomware response
│   │   └── unauthorized-access.md      # Unauthorized EHR access
│   └── lambda/
│       ├── auto-isolate-ec2.py          # Auto-isolate compromised instance
│       ├── revoke-iam-keys.py           # Auto-revoke leaked IAM credentials
│       └── notify-hipaa-officer.py      # HIPAA breach notification trigger
├── scripts/
│   ├── bootstrap.sh                     # Environment bootstrap script
│   ├── scan-all.sh                      # Run all security scans locally
│   └── generate-compliance-report.sh   # Generate full compliance report
└── docs/
    ├── architecture.md                  # Detailed architecture decisions
    ├── threat-model.md                  # STRIDE threat model
    └── compliance-matrix.md             # Control mapping matrix
```

---

## 🔒 Compliance Frameworks Covered

| Framework | Coverage | Controls Implemented |
|-----------|----------|---------------------|
| **HIPAA** | Full | PHI encryption, access controls, audit logs, BAA enforcement |
| **NIST SP 800-207** | Full | Zero Trust pillars, identity verification, micro-segmentation |
| **SOC 2 Type II** | Full | Availability, Confidentiality, Security, Processing Integrity |
| **FedRAMP Moderate** | Full | 325+ controls, continuous monitoring, ATO readiness |

---

## 🚀 Quick Start

### Prerequisites

```bash
# Install required tools
brew install terraform awscli azure-cli google-cloud-sdk checkov tfsec cfn-lint

# Install cfn-nag
gem install cfn-nag

# Clone the repository
git clone https://github.com/fmbravoglobal/upcare-mediconnect.git
cd upcare-mediconnect

# Bootstrap environment
chmod +x scripts/bootstrap.sh
./scripts/bootstrap.sh
```

### Deploy Infrastructure

```bash
# AWS
cd terraform/aws
terraform init && terraform plan && terraform apply

# Azure
cd terraform/azure
terraform init && terraform plan && terraform apply

# GCP
cd terraform/gcp
terraform init && terraform plan && terraform apply
```

### Run Security Scans

```bash
# Run all scans locally
./scripts/scan-all.sh

# Individual tools
checkov -d terraform/           # IaC security scan
tfsec terraform/                # Terraform-specific checks
cfn-lint cloudformation/        # CloudFormation linting
cfn_nag_scan --input-path cloudformation/  # CFN security rules
```

### Run Compliance Audit

```bash
# Generate full compliance report
./scripts/generate-compliance-report.sh

# Individual framework audits
python compliance/hipaa/hipaa-audit.py
python compliance/nist/nist-800-207-validator.py
python compliance/soc2/soc2-evidence-collector.py
python compliance/fedramp/fedramp-ato-checklist.py
```

---

## 🔧 CI/CD Security Pipeline

Every pull request triggers:

1. **Static Analysis** — cfn-lint, cfn-nag, Checkov, tfsec
2. **Secret Detection** — GitLeaks, TruffleHog
3. **SAST** — Semgrep security rules
4. **Compliance Validation** — HIPAA/NIST control checks
5. **Container Scanning** — Trivy image scan
6. **SBOM Generation** — Software Bill of Materials
7. **Drift Detection** — Terraform plan diff

---

## 👤 Author

**Oluwafemi Alabi Okunlola**  
Cloud Security Engineer | DevSecOps Specialist | Zero Trust Architect  
[GitHub: fmbravoglobal](https://github.com/fmbravoglobal)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
