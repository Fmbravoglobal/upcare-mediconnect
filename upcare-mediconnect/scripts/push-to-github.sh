#!/bin/bash
# ============================================================
# UpCare MediConnect — GitHub Push Script
# Run this once to initialize the repo and push to GitHub
# Author: Oluwafemi Alabi Okunlola | Fmbravoglobal Holdings Inc.
# ============================================================

set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'

GITHUB_USERNAME="fmbravoglobal"
REPO_NAME="upcare-mediconnect"
GITHUB_URL="https://github.com/$GITHUB_USERNAME/$REPO_NAME.git"

echo ""
echo "======================================================"
echo "  UpCare MediConnect — GitHub Push Setup"
echo "======================================================"
echo ""

# Step 1: Add .gitignore
cat > .gitignore << 'EOF'
# Terraform
.terraform/
*.tfstate
*.tfstate.backup
*.tfvars
.terraform.lock.hcl
terraform.tfplan

# Secrets (never commit these)
*.pem
*.key
*.p12
*credentials*
*secrets*
.env
.env.*

# Python
__pycache__/
*.pyc
*.pyo
*.egg-info/
.venv/
venv/

# Scan outputs
scan-results-*/
compliance-reports/
*.sarif
*.json.bak

# IDE
.idea/
.vscode/
*.swp
.DS_Store
EOF

echo -e "${GREEN}✅${NC} .gitignore created"

# Step 2: Add MIT License
cat > LICENSE << EOF
MIT License

Copyright (c) 2026 Oluwafemi Alabi Okunlola — Fmbravoglobal Holdings Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
EOF

echo -e "${GREEN}✅${NC} LICENSE created"

# Step 3: Make scripts executable
chmod +x scripts/bootstrap.sh scripts/scan-all.sh scripts/generate-compliance-report.sh
echo -e "${GREEN}✅${NC} Scripts made executable"

# Step 4: Initialize git
if [ ! -d ".git" ]; then
    git init
    echo -e "${GREEN}✅${NC} Git initialized"
else
    echo -e "${YELLOW}ℹ️${NC}  Git already initialized"
fi

git config user.name "Oluwafemi Alabi Okunlola"
git config user.email "femi@fmbravoglobal.com"

# Step 5: Stage and commit
git add .
git commit -m "feat: Initial commit — UpCare MediConnect multi-cloud healthcare security platform

Implements full-stack DevSecOps security for AI-driven healthcare platform:

🔐 Security Architecture:
- Zero Trust (NIST SP 800-207) across AWS + Azure + GCP
- HIPAA-compliant EHR infrastructure (KMS BYOK, audit logging, PHI controls)
- SOC 2 Type II evidence automation
- FedRAMP Moderate ATO readiness (325+ controls)

🏗️ Infrastructure as Code:
- Terraform modules: AWS IAM/encryption/network/logging, Azure, GCP
- CloudFormation: HIPAA EHR stack with KMS, CloudTrail, Macie, Lambda audit

🔄 CI/CD DevSecOps Pipeline:
- GitHub Actions: Gitleaks, Checkov, tfsec, cfn-lint, cfn-nag, Semgrep, Trivy
- Security gate blocks non-compliant PRs
- SARIF results uploaded to GitHub Security tab

📋 Compliance Automation:
- hipaa-audit.py: 20 HIPAA controls → 45 CFR § 164.312
- nist-800-207-validator.py: 23 Zero Trust controls across 5 pillars
- soc2-evidence-collector.py: SOC 2 Trust Service Criteria evidence
- fedramp-ato-checklist.py: 28 FedRAMP Moderate control families

🚨 Incident Response:
- auto-isolate-ec2.py: GuardDuty → auto-isolate + forensic snapshots
- phi-breach-playbook.md: HIPAA breach notification procedure
- MTTD target < 1hr | MTTR target < 24hr

Author: Oluwafemi Alabi Okunlola | Fmbravoglobal Holdings Inc.
GitHub: https://github.com/fmbravoglobal"

echo -e "${GREEN}✅${NC} Initial commit created"

# Step 6: Push to GitHub
echo ""
echo -e "${BLUE}[INFO]${NC} To push to GitHub, run:"
echo ""
echo "  # Option A — HTTPS"
echo "  git remote add origin $GITHUB_URL"
echo "  git branch -M main"
echo "  git push -u origin main"
echo ""
echo "  # Option B — SSH (if SSH key configured)"
echo "  git remote add origin git@github.com:$GITHUB_USERNAME/$REPO_NAME.git"
echo "  git branch -M main"
echo "  git push -u origin main"
echo ""
echo -e "${YELLOW}⚠️  First create the repo on GitHub:${NC}"
echo "  https://github.com/new"
echo "  Repo name: $REPO_NAME"
echo "  Visibility: Public"
echo "  Do NOT initialize with README (we have one)"
echo ""
echo "======================================================"
echo -e "${GREEN}✅ Project ready to push!${NC}"
echo "======================================================"
