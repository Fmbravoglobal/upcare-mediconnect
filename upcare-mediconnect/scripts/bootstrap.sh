#!/bin/bash
# ============================================================
# UpCare MediConnect — Environment Bootstrap Script
# Installs all required security scanning tools
# Author: Oluwafemi Alabi Okunlola | Fmbravoglobal Holdings Inc.
# ============================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✅ OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[⚠️  WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[❌ ERROR]${NC} $1"; }

echo ""
echo "======================================================"
echo "  UpCare MediConnect Security Tool Bootstrap"
echo "  Fmbravoglobal Holdings Inc. — Cloud Security"
echo "======================================================"
echo ""

# ── Detect OS ─────────────────────────────────────────────
OS=$(uname -s)
log_info "Detected OS: $OS"

# ── Terraform ─────────────────────────────────────────────
if ! command -v terraform &>/dev/null; then
    log_info "Installing Terraform..."
    if [[ "$OS" == "Darwin" ]]; then
        brew tap hashicorp/tap && brew install hashicorp/tap/terraform
    else
        curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
        sudo apt-add-repository "deb https://apt.releases.hashicorp.com $(lsb_release -cs) main"
        sudo apt-get update && sudo apt-get install -y terraform
    fi
    log_success "Terraform installed: $(terraform version | head -1)"
else
    log_success "Terraform: $(terraform version | head -1)"
fi

# ── AWS CLI ───────────────────────────────────────────────
if ! command -v aws &>/dev/null; then
    log_info "Installing AWS CLI..."
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
    unzip awscliv2.zip && sudo ./aws/install && rm -rf aws awscliv2.zip
    log_success "AWS CLI installed"
else
    log_success "AWS CLI: $(aws --version)"
fi

# ── Azure CLI ─────────────────────────────────────────────
if ! command -v az &>/dev/null; then
    log_info "Installing Azure CLI..."
    if [[ "$OS" == "Darwin" ]]; then
        brew install azure-cli
    else
        curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
    fi
    log_success "Azure CLI installed"
else
    log_success "Azure CLI: $(az version --query '"azure-cli"' -o tsv)"
fi

# ── Google Cloud CLI ──────────────────────────────────────
if ! command -v gcloud &>/dev/null; then
    log_info "Installing Google Cloud CLI..."
    if [[ "$OS" == "Darwin" ]]; then
        brew install --cask google-cloud-sdk
    else
        echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
          | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list
        curl https://packages.cloud.google.com/apt/doc/apt-key.gpg \
          | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
        sudo apt-get update && sudo apt-get install -y google-cloud-cli
    fi
    log_success "GCP CLI installed"
else
    log_success "GCP CLI: $(gcloud version --format='value(Google Cloud SDK)')"
fi

# ── Checkov ───────────────────────────────────────────────
if ! command -v checkov &>/dev/null; then
    log_info "Installing Checkov..."
    pip3 install checkov --quiet
    log_success "Checkov installed: $(checkov --version)"
else
    log_success "Checkov: $(checkov --version)"
fi

# ── tfsec ────────────────────────────────────────────────
if ! command -v tfsec &>/dev/null; then
    log_info "Installing tfsec..."
    if [[ "$OS" == "Darwin" ]]; then
        brew install tfsec
    else
        curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh | bash
    fi
    log_success "tfsec installed"
else
    log_success "tfsec: $(tfsec --version)"
fi

# ── cfn-lint ─────────────────────────────────────────────
if ! command -v cfn-lint &>/dev/null; then
    log_info "Installing cfn-lint..."
    pip3 install cfn-lint --quiet
    log_success "cfn-lint installed: $(cfn-lint --version)"
else
    log_success "cfn-lint: $(cfn-lint --version)"
fi

# ── cfn-nag ──────────────────────────────────────────────
if ! command -v cfn_nag_scan &>/dev/null; then
    log_info "Installing cfn-nag (requires Ruby)..."
    if command -v gem &>/dev/null; then
        gem install cfn-nag --quiet
        log_success "cfn-nag installed"
    else
        log_warn "Ruby not found — skipping cfn-nag. Install Ruby then run: gem install cfn-nag"
    fi
else
    log_success "cfn-nag installed"
fi

# ── Trivy ────────────────────────────────────────────────
if ! command -v trivy &>/dev/null; then
    log_info "Installing Trivy..."
    if [[ "$OS" == "Darwin" ]]; then
        brew install aquasecurity/trivy/trivy
    else
        sudo apt-get install -y wget apt-transport-https gnupg lsb-release
        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
          | sudo tee /etc/apt/sources.list.d/trivy.list
        sudo apt-get update && sudo apt-get install -y trivy
    fi
    log_success "Trivy installed: $(trivy --version | head -1)"
else
    log_success "Trivy: $(trivy --version | head -1)"
fi

# ── Gitleaks ─────────────────────────────────────────────
if ! command -v gitleaks &>/dev/null; then
    log_info "Installing Gitleaks..."
    if [[ "$OS" == "Darwin" ]]; then
        brew install gitleaks
    else
        GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | sed 's/.*"v\([^"]*\)".*/\1/')
        curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar xz
        sudo mv gitleaks /usr/local/bin/
    fi
    log_success "Gitleaks installed"
else
    log_success "Gitleaks installed"
fi

# ── Semgrep ──────────────────────────────────────────────
if ! command -v semgrep &>/dev/null; then
    log_info "Installing Semgrep..."
    pip3 install semgrep --quiet
    log_success "Semgrep installed: $(semgrep --version)"
else
    log_success "Semgrep: $(semgrep --version)"
fi

# ── Python dependencies ───────────────────────────────────
log_info "Installing Python compliance script dependencies..."
pip3 install boto3 azure-identity azure-mgmt-security google-cloud-securitycenter \
    pyyaml jinja2 tabulate reportlab --quiet
log_success "Python dependencies installed"

# ── Summary ───────────────────────────────────────────────
echo ""
echo "======================================================"
echo "  ✅ Bootstrap Complete!"
echo ""
echo "  Next steps:"
echo "  1. Configure cloud credentials:"
echo "     aws configure"
echo "     az login"
echo "     gcloud auth login"
echo ""
echo "  2. Run all security scans:"
echo "     ./scripts/scan-all.sh"
echo ""
echo "  3. Run compliance audit:"
echo "     ./scripts/generate-compliance-report.sh"
echo "======================================================"
echo ""
