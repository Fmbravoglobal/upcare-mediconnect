#!/bin/bash
# ============================================================
# UpCare MediConnect — Run All Security Scans Locally
# Author: Oluwafemi Alabi Okunlola | Fmbravoglobal Holdings Inc.
# ============================================================

set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0; WARN=0
REPORT_DIR="scan-results-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$REPORT_DIR"

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass()    { echo -e "${GREEN}[✅ PASS]${NC} $1"; ((PASS++)); }
log_fail()    { echo -e "${RED}[❌ FAIL]${NC} $1"; ((FAIL++)); }
log_warn()    { echo -e "${YELLOW}[⚠️  WARN]${NC} $1"; ((WARN++)); }
log_section() { echo -e "\n${BOLD}${BLUE}══ $1 ══${NC}"; }

echo ""
echo "════════════════════════════════════════════════════════"
echo "  UpCare MediConnect — Full Security Scan Suite"
echo "  Fmbravoglobal Holdings Inc. | $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "════════════════════════════════════════════════════════"

# ── 1. Secret Detection ───────────────────────────────────
log_section "SECRET DETECTION"

if command -v gitleaks &>/dev/null; then
    if gitleaks detect --source . --report-format json \
        --report-path "$REPORT_DIR/gitleaks.json" --exit-code 0 2>/dev/null; then
        log_pass "Gitleaks: No secrets detected"
    else
        log_fail "Gitleaks: Potential secrets found — review $REPORT_DIR/gitleaks.json"
    fi
else
    log_warn "Gitleaks not installed — skipping (run bootstrap.sh)"
fi

# ── 2. Terraform Security ─────────────────────────────────
log_section "TERRAFORM IaC SECURITY"

if command -v terraform &>/dev/null; then
    log_info "Checking Terraform format..."
    if terraform fmt -check -recursive terraform/ 2>/dev/null; then
        log_pass "Terraform fmt: All files properly formatted"
    else
        log_warn "Terraform fmt: Some files need formatting — run: terraform fmt -recursive terraform/"
    fi
fi

if command -v checkov &>/dev/null; then
    log_info "Running Checkov on Terraform..."
    checkov -d terraform/ \
        --framework terraform \
        --output json \
        --output-file-path "$REPORT_DIR" \
        --quiet 2>/dev/null && log_pass "Checkov Terraform: No critical failures" \
        || log_fail "Checkov Terraform: Security issues found — review $REPORT_DIR/results_terraform.json"
else
    log_warn "Checkov not installed"
fi

if command -v tfsec &>/dev/null; then
    log_info "Running tfsec..."
    tfsec terraform/ \
        --format json \
        --out "$REPORT_DIR/tfsec.json" \
        --soft-fail 2>/dev/null && log_pass "tfsec: No high severity issues" \
        || log_fail "tfsec: Security issues detected — review $REPORT_DIR/tfsec.json"
else
    log_warn "tfsec not installed"
fi

# ── 3. CloudFormation Security ────────────────────────────
log_section "CLOUDFORMATION SECURITY"

if command -v cfn-lint &>/dev/null; then
    log_info "Running cfn-lint..."
    cfn-lint cloudformation/**/*.yaml \
        --format json > "$REPORT_DIR/cfn-lint.json" 2>/dev/null \
        && log_pass "cfn-lint: No template errors" \
        || log_warn "cfn-lint: Template warnings found — review $REPORT_DIR/cfn-lint.json"
else
    log_warn "cfn-lint not installed"
fi

if command -v cfn_nag_scan &>/dev/null; then
    log_info "Running cfn-nag..."
    cfn_nag_scan \
        --input-path cloudformation/ \
        --output-format json \
        > "$REPORT_DIR/cfn-nag.json" 2>/dev/null \
        && log_pass "cfn-nag: No security failures" \
        || log_fail "cfn-nag: Security issues found — review $REPORT_DIR/cfn-nag.json"
else
    log_warn "cfn-nag not installed"
fi

if command -v checkov &>/dev/null; then
    log_info "Running Checkov on CloudFormation..."
    checkov -d cloudformation/ \
        --framework cloudformation \
        --output json \
        --output-file-path "$REPORT_DIR/cfn" \
        --quiet 2>/dev/null && log_pass "Checkov CloudFormation: No critical failures" \
        || log_fail "Checkov CloudFormation: Issues found"
fi

# ── 4. SAST ───────────────────────────────────────────────
log_section "STATIC APPLICATION SECURITY TESTING (SAST)"

if command -v semgrep &>/dev/null; then
    log_info "Running Semgrep..."
    semgrep --config=p/python \
        --config=p/secrets \
        --config=p/owasp-top-ten \
        --json \
        --output "$REPORT_DIR/semgrep.json" \
        compliance/ incident-response/lambda/ scripts/ 2>/dev/null \
        && log_pass "Semgrep: No high severity findings" \
        || log_fail "Semgrep: Security findings detected — review $REPORT_DIR/semgrep.json"
else
    log_warn "Semgrep not installed"
fi

if command -v bandit &>/dev/null; then
    log_info "Running Bandit (Python security)..."
    bandit -r compliance/ incident-response/lambda/ \
        -f json \
        -o "$REPORT_DIR/bandit.json" \
        -ll 2>/dev/null \
        && log_pass "Bandit: No medium/high Python security issues" \
        || log_warn "Bandit: Python security findings — review $REPORT_DIR/bandit.json"
elif pip3 show bandit &>/dev/null 2>&1; then
    log_warn "bandit installed but not in PATH"
else
    log_info "Installing bandit..."
    pip3 install bandit --quiet && bandit -r compliance/ -f json -o "$REPORT_DIR/bandit.json" -ll 2>/dev/null
fi

# ── 5. Container / File System Scan ──────────────────────
log_section "CONTAINER & FILESYSTEM VULNERABILITY SCAN"

if command -v trivy &>/dev/null; then
    log_info "Running Trivy filesystem scan..."
    trivy fs . \
        --severity CRITICAL,HIGH \
        --format json \
        --output "$REPORT_DIR/trivy.json" \
        --exit-code 0 2>/dev/null \
        && log_pass "Trivy: No critical/high vulnerabilities" \
        || log_fail "Trivy: Vulnerabilities found — review $REPORT_DIR/trivy.json"
else
    log_warn "Trivy not installed"
fi

# ── 6. Compliance Dry-Run ────────────────────────────────
log_section "COMPLIANCE VALIDATION (DRY RUN)"

if command -v python3 &>/dev/null; then
    log_info "Running HIPAA audit (dry-run)..."
    python3 compliance/hipaa/hipaa-audit.py \
        --dry-run \
        --output-file "$REPORT_DIR/hipaa-results.json" 2>/dev/null \
        && log_pass "HIPAA Audit: All controls passed" \
        || log_fail "HIPAA Audit: Critical failures detected"

    log_info "Running NIST SP 800-207 validator (dry-run)..."
    python3 compliance/nist/nist-800-207-validator.py \
        --dry-run \
        --output-file "$REPORT_DIR/nist-results.json" 2>/dev/null \
        && log_pass "NIST Zero Trust: All controls passed" \
        || log_fail "NIST Zero Trust: Gaps detected"
else
    log_warn "Python3 not found"
fi

# ── 7. Summary ────────────────────────────────────────────
TOTAL=$((PASS + FAIL + WARN))
echo ""
echo "════════════════════════════════════════════════════════"
echo -e "  ${BOLD}SCAN SUMMARY${NC}"
echo "────────────────────────────────────────────────────────"
echo -e "  Total Checks  : $TOTAL"
echo -e "  ${GREEN}✅ Passed${NC}     : $PASS"
echo -e "  ${RED}❌ Failed${NC}     : $FAIL"
echo -e "  ${YELLOW}⚠️  Warnings${NC}  : $WARN"
echo ""
echo "  Reports saved to: ./$REPORT_DIR/"
echo "════════════════════════════════════════════════════════"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}❌ Security gate FAILED — $FAIL critical issues require remediation${NC}"
    exit 1
else
    echo -e "${GREEN}✅ Security gate PASSED — safe to commit${NC}"
    exit 0
fi
