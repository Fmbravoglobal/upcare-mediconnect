#!/bin/bash
# ============================================================
# UpCare MediConnect — Generate Full Compliance Report
# Runs all four compliance scripts and produces a combined report
# Author: Oluwafemi Alabi Okunlola | Fmbravoglobal Holdings Inc.
# ============================================================

set -uo pipefail

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'

REPORT_DATE=$(date -u +"%Y-%m-%d_%H%M%S")
REPORT_DIR="compliance-reports/$REPORT_DATE"
mkdir -p "$REPORT_DIR"

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✅ OK]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[⚠️ ]${NC} $1"; }
log_error()   { echo -e "${RED}[❌]${NC} $1"; }

DRY_RUN="${1:---dry-run}"

echo ""
echo "════════════════════════════════════════════════════════"
echo -e "  ${BOLD}UpCare MediConnect — Compliance Report Generator${NC}"
echo "  Frameworks: HIPAA | NIST SP 800-207 | SOC 2 | FedRAMP"
echo "  Generated: $(date -u '+%Y-%m-%d %H:%M UTC')"
echo "════════════════════════════════════════════════════════"
echo ""

log_info "Output directory: $REPORT_DIR"
log_info "Mode: $DRY_RUN"
echo ""

# ── HIPAA ─────────────────────────────────────────────────
echo -e "${BOLD}[1/4] Running HIPAA Compliance Audit...${NC}"
if python3 compliance/hipaa/hipaa-audit.py \
    $DRY_RUN \
    --output-file "$REPORT_DIR/hipaa-results.json" 2>&1; then
    log_success "HIPAA audit complete → $REPORT_DIR/hipaa-results.json"
else
    log_error "HIPAA audit found critical failures — review report"
fi

# ── NIST SP 800-207 ───────────────────────────────────────
echo -e "\n${BOLD}[2/4] Running NIST SP 800-207 Zero Trust Validation...${NC}"
if python3 compliance/nist/nist-800-207-validator.py \
    $DRY_RUN \
    --output-file "$REPORT_DIR/nist-results.json" 2>&1; then
    log_success "NIST Zero Trust validation complete → $REPORT_DIR/nist-results.json"
else
    log_error "NIST Zero Trust gaps detected — review report"
fi

# ── SOC 2 ────────────────────────────────────────────────
echo -e "\n${BOLD}[3/4] Collecting SOC 2 Evidence...${NC}"
if python3 compliance/soc2/soc2-evidence-collector.py \
    $DRY_RUN \
    --output-file "$REPORT_DIR/soc2-results.json" 2>&1; then
    log_success "SOC 2 evidence collected → $REPORT_DIR/soc2-results.json"
else
    log_warn "SOC 2 evidence collection incomplete — review report"
fi

# ── FedRAMP ───────────────────────────────────────────────
echo -e "\n${BOLD}[4/4] Running FedRAMP ATO Readiness Check...${NC}"
if python3 compliance/fedramp/fedramp-ato-checklist.py \
    $DRY_RUN \
    --output-file "$REPORT_DIR/fedramp-results.json" 2>&1; then
    log_success "FedRAMP ATO check complete → $REPORT_DIR/fedramp-results.json"
else
    log_error "FedRAMP gaps detected — ATO not ready"
fi

# ── Combine into summary ──────────────────────────────────
echo -e "\n${BOLD}Generating combined summary...${NC}"
python3 << PYEOF
import json, glob, os
from datetime import datetime, timezone

report_dir = "$REPORT_DIR"
files = {
    "hipaa":   os.path.join(report_dir, "hipaa-results.json"),
    "nist":    os.path.join(report_dir, "nist-results.json"),
    "soc2":    os.path.join(report_dir, "soc2-results.json"),
    "fedramp": os.path.join(report_dir, "fedramp-results.json"),
}

combined = {
    "report_metadata": {
        "title": "UpCare MediConnect — Combined Compliance Dashboard",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "frameworks": ["HIPAA", "NIST SP 800-207", "SOC 2 Type II", "FedRAMP Moderate"],
        "author": "Oluwafemi Alabi Okunlola | Fmbravoglobal Holdings Inc."
    },
    "dashboard": {}
}

for fw, path in files.items():
    if os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
        summary = data.get("summary", {})
        combined["dashboard"][fw.upper()] = {
            "score": summary.get(
                "compliance_score_percent",
                summary.get("zero_trust_score_percent",
                summary.get("readiness_score",
                summary.get("ato_readiness_score", 0)))
            ),
            "status": summary.get(
                "overall_status",
                summary.get("ato_status", "UNKNOWN")
            ),
            "passed": summary.get(
                "passed",
                summary.get("implemented",
                summary.get("collected", 0))
            ),
            "failed": summary.get(
                "failed",
                summary.get("not_implemented",
                summary.get("missing", 0))
            )
        }
    else:
        combined["dashboard"][fw.upper()] = {"status": "REPORT_NOT_FOUND"}

out = os.path.join(report_dir, "combined-compliance-dashboard.json")
with open(out, "w") as f:
    json.dump(combined, f, indent=2)

print("\n  ╔══════════════════════════════════════════════╗")
print("  ║  COMPLIANCE DASHBOARD SUMMARY                ║")
print("  ╠══════════════════════════════════════════════╣")
for fw, data in combined["dashboard"].items():
    score  = data.get("score", "N/A")
    status = data.get("status", "UNKNOWN")
    icon   = "✅" if "COMPLIANT" in str(status) or "READY" in str(status) or "PASS" in str(status) else "❌"
    print(f"  ║  {icon} {fw:<12} Score: {str(score)+'%':<8} | {status}")
print("  ╚══════════════════════════════════════════════╝")
print(f"\n  Combined report: {out}")
PYEOF

echo ""
echo "════════════════════════════════════════════════════════"
log_success "All compliance reports saved to: ./$REPORT_DIR/"
echo ""
echo "  Files:"
ls "$REPORT_DIR/"
echo "════════════════════════════════════════════════════════"
echo ""
