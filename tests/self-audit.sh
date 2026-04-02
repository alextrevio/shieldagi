#!/usr/bin/env bash
set -euo pipefail

echo "==========================================="
echo "  ShieldAGI Self-Audit"
echo "==========================================="

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FAILURES=0

echo ""
echo "[1/4] Running semgrep static analysis..."
if command -v semgrep &>/dev/null; then
    semgrep --config=p/owasp-top-ten --config=p/security-audit \
        --json "$REPO_ROOT/tools/src" 2>/dev/null | \
        python3 -c "import sys,json; r=json.load(sys.stdin); errs=r.get('results',[]); print(f'  Found {len(errs)} findings'); sys.exit(1 if errs else 0)" || FAILURES=$((FAILURES+1))
else
    echo "  [SKIP] semgrep not installed"
fi

echo ""
echo "[2/4] Scanning for hardcoded secrets..."
if command -v gitleaks &>/dev/null; then
    gitleaks detect --source="$REPO_ROOT" --no-banner --report-format=json 2>/dev/null && \
        echo "  No secrets found" || { echo "  SECRETS DETECTED"; FAILURES=$((FAILURES+1)); }
elif command -v trufflehog &>/dev/null; then
    trufflehog filesystem "$REPO_ROOT" --json 2>/dev/null | head -1 | \
        python3 -c "import sys; line=sys.stdin.readline(); print('  No secrets found' if not line.strip() else '  SECRETS DETECTED'); sys.exit(1 if line.strip() else 0)" || FAILURES=$((FAILURES+1))
else
    echo "  [SKIP] Neither gitleaks nor trufflehog installed"
fi

echo ""
echo "[3/4] Auditing Rust dependencies..."
if command -v cargo &>/dev/null; then
    cd "$REPO_ROOT/tools"
    cargo audit 2>/dev/null && echo "  No vulnerable dependencies" || { echo "  VULNERABLE DEPS FOUND"; FAILURES=$((FAILURES+1)); }
    cd "$REPO_ROOT"
else
    echo "  [SKIP] cargo not installed"
fi

echo ""
echo "[4/4] Checking for common security anti-patterns..."
ANTIPATTERNS=0
# Check for unwrap() in production code (excluding tests)
UNWRAP_COUNT=$(grep -r "\.unwrap()" "$REPO_ROOT/tools/src/" --include="*.rs" | grep -v "#\[cfg(test)\]" | grep -v "mod tests" | wc -l | tr -d ' ')
if [ "$UNWRAP_COUNT" -gt 50 ]; then
    echo "  WARNING: $UNWRAP_COUNT unwrap() calls found (consider using ? operator)"
    ANTIPATTERNS=$((ANTIPATTERNS+1))
fi
# Check for TODO/FIXME
TODO_COUNT=$(grep -rn "TODO\|FIXME\|HACK\|XXX" "$REPO_ROOT/tools/src/" --include="*.rs" | wc -l | tr -d ' ')
if [ "$TODO_COUNT" -gt 0 ]; then
    echo "  WARNING: $TODO_COUNT TODO/FIXME comments found"
fi
echo "  Anti-pattern check complete"

echo ""
echo "==========================================="
if [ "$FAILURES" -gt 0 ]; then
    echo "  SELF-AUDIT FAILED: $FAILURES issue(s) found"
    exit 1
else
    echo "  SELF-AUDIT PASSED"
    exit 0
fi
