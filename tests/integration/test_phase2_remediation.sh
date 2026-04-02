#!/usr/bin/env bash
set -euo pipefail

echo "=== Phase 2 Remediation Integration Test ==="

REPO_PATH="${TEST_REPO_PATH:-/tmp/shieldagi-test-repo}"
REPORT_PATH="${TEST_REPORT_PATH:-/tmp/shieldagi-test-report.json}"
PASSED=0
FAILED=0

run_test() {
    local name="$1"
    local cmd="$2"
    echo -n "  Testing $name... "
    if eval "$cmd" >/dev/null 2>&1; then
        echo "PASS"
        PASSED=$((PASSED+1))
    else
        echo "FAIL"
        FAILED=$((FAILED+1))
    fi
}

echo ""
echo "[Phase 2.1] Framework detection..."
run_test "detect framework" "test -f '$REPO_PATH/package.json' || test -f '$REPO_PATH/manage.py' || test -f '$REPO_PATH/Cargo.toml'"

echo ""
echo "[Phase 2.2] Report loading..."
if [ -f "$REPORT_PATH" ]; then
    run_test "report valid JSON" "python3 -c \"import json; json.load(open('$REPORT_PATH'))\""
    VULN_COUNT=$(python3 -c "import json; r=json.load(open('$REPORT_PATH')); print(len(r.get('vulnerabilities',[])))" 2>/dev/null || echo "0")
    echo "  Found $VULN_COUNT vulnerabilities in report"
else
    echo "  [SKIP] No test report at $REPORT_PATH"
fi

echo ""
echo "[Phase 2.3] Git operations..."
run_test "git available" "command -v git"
run_test "repo is git" "cd '$REPO_PATH' && git status 2>/dev/null"

echo ""
echo "[Phase 2.4] Test runner..."
run_test "npm test exists" "test -f '$REPO_PATH/package.json' && cd '$REPO_PATH' && npm test 2>/dev/null"

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
