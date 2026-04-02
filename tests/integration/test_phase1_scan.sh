#!/usr/bin/env bash
set -euo pipefail

echo "=== Phase 1 Scan Integration Test ==="

SANDBOX_TARGET="${SANDBOX_TARGET:-http://172.28.0.10:3000}"
REPO_PATH="${TEST_REPO_PATH:-/tmp/shieldagi-test-repo}"
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
echo "[Phase 1.1] Port scanning..."
run_test "nmap_scan" "curl -s '$SANDBOX_TARGET' --connect-timeout 5"

echo ""
echo "[Phase 1.2] Static analysis..."
run_test "semgrep available" "command -v semgrep"
run_test "repo exists" "test -d '$REPO_PATH'"

echo ""
echo "[Phase 1.3] Dependency audit..."
run_test "npm audit" "cd '$REPO_PATH' && npm audit --json 2>/dev/null"

echo ""
echo "[Phase 1.4] Secret scanning..."
run_test "gitleaks" "command -v gitleaks || command -v trufflehog"

echo ""
echo "[Phase 1.5] Header audit..."
run_test "security headers" "curl -sI '$SANDBOX_TARGET' | grep -qi 'x-content-type'"

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
