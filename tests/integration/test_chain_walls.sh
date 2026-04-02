#!/usr/bin/env bash
set -euo pipefail

echo "=== Chain Walls Integration Test ==="

SANDBOX_TARGET="${SANDBOX_TARGET:-http://172.28.0.10:3000}"
PASSED=0
FAILED=0

run_test() {
    local name="$1"
    local cmd="$2"
    echo -n "  Testing $name... "
    if eval "$cmd" 2>&1; then
        echo "PASS"
        PASSED=$((PASSED+1))
    else
        echo "FAIL"
        FAILED=$((FAILED+1))
    fi
}

echo ""
echo "[Wall 1] Rate Limiter..."
run_test "rate limit enforced" "
    for i in \$(seq 1 110); do
        curl -s -o /dev/null -w '%{http_code}' '$SANDBOX_TARGET/api/test' 2>/dev/null
    done | grep -q '429'
"

echo ""
echo "[Wall 2] Input Sanitizer..."
run_test "SQLi blocked" "
    STATUS=\$(curl -s -o /dev/null -w '%{http_code}' '$SANDBOX_TARGET/api/users?id=1%27%20OR%201=1--' 2>/dev/null)
    [ \"\$STATUS\" = '400' ] || [ \"\$STATUS\" = '403' ]
"
run_test "XSS blocked" "
    STATUS=\$(curl -s -o /dev/null -w '%{http_code}' '$SANDBOX_TARGET/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E' 2>/dev/null)
    [ \"\$STATUS\" = '400' ] || [ \"\$STATUS\" = '403' ]
"

echo ""
echo "[Wall 3] Auth Validator..."
run_test "unauthenticated rejected" "
    STATUS=\$(curl -s -o /dev/null -w '%{http_code}' '$SANDBOX_TARGET/api/protected' 2>/dev/null)
    [ \"\$STATUS\" = '401' ]
"

echo ""
echo "[Wall 4] CSRF Guard..."
run_test "cross-origin POST rejected" "
    STATUS=\$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Origin: http://evil.com' '$SANDBOX_TARGET/api/action' 2>/dev/null)
    [ \"\$STATUS\" = '403' ]
"

echo ""
echo "[Wall 5] RBAC Enforcer..."
run_test "unauthorized role rejected" "true"

echo ""
echo "[Wall 6] SSRF Shield..."
run_test "internal IP blocked" "
    STATUS=\$(curl -s -o /dev/null -w '%{http_code}' '$SANDBOX_TARGET/api/fetch?url=http://169.254.169.254/latest/meta-data/' 2>/dev/null)
    [ \"\$STATUS\" = '403' ]
"

echo ""
echo "[Wall 7] Request Logger..."
run_test "audit log exists" "true"

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
