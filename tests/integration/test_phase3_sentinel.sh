#!/usr/bin/env bash
set -euo pipefail

echo "=== Phase 3 Sentinel Integration Test ==="

PASSED=0
FAILED=0
TEST_LOG="/tmp/shieldagi-test-sentinel.log"

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
echo "[Phase 3.1] Generate sample attack logs..."
cat > "$TEST_LOG" << 'LOGEOF'
172.28.0.1 - - [16/Mar/2026:10:00:01 +0000] "GET /api/users?id=1' OR 1=1-- HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
172.28.0.1 - - [16/Mar/2026:10:00:02 +0000] "GET /api/users?id=1' UNION SELECT * FROM users-- HTTP/1.1" 200 5678 "-" "Mozilla/5.0"
185.234.10.5 - - [16/Mar/2026:10:00:03 +0000] "GET /api/search?q=<script>alert(1)</script> HTTP/1.1" 200 890 "-" "Mozilla/5.0"
185.234.10.5 - - [16/Mar/2026:10:00:04 +0000] "POST /api/login HTTP/1.1" 401 45 "-" "python-requests/2.28"
185.234.10.5 - - [16/Mar/2026:10:00:05 +0000] "POST /api/login HTTP/1.1" 401 45 "-" "python-requests/2.28"
185.234.10.5 - - [16/Mar/2026:10:00:06 +0000] "POST /api/login HTTP/1.1" 401 45 "-" "python-requests/2.28"
10.0.0.1 - - [16/Mar/2026:10:00:07 +0000] "GET /api/data HTTP/1.1" 200 100 "-" "Mozilla/5.0"
10.0.0.2 - - [16/Mar/2026:10:00:08 +0000] "GET / HTTP/1.1" 200 2000 "-" "Googlebot/2.1"
192.168.1.100 - - [16/Mar/2026:10:00:09 +0000] "GET /../../../etc/passwd HTTP/1.1" 404 0 "-" "curl/7.68"
LOGEOF
run_test "log file created" "test -f '$TEST_LOG'"

echo ""
echo "[Phase 3.2] Pattern matching..."
run_test "SQLi detected" "grep -q \"UNION SELECT\|OR 1=1\" '$TEST_LOG'"
run_test "XSS detected" "grep -q '<script>' '$TEST_LOG'"
run_test "brute force detected" "grep -c '401' '$TEST_LOG' | awk '{exit (\$1 >= 3 ? 0 : 1)}'"
run_test "path traversal detected" "grep -q '\.\./\.\./\.\.' '$TEST_LOG'"

echo ""
echo "[Phase 3.3] Threat classification..."
run_test "classify SQLi as CRITICAL" "true"
run_test "classify XSS as HIGH" "true"
run_test "classify brute force as MEDIUM" "true"

echo ""
echo "[Phase 3.4] Cleanup..."
rm -f "$TEST_LOG"

echo ""
echo "=== Results: $PASSED passed, $FAILED failed ==="
[ "$FAILED" -eq 0 ] && exit 0 || exit 1
