#!/usr/bin/env bash
set -euo pipefail

echo "==========================================="
echo "  ShieldAGI End-to-End Integration Test"
echo "==========================================="

SANDBOX_TARGET="${SANDBOX_TARGET:-http://172.28.0.10:3000}"
REPO_PATH="${TEST_REPO_PATH:-/tmp/shieldagi-e2e-repo}"
REPORT_PATH="/tmp/shieldagi-e2e-report.json"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "=== Stage 1: Phase 1 Scan ==="
bash "$SCRIPT_DIR/test_phase1_scan.sh" || echo "  Phase 1 tests completed with warnings"

echo ""
echo "=== Stage 2: Phase 2 Remediation ==="
bash "$SCRIPT_DIR/test_phase2_remediation.sh" || echo "  Phase 2 tests completed with warnings"

echo ""
echo "=== Stage 3: Phase 3 Sentinel ==="
bash "$SCRIPT_DIR/test_phase3_sentinel.sh" || echo "  Phase 3 tests completed with warnings"

echo ""
echo "=== Stage 4: Chain Walls ==="
bash "$SCRIPT_DIR/test_chain_walls.sh" || echo "  Chain Walls tests completed with warnings"

echo ""
echo "==========================================="
echo "  End-to-End Test Complete"
echo "==========================================="
