#!/usr/bin/env bash
# ==============================================================================
# Linux File Permission Analyzer (LfPA) - Automated Test Suite
# Course: 25CS2104E - Operating Systems and Systems Programming (OSSP)
# Runs 8 comprehensive test assertions with PASS/FAIL metrics
# ==============================================================================

set -u

ANALYZER_BIN="./bin/analyzer"
SANDBOX="./demo_sandbox"
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Colors for terminal reporting
C_GREEN="\033[1;32m"
C_RED="\033[1;31m"
C_YELLOW="\033[1;33m"
C_BLUE="\033[1;34m"
C_RESET="\033[0m"

assert_equal() {
    local test_name="$1"
    local expected="$2"
    local actual="$3"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if [ "$expected" = "$actual" ]; then
        echo -e "  [${C_GREEN}PASS${C_RESET}] ${test_name}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  [${C_RED}FAIL${C_RESET}] ${test_name} (Expected: '$expected', Got: '$actual')"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

assert_contains() {
    local test_name="$1"
    local needle="$2"
    local haystack="$3"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if echo "$haystack" | grep -F -q "$needle"; then
        echo -e "  [${C_GREEN}PASS${C_RESET}] ${test_name}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "  [${C_RED}FAIL${C_RESET}] ${test_name} (Output did not contain: '$needle')"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

echo -e "\n${C_BLUE}======================================================================${C_RESET}"
echo -e "${C_BLUE}   LINUX FILE PERMISSION ANALYZER - AUTOMATED TEST SUITE (CO1-CO6)   ${C_RESET}"
echo -e "${C_BLUE}======================================================================${C_RESET}\n"

# ------------------------------------------------------------------------------
# Test 1: Compilation Sanity
# ------------------------------------------------------------------------------
echo -e "${C_YELLOW}[TEST 1] Compilation & Binary Generation (gcc, make)${C_RESET}"
make clean >/dev/null 2>&1 || true
make all >/dev/null 2>&1
if [ -f "$ANALYZER_BIN" ]; then
    assert_equal "Binary successfully compiled at $ANALYZER_BIN" "yes" "yes"
else
    assert_equal "Binary successfully compiled at $ANALYZER_BIN" "yes" "no"
    exit 1
fi

# Detect if local filesystem supports POSIX permission bits (e.g. not Windows DrvFs mount)
touch .test_posix_perm
chmod 600 .test_posix_perm 2>/dev/null || true
CURR_P=$(stat -c "%a" .test_posix_perm 2>/dev/null || stat -f "%OLp" .test_posix_perm 2>/dev/null || echo "")
rm -f .test_posix_perm

if [ "$CURR_P" != "600" ]; then
    echo -e "${C_YELLOW}[!] Notice: Local filesystem does not persist POSIX permission bits (DrvFs detected).${C_RESET}"
    echo -e "    Redirecting automated test sandbox to '/tmp/demo_sandbox' for POSIX compliance.\n"
    SANDBOX="/tmp/demo_sandbox"
else
    SANDBOX="./demo_sandbox"
fi

# Re-setup sandbox
bash scripts/setup_sandbox.sh "$SANDBOX" >/dev/null 2>&1

# ------------------------------------------------------------------------------
# Test 2: Basic Scan Execution & Exit Code
# ------------------------------------------------------------------------------
echo -e "\n${C_YELLOW}[TEST 2] Basic VFS Traversal on Sandbox Directory${C_RESET}"
OUTPUT=$($ANALYZER_BIN -p "$SANDBOX")
EXIT_CODE=$?
assert_equal "Analyzer exited with code 0" "0" "$EXIT_CODE"
assert_contains "Summary report contains scanned files" "Files Inspected" "$OUTPUT"

# ------------------------------------------------------------------------------
# Test 3: SUID and SGID Special Bit Detection
# ------------------------------------------------------------------------------
echo -e "\n${C_YELLOW}[TEST 3] Special Permissions Detection (SUID & SGID Bitmasks)${C_RESET}"
assert_contains "Detection of SUID bit (SEC-002)" "SEC-002" "$OUTPUT"
assert_contains "Detection of SGID bit (SEC-003)" "SEC-003" "$OUTPUT"

# ------------------------------------------------------------------------------
# Test 4: Sticky Bit on World-Writable Directory
# ------------------------------------------------------------------------------
echo -e "\n${C_YELLOW}[TEST 4] Sticky Bit Absence Detection (SEC-004)${C_RESET}"
assert_contains "Detection of World-Writable Directory lacking Sticky Bit" "SEC-004" "$OUTPUT"

# ------------------------------------------------------------------------------
# Test 5: Sensitive Credentials and Private Key Detection
# ------------------------------------------------------------------------------
echo -e "\n${C_YELLOW}[TEST 5] Sensitive Credential Exposure (SEC-005 on id_rsa and .env)${C_RESET}"
assert_contains "Detection of exposed private key/secrets" "SEC-005" "$OUTPUT"

# ------------------------------------------------------------------------------
# Test 6: Rule #7 Safety Guardrail Enforcement (Protect /etc, /bin, etc.)
# ------------------------------------------------------------------------------
echo -e "\n${C_YELLOW}[TEST 6] Safety Guardrail Refusal on Protected System Paths${C_RESET}"
GUARD_OUTPUT=$($ANALYZER_BIN -p /etc --fix 2>&1 || true)
assert_contains "Guardrail refusal or protection trigger" "System path is protected" "$GUARD_OUTPUT"

# ------------------------------------------------------------------------------
# Test 7: Auto-Remediation Dry-Run Simulation
# ------------------------------------------------------------------------------
echo -e "\n${C_YELLOW}[TEST 7] Dry-Run Mode Safety Simulation${C_RESET}"
DRY_OUTPUT=$($ANALYZER_BIN -p "$SANDBOX" --fix --dry-run)
assert_contains "Dry-run simulation marker present" "[DRY-RUN]" "$DRY_OUTPUT"
# Verify file permission was NOT altered in dry-run
CURRENT_MODE=$(stat -c "%a" "$SANDBOX/credentials/id_rsa" 2>/dev/null || stat -f "%OLp" "$SANDBOX/credentials/id_rsa")
assert_equal "id_rsa mode remained 644 during dry-run" "644" "$CURRENT_MODE"

# ------------------------------------------------------------------------------
# Test 8: Live Process-Isolated Auto-Remediation (CO2: fork/waitpid/chmod)
# ------------------------------------------------------------------------------
echo -e "\n${C_YELLOW}[TEST 8] Live Auto-Remediation Execution${C_RESET}"
FIX_OUTPUT=$($ANALYZER_BIN -p "$SANDBOX" --fix)
assert_contains "Auto-remediation engine executed" "AUTO-REMEDIATION ENGINE RUNNING" "$FIX_OUTPUT"

# Verify permissions were safely updated
FIXED_ID_RSA=$(stat -c "%a" "$SANDBOX/credentials/id_rsa" 2>/dev/null || stat -f "%OLp" "$SANDBOX/credentials/id_rsa")
assert_equal "id_rsa successfully hardened to 600" "600" "$FIXED_ID_RSA"

# ------------------------------------------------------------------------------
# Test 9: HTML and JSON Report Generation
# ------------------------------------------------------------------------------
echo -e "\n${C_YELLOW}[TEST 9] Export Reports Generation (POSIX open/write/close)${C_RESET}"
rm -f report_test.html report_test.json
$ANALYZER_BIN -p "$SANDBOX" -o report_test.html >/dev/null 2>&1
$ANALYZER_BIN -p "$SANDBOX" -o report_test.json >/dev/null 2>&1

if [ -s "report_test.html" ]; then
    assert_equal "HTML report created and non-empty" "yes" "yes"
else
    assert_equal "HTML report created and non-empty" "yes" "no"
fi

if [ -s "report_test.json" ]; then
    assert_equal "JSON report created and non-empty" "yes" "yes"
else
    assert_equal "JSON report created and non-empty" "yes" "no"
fi

rm -f report_test.html report_test.json

# ------------------------------------------------------------------------------
# Test Summary
# ------------------------------------------------------------------------------
echo -e "\n${C_BLUE}======================================================================${C_RESET}"
echo -e "  TOTAL TESTS RUN : ${TOTAL_TESTS}"
echo -e "  PASSED          : ${C_GREEN}${PASSED_TESTS}${C_RESET}"
echo -e "  FAILED          : ${C_RED}${FAILED_TESTS}${C_RESET}"
echo -e "${C_BLUE}======================================================================${C_RESET}\n"

if [ "$FAILED_TESTS" -eq 0 ]; then
    echo -e "${C_GREEN}[✓] ALL TEST SUITE ASSERTIONS PASSED WITH 100% SUCCESS!${C_RESET}\n"
    exit 0
else
    echo -e "${C_RED}[✗] SOME TEST ASSERTIONS FAILED.${C_RESET}\n"
    exit 1
fi
