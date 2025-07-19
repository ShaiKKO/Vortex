#!/bin/bash

# OCaml Crypto Linter Test Runner
# Tests various vulnerability patterns and output formats

set -e

LINTER="opam exec -- dune exec bin/main_simple.exe --"
TEST_DIR="test_samples"
RESULTS_DIR="test_results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== OCaml Crypto Linter Test Suite ===${NC}"
echo

# Create results directory
mkdir -p "$RESULTS_DIR"

# Function to run test
run_test() {
    local test_name=$1
    local test_file=$2
    local expected_rules=$3
    
    echo -e "${YELLOW}Testing: $test_name${NC}"
    echo "File: $test_file"
    echo "Expected rules: $expected_rules"
    
    # Run linter with text output
    echo -e "\n${BLUE}Text output:${NC}"
    $LINTER "$test_file" -f text || true
    
    # Run with JSON output
    $LINTER "$test_file" -f json -o "$RESULTS_DIR/${test_name}.json" || true
    
    # Check if expected rules were found
    if [ -n "$expected_rules" ]; then
        for rule in $expected_rules; do
            if grep -q "\"rule_id\": \"$rule\"" "$RESULTS_DIR/${test_name}.json"; then
                echo -e "${GREEN}✓ Found expected rule: $rule${NC}"
            else
                echo -e "${RED}✗ Missing expected rule: $rule${NC}"
            fi
        done
    fi
    
    echo -e "\n---\n"
}

# Test 1: Hardcoded Keys
run_test "hardcoded_keys" \
    "$TEST_DIR/vulnerable/hardcoded_keys.ml" \
    "KEY001"

# Test 2: Weak Algorithms
run_test "weak_algorithms" \
    "$TEST_DIR/vulnerable/weak_algorithms.ml" \
    "ALGO001 ALGO002 ALGO003"

# Test 3: Timing Attacks
run_test "timing_attacks" \
    "$TEST_DIR/vulnerable/timing_attacks.ml" \
    "SIDE001"

# Test 4: API Misuse
run_test "api_misuse" \
    "$TEST_DIR/vulnerable/api_misuse.ml" \
    "API001 API002 API003 API005"

# Test 5: Secure Code (should have minimal/no findings)
run_test "secure_code" \
    "$TEST_DIR/secure/good_crypto.ml" \
    ""

# Test 6: Real-world JWT
run_test "jwt_implementation" \
    "$TEST_DIR/real_world/jwt_implementation.ml" \
    "KEY001 SIDE001 API005"

# Test SARIF output
echo -e "${YELLOW}Testing SARIF output format:${NC}"
$LINTER "$TEST_DIR/vulnerable/weak_algorithms.ml" -f sarif -o "$RESULTS_DIR/sarif_test.sarif"
echo -e "${GREEN}✓ SARIF output generated${NC}"

# Test multiple files at once
echo -e "\n${YELLOW}Testing multiple file analysis:${NC}"
$LINTER "$TEST_DIR/vulnerable/"*.ml -f json -o "$RESULTS_DIR/all_vulnerable.json"
TOTAL_FINDINGS=$(jq '.summary.total_findings' "$RESULTS_DIR/all_vulnerable.json")
echo -e "Total findings across all vulnerable files: ${RED}$TOTAL_FINDINGS${NC}"

# Summary report
echo -e "\n${BLUE}=== Test Summary ===${NC}"
echo "Results saved in: $RESULTS_DIR/"
echo
echo "JSON reports:"
ls -la "$RESULTS_DIR"/*.json

# Generate summary statistics
echo -e "\n${BLUE}Finding Statistics:${NC}"
for json_file in "$RESULTS_DIR"/*.json; do
    if [ -f "$json_file" ]; then
        name=$(basename "$json_file" .json)
        if [[ "$json_file" != *"sarif"* ]]; then
            findings=$(jq '.summary.total_findings // .findings | length' "$json_file" 2>/dev/null || echo "0")
            echo "$name: $findings findings"
        fi
    fi
done

echo -e "\n${GREEN}Test suite completed!${NC}"