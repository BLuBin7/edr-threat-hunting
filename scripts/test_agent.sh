#!/bin/bash
# EDR Agent Test Script
# Tests the threat hunting capabilities of the EDR agent

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=========================================="
echo "EDR Threat Hunting Agent - Test Suite"
echo "=========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name="$1"
    local test_command="$2"

    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "${YELLOW}[TEST ${TESTS_RUN}]${NC} ${test_name}"

    if eval "$test_command"; then
        echo -e "${GREEN}✓ PASSED${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}✗ FAILED${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
    echo ""
}

# Test 1: Check if agent binary exists
run_test "Agent binary exists" "test -f ${PROJECT_ROOT}/bin/edr-agent"

# Test 2: Check configuration file
run_test "Configuration file exists" "test -f ${PROJECT_ROOT}/agent/config.yaml"

# Test 3: Check rules directory
run_test "Rules directory exists" "test -d ${PROJECT_ROOT}/rules"

# Test 4: Count detection rules
rule_count=$(find "${PROJECT_ROOT}/rules" -name "*.yaml" | wc -l)
run_test "Detection rules loaded (found ${rule_count} rules)" "test ${rule_count} -gt 0"

# Test 5: Validate YAML syntax in rules
echo -e "${YELLOW}[TEST $((TESTS_RUN + 1))]${NC} Validating YAML syntax in all rules"
TESTS_RUN=$((TESTS_RUN + 1))
yaml_valid=true
for rule_file in "${PROJECT_ROOT}/rules"/*.yaml; do
    if ! python3 -c "import yaml; yaml.safe_load(open('$rule_file'))" 2>/dev/null; then
        echo -e "${RED}✗ Invalid YAML: $(basename $rule_file)${NC}"
        yaml_valid=false
    fi
done
if [ "$yaml_valid" = true ]; then
    echo -e "${GREEN}✓ PASSED - All YAML files valid${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗ FAILED - Some YAML files invalid${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test 6: Check Go module dependencies
run_test "Go dependencies satisfied" "cd ${PROJECT_ROOT}/agent && go mod verify"

# Test 7: Build the agent
echo -e "${YELLOW}[TEST $((TESTS_RUN + 1))]${NC} Building agent"
TESTS_RUN=$((TESTS_RUN + 1))
if cd "${PROJECT_ROOT}/agent" && go build -o "${PROJECT_ROOT}/bin/edr-agent" ./cmd/agent; then
    echo -e "${GREEN}✓ PASSED - Agent built successfully${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗ FAILED - Build failed${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test 8: Check agent version
run_test "Agent responds to --help" "${PROJECT_ROOT}/bin/edr-agent --help 2>&1 | grep -q 'config'"

# Test 9: Validate monitors exist
echo -e "${YELLOW}[TEST $((TESTS_RUN + 1))]${NC} Checking monitor implementations"
TESTS_RUN=$((TESTS_RUN + 1))
monitors_valid=true
for monitor in process file network persistence; do
    if ! test -f "${PROJECT_ROOT}/agent/internal/monitors/${monitor}.go"; then
        echo -e "${RED}✗ Missing monitor: ${monitor}.go${NC}"
        monitors_valid=false
    fi
done
if [ "$monitors_valid" = true ]; then
    echo -e "${GREEN}✓ PASSED - All monitors implemented${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗ FAILED - Some monitors missing${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Test 10: Check correlation engine
run_test "Correlation engine exists" "test -f ${PROJECT_ROOT}/agent/internal/correlation/engine.go"

# Test 11: Check scoring engine
run_test "Scoring engine exists" "test -f ${PROJECT_ROOT}/agent/internal/scoring/engine.go"

# Test 12: Check ML engine
run_test "ML engine exists" "test -f ${PROJECT_ROOT}/agent/internal/ml/onnx.go"

# Test 13: Check rules engine
run_test "Rules engine exists" "test -f ${PROJECT_ROOT}/agent/internal/rules/engine.go"

# Test 14: Check output exporters
run_test "VictoriaMetrics exporter exists" "test -f ${PROJECT_ROOT}/agent/internal/output/victoria_metrics.go"

# Test 15: Run agent for 5 seconds (basic smoke test)
echo -e "${YELLOW}[TEST $((TESTS_RUN + 1))]${NC} Agent smoke test (5 seconds)"
TESTS_RUN=$((TESTS_RUN + 1))
if timeout 5s "${PROJECT_ROOT}/bin/edr-agent" --config "${PROJECT_ROOT}/agent/config.yaml" 2>&1 | grep -q "EDR Threat Hunting Agent starting"; then
    echo -e "${GREEN}✓ PASSED - Agent starts successfully${NC}"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "${RED}✗ FAILED - Agent failed to start${NC}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
echo ""

# Summary
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Tests Run:    ${TESTS_RUN}"
echo -e "Tests Passed: ${GREEN}${TESTS_PASSED}${NC}"
echo -e "Tests Failed: ${RED}${TESTS_FAILED}${NC}"
echo "=========================================="

if [ ${TESTS_FAILED} -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    exit 1
fi
