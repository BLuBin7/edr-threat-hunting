#!/bin/bash
# Demo Attack Scenario 1: Encoded PowerShell Command Execution
# This simulates a common attack pattern where PowerShell is used with encoded commands

echo "=========================================="
echo "Demo Attack: Encoded PowerShell Execution"
echo "=========================================="
echo ""
echo "Simulating: bash → sh → base64-encoded command"
echo "Expected Detection: HIGH severity (encoded command + suspicious lineage)"
echo ""

# Check if running on Linux (PowerShell might not be available)
if ! command -v pwsh &> /dev/null; then
    echo "⚠️  PowerShell not found, simulating with bash equivalent"

    # Simulate the attack pattern with bash
    echo "[Step 1] Parent: bash process"

    echo "[Step 2] Child: sh with long commandline"
    /bin/sh -c "echo 'aGVsbG8gd29ybGQ=' | base64 -d" &
    CHILD_PID=$!

    echo "[Step 3] Encoded command execution (base64)"
    echo "   Command: echo 'aGVsbG8gd29ybGQ=' | base64 -d"
    echo "   Decoded: hello world"

    wait $CHILD_PID
else
    echo "[Step 1] Parent: bash process"

    echo "[Step 2] Child: PowerShell with encoded command"
    # Base64 encoded: Write-Host "This is a test"
    ENCODED_CMD="VwByAGkAdABlAC0ASABvAHMAdAAgACIAVABoAGkAcwAgAGkAcwAgAGEAIAB0AGUAcwB0ACIA"

    pwsh -EncodedCommand "$ENCODED_CMD" &
    CHILD_PID=$!

    echo "[Step 3] PowerShell executing encoded command"
    echo "   Encoded: $ENCODED_CMD"

    wait $CHILD_PID
fi

echo ""
echo "✅ Attack simulation completed"
echo ""
echo "Expected EDR Detection:"
echo "  - Process lineage: bash → sh/pwsh"
echo "  - High commandline entropy"
echo "  - Encoded command flag: TRUE"
echo "  - Threat Score: ~0.75-0.85 (HIGH)"
echo "  - MITRE: T1059 - Command and Scripting Interpreter"
echo ""
echo "Check EDR agent logs and Grafana dashboard for alerts"
echo "=========================================="
