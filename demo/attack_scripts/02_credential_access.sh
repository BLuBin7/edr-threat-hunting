#!/bin/bash
# Demo Attack Scenario 2: Credential Access (Sensitive File Access)
# Simulates credential dumping by accessing sensitive files

echo "=========================================="
echo "Demo Attack: Credential Access"
echo "=========================================="
echo ""
echo "Simulating: Sensitive file access (/etc/shadow, /etc/passwd)"
echo "Expected Detection: HIGH/CRITICAL severity"
echo ""

echo "[Step 1] Attempting to read /etc/passwd"
cat /etc/passwd | head -n 5
sleep 1

echo ""
echo "[Step 2] Attempting to read /etc/shadow (requires root)"
if [ "$EUID" -eq 0 ]; then
    cat /etc/shadow | head -n 3 2>/dev/null || echo "  ⚠️  Access denied (normal behavior)"
else
    echo "  ⚠️  Not running as root, skipping /etc/shadow"
    echo "  (In real attack, attacker would escalate privileges first)"
fi
sleep 1

echo ""
echo "[Step 3] Accessing SSH keys"
if [ -d "$HOME/.ssh" ]; then
    ls -la "$HOME/.ssh/" 2>/dev/null || echo "  ℹ️  No SSH keys found"
else
    echo "  ℹ️  ~/.ssh directory not found"
fi

echo ""
echo "✅ Attack simulation completed"
echo ""
echo "Expected EDR Detection:"
echo "  - Sensitive file access: /etc/passwd, /etc/shadow"
echo "  - File Monitor: Multiple sensitive file reads"
echo "  - Threat Score: ~0.80-0.90 (HIGH/CRITICAL)"
echo "  - MITRE: TA0006 - Credential Access"
echo "  - MITRE: T1003 - OS Credential Dumping"
echo ""
echo "Check EDR agent logs for file access events"
echo "=========================================="
