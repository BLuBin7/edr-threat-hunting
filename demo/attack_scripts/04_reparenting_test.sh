#!/bin/bash
# Demo Attack Scenario 4: Process Reparenting Test
# Simulates process orphanage where a child process gets reparented to init (PID 1)

echo "=========================================="
echo "Demo Test: Process Reparenting (PPID)"
echo "=========================================="
echo ""

# Current shell PID
SHELL_PID=$$
echo "Current Shell PID: $SHELL_PID"

echo "Spawning a background child process under a transient subshell..."
# Start a subshell that spawns a sleep process and exits immediately
(
    sleep 20 &
    CHILD_PID=$!
    echo "  [Subshell] Spawned sleep process (PID: $CHILD_PID)"
)

# Wait 1 second for subshell to exit and reparenting to occur
sleep 1

# Check the new PPID of the sleep process from OS view
CHILD_PID=$(pgrep -f "sleep 20" | head -n 1)
if [ -z "$CHILD_PID" ]; then
    echo "Error: sleep process not found!"
    exit 1
fi

NEW_PPID=$(ps -o ppid= -p $CHILD_PID | tr -d ' ')
echo ""
echo "From OS perspective (/proc or ps):"
echo "  Child Process PID: $CHILD_PID"
echo "  New Parent PID (PPID): $NEW_PPID"
if [ "$NEW_PPID" -eq 1 ] || [ "$NEW_PPID" -eq 999 ]; then
    echo "  ✓ Successfully reparented to init/systemd (PID 1)!"
else
    echo "  ✓ Reparented to process reaper (PPID: $NEW_PPID)"
fi
echo ""
echo "Expected EDR Detection:"
echo "  The EDR Agent's Context Engine retains the true parent-child lineage"
echo "  and links it back to bash ($SHELL_PID) instead of the process reaper."
echo "=========================================="
