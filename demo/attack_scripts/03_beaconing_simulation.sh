#!/bin/bash
# Demo Attack Scenario 3: C2 Beaconing Simulation
# Simulates periodic network connections to simulate Command & Control communication

echo "=========================================="
echo "Demo Attack: C2 Beaconing"
echo "=========================================="
echo ""
echo "Simulating: Periodic HTTP requests to simulate C2 beaconing"
echo "Expected Detection: HIGH severity (beaconing pattern)"
echo ""

BEACON_INTERVAL=5  # seconds
BEACON_COUNT=10
TARGET_HOST="example.com"
TARGET_PORT=80

echo "Configuration:"
echo "  Target: $TARGET_HOST:$TARGET_PORT"
echo "  Interval: ${BEACON_INTERVAL}s"
echo "  Count: $BEACON_COUNT beacons"
echo ""

for i in $(seq 1 $BEACON_COUNT); do
    echo "[Beacon $i/$BEACON_COUNT] Connecting to $TARGET_HOST..."

    # Simulate HTTP request
    timeout 2 bash -c "echo -e 'GET / HTTP/1.0\r\n\r\n' | nc $TARGET_HOST $TARGET_PORT" > /dev/null 2>&1

    if [ $? -eq 0 ]; then
        echo "  ✓ Connection successful ($(date '+%H:%M:%S'))"
    else
        echo "  ✗ Connection failed (expected, just simulating pattern)"
    fi

    # Sleep for fixed interval (creates low variance = beaconing pattern)
    if [ $i -lt $BEACON_COUNT ]; then
        sleep $BEACON_INTERVAL
    fi
done

echo ""
echo "✅ Attack simulation completed"
echo ""
echo "Expected EDR Detection:"
echo "  - Network connections: $BEACON_COUNT connections"
echo "  - Low interval variance: ~${BEACON_INTERVAL}s ± 0.5s"
echo "  - Beaconing score: >0.8 (HIGH)"
echo "  - Threat Score: ~0.75-0.85 (HIGH)"
echo "  - MITRE: TA0011 - Command and Control"
echo "  - MITRE: T1071 - Application Layer Protocol"
echo ""
echo "Check EDR agent logs for network beaconing detection"
echo "=========================================="
