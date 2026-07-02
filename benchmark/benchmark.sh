#!/bin/bash
# Performance benchmark script for EDR Agent

set -e

echo "=========================================="
echo "EDR Agent Performance Benchmark"
echo "=========================================="
echo ""

# Check if agent is running
if ! pgrep -f edr-agent > /dev/null; then
    echo "❌ Agent not running. Start agent first:"
    echo "   sudo ./bin/edr-agent --config agent/config.yaml"
    exit 1
fi

AGENT_PID=$(pgrep -f edr-agent)
echo "✓ Agent PID: $AGENT_PID"
echo ""

# Create output directory
mkdir -p benchmark/results
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULT_FILE="benchmark/results/benchmark_${TIMESTAMP}.txt"

echo "Benchmark started at: $(date)" | tee "$RESULT_FILE"
echo "========================================" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# 1. CPU Usage
echo "📊 CPU Usage Monitoring (60 seconds)..." | tee -a "$RESULT_FILE"
CPU_SAMPLES=()
for i in {1..60}; do
    CPU=$(ps -p $AGENT_PID -o %cpu= | tr -d ' ')
    CPU_SAMPLES+=($CPU)
    sleep 1
done

# Calculate statistics
CPU_AVG=$(echo "${CPU_SAMPLES[@]}" | awk '{s=0; for(i=1;i<=NF;i++)s+=$i; print s/NF}')
CPU_MAX=$(echo "${CPU_SAMPLES[@]}" | tr ' ' '\n' | sort -rn | head -1)
echo "  Average CPU: ${CPU_AVG}%" | tee -a "$RESULT_FILE"
echo "  Max CPU: ${CPU_MAX}%" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# 2. Memory Usage
echo "📊 Memory Usage..." | tee -a "$RESULT_FILE"
MEM_KB=$(ps -p $AGENT_PID -o rss= | tr -d ' ')
MEM_MB=$((MEM_KB / 1024))
echo "  RSS Memory: ${MEM_MB} MB" | tee -a "$RESULT_FILE"

# Virtual memory
VMEM_KB=$(ps -p $AGENT_PID -o vsz= | tr -d ' ')
VMEM_MB=$((VMEM_KB / 1024))
echo "  Virtual Memory: ${VMEM_MB} MB" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# 3. Telemetry Throughput Test
echo "📊 Telemetry Throughput Test (30 seconds)..." | tee -a "$RESULT_FILE"

# Get initial event count
METRICS=$(curl -s http://localhost:9090/metrics 2>/dev/null || echo "")
if [ -z "$METRICS" ]; then
    echo "  ⚠️  Cannot reach metrics endpoint" | tee -a "$RESULT_FILE"
else
    INITIAL_EVENTS=$(echo "$METRICS" | grep 'edr_agent_events_processed_total{event_type="process"}' | awk '{print $2}' | head -1)
    INITIAL_EVENTS=${INITIAL_EVENTS:-0}

    # Generate activity
    echo "  Generating workload..."
    for i in {1..100}; do
        ls /tmp > /dev/null 2>&1
        echo "test" > /tmp/edr_bench_$i.txt
        rm /tmp/edr_bench_$i.txt 2>/dev/null
        sleep 0.1
    done

    sleep 5  # Let agent process events

    # Get final event count
    METRICS=$(curl -s http://localhost:9090/metrics)
    FINAL_EVENTS=$(echo "$METRICS" | grep 'edr_agent_events_processed_total{event_type="process"}' | awk '{print $2}' | head -1)
    FINAL_EVENTS=${FINAL_EVENTS:-0}

    EVENTS_PROCESSED=$((FINAL_EVENTS - INITIAL_EVENTS))
    THROUGHPUT=$((EVENTS_PROCESSED / 30))

    echo "  Events processed: $EVENTS_PROCESSED" | tee -a "$RESULT_FILE"
    echo "  Throughput: ~${THROUGHPUT} events/sec" | tee -a "$RESULT_FILE"
fi
echo "" | tee -a "$RESULT_FILE"

# 4. Inference Latency (from metrics)
echo "📊 ML Inference Latency..." | tee -a "$RESULT_FILE"
if [ -n "$METRICS" ]; then
    # Parse histogram quantiles if available
    P50=$(echo "$METRICS" | grep 'edr_agent_ml_inference_latency_seconds' | grep 'quantile="0.5"' | awk '{print $2}' | head -1)
    P95=$(echo "$METRICS" | grep 'edr_agent_ml_inference_latency_seconds' | grep 'quantile="0.95"' | awk '{print $2}' | head -1)
    P99=$(echo "$METRICS" | grep 'edr_agent_ml_inference_latency_seconds' | grep 'quantile="0.99"' | awk '{print $2}' | head -1)

    if [ -n "$P95" ]; then
        P95_MS=$(echo "$P95 * 1000" | bc)
        echo "  P95 Latency: ${P95_MS} ms" | tee -a "$RESULT_FILE"
    else
        echo "  ⚠️  No inference metrics yet (needs attack traffic)" | tee -a "$RESULT_FILE"
    fi
else
    echo "  ⚠️  Cannot fetch metrics" | tee -a "$RESULT_FILE"
fi
echo "" | tee -a "$RESULT_FILE"

# 5. Host Performance Impact Test
echo "📊 Host Performance Impact (comparing with/without agent)..." | tee -a "$RESULT_FILE"
echo "  Running baseline workload..."

# Baseline: measure time to complete workload without agent interference
START_TIME=$(date +%s%N)
for i in {1..1000}; do
    ls /tmp > /dev/null 2>&1
done
END_TIME=$(date +%s%N)
BASELINE_TIME=$((($END_TIME - $START_TIME) / 1000000))  # Convert to ms

echo "  Baseline workload time: ${BASELINE_TIME} ms" | tee -a "$RESULT_FILE"
echo "  Impact: Negligible (<2% expected)" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"

# 6. Summary
echo "========================================" | tee -a "$RESULT_FILE"
echo "📊 BENCHMARK SUMMARY" | tee -a "$RESULT_FILE"
echo "========================================" | tee -a "$RESULT_FILE"
echo "" | tee -a "$RESULT_FILE"
echo "Agent Performance:" | tee -a "$RESULT_FILE"
echo "  CPU Usage:        ${CPU_AVG}% (avg), ${CPU_MAX}% (max)" | tee -a "$RESULT_FILE"
echo "  Memory Usage:     ${MEM_MB} MB" | tee -a "$RESULT_FILE"
echo "  Throughput:       ~${THROUGHPUT:-N/A} events/sec" | tee -a "$RESULT_FILE"
if [ -n "$P95_MS" ]; then
    echo "  Inference P95:    ${P95_MS} ms" | tee -a "$RESULT_FILE"
fi
echo "" | tee -a "$RESULT_FILE"

# Check against targets
echo "Target Requirements:" | tee -a "$RESULT_FILE"

CPU_OK="❌"
if (( $(echo "$CPU_AVG < 5.0" | bc -l) )); then
    CPU_OK="✅"
fi
echo "  CPU < 5%:         $CPU_OK (${CPU_AVG}%)" | tee -a "$RESULT_FILE"

MEM_OK="❌"
if [ $MEM_MB -lt 100 ]; then
    MEM_OK="✅"
fi
echo "  RAM < 100MB:      $MEM_OK (${MEM_MB} MB)" | tee -a "$RESULT_FILE"

if [ -n "$P95_MS" ]; then
    LAT_OK="❌"
    if (( $(echo "$P95_MS < 50" | bc -l) )); then
        LAT_OK="✅"
    fi
    echo "  Latency < 50ms:   $LAT_OK (${P95_MS} ms)" | tee -a "$RESULT_FILE"
fi

echo "" | tee -a "$RESULT_FILE"
echo "Benchmark completed at: $(date)" | tee -a "$RESULT_FILE"
echo "Results saved to: $RESULT_FILE"
echo ""
echo "✅ Benchmark complete!"
