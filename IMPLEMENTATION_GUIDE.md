# EDR Threat Hunting Agent - Implementation Guide

## Overview

This is an agent-side EDR (Endpoint Detection and Response) threat hunting system that performs **behavioral correlation and weak signal analysis** directly on the endpoint, reducing dependency on backend analytics.

## Key Features

### 1. Agent-side Behavioral Correlation
- **Sliding window analytics** - Maintains temporal context without unbounded memory growth
- **Process tree tracking** - Monitors parent-child relationships and execution chains
- **Multi-signal correlation** - Combines process, file, network, and persistence events

### 2. Threat Hunting Engine
- **Weak signal detection** - Identifies suspicious behaviors that don't trigger traditional rules
- **Attack chain analysis** - Correlates multiple low-severity events into high-confidence threats
- **Rarity scoring** - Detects uncommon process lineages and behaviors
- **Beaconing detection** - Identifies periodic C2 communications

### 3. Multi-layered Detection

#### Layer 1: Rule-based Detection (Fast Path)
- YAML-based detection rules (similar to YARA/Sigma)
- Pattern matching for known threats
- 10 pre-built detection rules covering MITRE ATT&CK techniques

#### Layer 2: Behavioral Correlation
- Local event correlation in sliding window
- Process lineage analysis
- Temporal pattern detection
- Context enrichment

#### Layer 3: ML Anomaly Detection
- Isolation Forest model for anomaly scoring
- 15-feature behavioral analysis
- Fallback to rule-based scoring

### 4. Threat Scoring
Composite score from three components:
- **Rarity Score** (30%) - Rare processes, encoded commands, privilege escalation
- **Sequence Score** (40%) - Attack chain patterns, execution→file→network sequences
- **ML Score** (30%) - Machine learning anomaly detection

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     EDR Agent (Go)                          │
├─────────────────────────────────────────────────────────────┤
│  Telemetry Monitors                                         │
│  ├─ Process Monitor (/proc polling)                         │
│  ├─ File Monitor (fsnotify)                                 │
│  ├─ Network Monitor (netstat)                               │
│  └─ Persistence Monitor (cron, systemd)                     │
├─────────────────────────────────────────────────────────────┤
│  Detection Pipeline                                         │
│  ├─ Rules Engine (YAML-based detection)                     │
│  ├─ Correlation Engine (Sliding window + Process tree)      │
│  ├─ ML Engine (ONNX Runtime / Fallback)                     │
│  └─ Scoring Engine (Threat score calculation)               │
├─────────────────────────────────────────────────────────────┤
│  Output                                                     │
│  ├─ Structured Logging (JSON)                               │
│  ├─ Prometheus Metrics (:9090/metrics)                      │
│  └─ VictoriaMetrics Exporter (Threat alerts)                │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites
- Go 1.21+
- Linux system (for /proc monitoring)
- Python 3.8+ (for ML training)

### 1. Build the Agent

```bash
cd agent
go build -o ../bin/edr-agent ./cmd/agent
```

### 2. Configure the Agent

Edit `agent/config.yaml`:

```yaml
agent:
  hostname: your-hostname
  environment: production

rules:
  enabled: true
  rules_dir: /etc/edr-agent/rules
  auto_reload: true

correlation:
  window_size: 30m
  max_memory_mb: 100

scoring:
  rarity_weight: 0.3
  sequence_weight: 0.4
  ml_weight: 0.3
  threshold: 0.7

output:
  victoria_metrics:
    enabled: false
    endpoint: http://victoria-metrics:8428/api/v1/write
```

### 3. Deploy Detection Rules

```bash
sudo mkdir -p /etc/edr-agent/rules
sudo cp rules/*.yaml /etc/edr-agent/rules/
```

### 4. Run the Agent

```bash
sudo ./bin/edr-agent --config agent/config.yaml
```

### 5. View Metrics

```bash
curl http://localhost:9090/metrics
```

## Detection Rules

The system includes 10 pre-built detection rules:

| Rule | Severity | MITRE Technique | Description |
|------|----------|-----------------|-------------|
| 001_encoded_powershell | HIGH | T1059.001, T1027 | Encoded PowerShell execution |
| 002_suspicious_shell_spawned_by_office | CRITICAL | T1566.001 | Office app spawning shells |
| 003_credential_dumping_lsass_access | CRITICAL | T1003.001 | LSASS memory access |
| 004_suspicious_dns_query | MEDIUM | T1071.004 | Suspicious DNS queries |
| 005_persistence_cron_modification | MEDIUM | T1053.003 | Cron job modifications |
| 006_lolbin_abuse | HIGH | T1218 | LOLBin abuse detection |
| 007_mass_file_modification | CRITICAL | T1486 | Mass file modifications |
| 008_ssh_config_modification | HIGH | T1098.004 | SSH config changes |
| 009_privilege_escalation_sudo | HIGH | T1548.003 | Privilege escalation |
| 010_reverse_shell_indicators | CRITICAL | T1071.001 | Reverse shell patterns |

## Behavioral Correlation Examples

### Example 1: Script-based Attack Chain

```
winword.exe (PID: 1234)
    ↓
powershell.exe -enc <base64> (PID: 5678)
    ↓
DNS query to malicious.tk
    ↓
Outbound connection to 1.2.3.4:443
```

**Detection Logic:**
1. Office app spawning PowerShell → Suspicious
2. Encoded command → High entropy detected
3. DNS to .tk domain → Suspicious TLD
4. Network connection immediately after → C2 pattern

**Threat Score:** 0.85 (HIGH)

### Example 2: Credential Dumping

```
attacker_tool.exe (PID: 9999)
    ↓
Access /proc/<lsass_pid>/mem
    ↓
File write: /tmp/creds.txt
    ↓
Network upload
```

**Detection Logic:**
1. LSASS memory access → CRITICAL rule match
2. Sensitive file access → Rarity score +0.4
3. Immediate network activity → Exfiltration pattern

**Threat Score:** 0.95 (CRITICAL)

## ML Model Training

### Feature Engineering (15 features)

1. **Process Features (3)**
   - Process lineage depth
   - Rare parent-child relationship
   - Privilege escalation detected

2. **Commandline Features (3)**
   - Commandline length
   - Commandline entropy (Shannon)
   - Encoded command detected

3. **File Activity Features (3)**
   - File modification count
   - Sensitive file access count
   - Mass file activity rate

4. **Network Features (3)**
   - Network connection count
   - Suspicious DNS detected
   - Beaconing score

5. **Persistence Features (3)**
   - Persistence mechanism detected
   - Cron job count
   - Service creation count

### Training the Model

```bash
cd ml-training
pip install -r requirements.txt
python scripts/train_isolation_forest.py
python scripts/export_onnx.py
```

This generates:
- `model.onnx` - ONNX format model
- `model.onnx.metadata.json` - Model metadata

## Performance Characteristics

### Resource Usage (Target)
- **CPU**: < 5% per core
- **Memory**: < 100MB
- **Events/sec**: ~10,000
- **Detection latency**: < 100ms

### Sliding Window
- **Default window**: 30 minutes
- **Cleanup interval**: 1 minute
- **Max memory**: 100MB

### Detection Capabilities
- **Known threats**: Rule-based detection (microseconds)
- **Unknown threats**: Behavioral correlation (milliseconds)
- **APT detection**: Multi-stage attack chains (minutes to hours)

## Testing

### Run Test Suite

```bash
./scripts/test_agent.sh
```

### Simulate Attacks

```bash
# Encoded PowerShell
./demo/attack_scripts/01_encoded_powershell.sh

# Credential Access
./demo/attack_scripts/02_credential_access.sh

# Beaconing
./demo/attack_scripts/03_beaconing_simulation.sh
```

## Deployment

### Kubernetes

```bash
kubectl apply -f k8s/agent/daemonset.yaml
```

### Docker

```bash
docker build -t edr-agent:latest .
docker run --privileged --pid=host -v /proc:/host/proc:ro edr-agent:latest
```

## Monitoring & Observability

### Prometheus Metrics

- `edr_events_processed_total{type}` - Events processed by type
- `edr_alerts_generated_total{severity}` - Alerts by severity
- `edr_inference_latency_seconds` - ML inference latency
- `edr_correlation_chains_active` - Active attack chains

### Grafana Dashboard

Import `docs/grafana-edr-dashboard.json` for visualization.

## Future Enhancements

1. **Real ONNX Runtime Integration** - Replace fallback with actual ONNX inference
2. **eBPF Support** - Kernel-level telemetry for better performance
3. **Graph-based Analysis** - Attack graph visualization
4. **Federated Learning** - Cross-endpoint pattern sharing
5. **Automated Response** - Process termination, network blocking

## Comparison with Traditional EDR

| Feature | Traditional EDR | This Project |
|---------|----------------|--------------|
| Detection Method | Rule + IOC | Behavioral + Weak Signal |
| Processing | Backend SIEM | Agent-side |
| Latency | Seconds to minutes | Milliseconds |
| Unknown Threats | Limited | Strong |
| Bandwidth | High telemetry | Low (alerts only) |
| Offline Detection | No | Yes |

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Isolation Forest Paper](https://cs.nju.edu.cn/zhouzh/zhouzh.files/publication/icdm08b.pdf)
- [LOLBins Project](https://lolbas-project.github.io/)

## License

MIT License

## Contributors

- Built as part of EDR Threat Hunting thesis project
- Focus: Agent-side behavioral analytics and autonomous threat hunting
