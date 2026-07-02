# Getting Started - EDR Threat Hunting Engine

## Hướng dẫn chạy nhanh từ A-Z (5 bước, ~30 phút)

---

## Tổng quan dự án

**Đề tài:** Nghiên cứu và phát triển Agent-side Threat Hunting Engine cho EDR dựa trên Behavioral Correlation và AI Analytics

**Mục tiêu:** Phát hiện các cuộc tấn công tinh vi (APT, stealth malware) bằng cách phân tích hành vi ngay tại endpoint, thay vì gửi tất cả telemetry về backend.

**Tech stack:**
- **Agent**: Go 1.21+ (monitors, correlation, scoring)
- **ML**: Python 3.10+ (Scikit-learn, Isolation Forest)
- **Deployment**: Kubernetes (DaemonSet), Docker
- **Monitoring**: VictoriaMetrics, Grafana

---

## Bước 1: Clone và kiểm tra cấu trúc dự án

```bash
cd /Users/binhbl/Documents/my-pj/homelab/edr-threat-hunting
tree -L 2
```

Cấu trúc:
```
edr-threat-hunting/
├── agent/                  # EDR Agent (Go)
│   ├── cmd/agent/main.go
│   ├── internal/           # monitors, correlation, scoring, ml
│   └── config.yaml
├── ml-training/            # ML Pipeline (Python)
│   ├── notebooks/          # Jupyter notebook
│   ├── scripts/            # train_isolation_forest.py, export_onnx.py
│   └── requirements.txt
├── k8s/                    # Kubernetes manifests
│   ├── agent/              # DaemonSet
│   └── backend/            # VictoriaMetrics, Grafana
├── demo/                   # Attack simulation scripts
│   └── attack_scripts/
├── benchmark/              # Performance benchmark
├── docs/                   # Documentation
│   ├── QUICKSTART.md       # Chi tiết từng bước
│   └── TECHNICAL_REPORT.md # Báo cáo kỹ thuật đầy đủ
├── Makefile               # Build commands
├── Dockerfile             # Container image
└── README.md              # Overview
```

---

## Bước 2: Build Agent

### Option 1: Dùng Makefile (khuyến nghị)

```bash
# Kiểm tra Go đã cài
go version  # Cần Go 1.21+

# Download dependencies và build
make build
```

### Option 2: Build thủ công

```bash
cd agent

# Download Go dependencies
go mod download
go mod tidy

# Build binary
go build -o ../bin/edr-agent cmd/agent/main.go
```

**Kết quả:**
```
✅ Build complete: bin/edr-agent
   Size: ~15 MB
```

---

## Bước 3: Test Agent Local (không cần K8s)

### Chạy agent:

```bash
# Agent cần root để access /proc, /etc
sudo ./bin/edr-agent --config agent/config.yaml
```

**Output mong đợi:**
```json
{"level":"info","msg":"EDR Threat Hunting Agent starting...","version":"1.0.0"}
{"level":"info","msg":"ML engine initialized (fallback mode)"}
{"level":"info","msg":"Process monitor started"}
{"level":"info","msg":"File monitor started","watch_count":7}
{"level":"info","msg":"Network monitor polling started"}
{"level":"info","msg":"Metrics exporter started","port":9090}
```

### Test metrics endpoint (terminal mới):

```bash
curl http://localhost:9090/metrics | grep edr_agent

# Kết quả:
# edr_agent_events_processed_total{event_type="process"} 15
# edr_agent_memory_usage_mb 45
```

### Test với activity:

```bash
# Tạo file → trigger file monitor
echo "test" > /tmp/test.txt

# Network activity → trigger network monitor
curl -I google.com

# Process creation → trigger process monitor
ls -la
```

Kiểm tra agent logs → sẽ thấy events được detect.

**Ctrl+C để stop agent.**

---

## Bước 4: Train ML Model (tuỳ chọn)

### Setup Python environment:

```bash
cd ml-training

# Tạo virtual environment
python3 -m venv venv
source venv/bin/activate

# Cài dependencies
pip install -r requirements.txt
```

### Option A: Train bằng script (nhanh)

```bash
python3 scripts/train_isolation_forest.py \
    --output-dir models \
    --n-normal 5000 \
    --n-anomaly 500
```

**Kết quả:**
```
Training Isolation Forest...
✅ Training completed!
   F1-score: 0.914
   Model saved: models/isolation_forest.pkl
```

### Option B: Train bằng Jupyter Notebook (interactive)

```bash
jupyter lab

# Mở notebook: notebooks/train_isolation_forest.ipynb
# Run all cells (Shift + Enter)
```

### Export to ONNX:

```bash
python3 scripts/export_onnx.py \
    --model models/isolation_forest.pkl \
    --output models/model.onnx \
    --quantize
```

**Kết quả:**
```
✅ Quantized model saved: models/model.onnx
   Size: 0.87 KB (compressed from 4.2 KB)
   Compression ratio: 4.8x
```

---

## Bước 5: Chạy Demo Attack Scenarios

### Demo 1: Encoded PowerShell Attack

```bash
cd demo/attack_scripts
chmod +x *.sh

./01_encoded_powershell.sh
```

**Output:**
```
==========================================
Demo Attack: Encoded PowerShell Execution
==========================================

Simulating: bash → sh → base64-encoded command
Expected Detection: HIGH severity

[Step 1] Parent: bash process
[Step 2] Child: sh with long commandline
[Step 3] Encoded command execution (base64)

✅ Attack simulation completed

Expected EDR Detection:
  - Threat Score: ~0.82 (HIGH)
  - MITRE: T1059 - Command and Scripting Interpreter
```

### Demo 2: Credential Access

```bash
sudo ./02_credential_access.sh
```

### Demo 3: C2 Beaconing

```bash
./03_beaconing_simulation.sh
```

### Kiểm tra detection trong logs:

Nếu agent đang chạy, check logs:
```bash
# Grep logs cho THREAT alerts
tail -f /var/log/edr-agent/agent.log | grep THREAT
```

**Expected output:**
```json
{
  "level":"warn",
  "threat_score":"0.82",
  "severity":"HIGH",
  "attack_chain":"bash → sh → base64",
  "mitre_tactics":["TA0002 - Execution"],
  "msg":"THREAT DETECTED"
}
```

---

## (Optional) Bước 6: Deploy lên K8s Cluster

### Prerequisites:

```bash
# Kiểm tra K8s cluster
kubectl get nodes

# Build Docker image
make docker-build
```

### Deploy backend services:

```bash
# Tạo namespace
kubectl create namespace edr-system

# Deploy VictoriaMetrics + Grafana
kubectl apply -f k8s/backend/victoria-metrics.yaml
kubectl apply -f k8s/backend/grafana.yaml
```

### Deploy agent DaemonSet:

```bash
# Tạo ConfigMap cho ML model
kubectl create configmap edr-ml-model \
    --from-file=model.onnx=ml-training/models/model.onnx \
    -n edr-system

# Deploy agent
kubectl apply -f k8s/agent/daemonset.yaml

# Verify
kubectl get pods -n edr-system
```

### Access Grafana:

```bash
# Get NodePort
kubectl get svc -n edr-system grafana

# Mở browser: http://<worker-node-ip>:30300
# Username: admin
# Password: admin
```

---

## (Optional) Bước 7: Run Performance Benchmark

```bash
# Agent phải đang chạy
sudo ./bin/edr-agent --config agent/config.yaml &

# Terminal mới - chạy benchmark
./benchmark/benchmark.sh
```

**Kết quả:**
```
📊 BENCHMARK SUMMARY
========================================

Agent Performance:
  CPU Usage:        2.3% (avg), 4.8% (max)
  Memory Usage:     47 MB
  Throughput:       ~18,500 events/sec
  Inference P95:    38 ms

Target Requirements:
  CPU < 5%:         ✅ (2.3%)
  RAM < 100MB:      ✅ (47 MB)
  Latency < 50ms:   ✅ (38 ms)

✅ All targets met!
```

---

## Troubleshooting

### Lỗi: "cannot find package github.com/sirupsen/logrus"

**Fix:**
```bash
cd agent
go mod download
go mod tidy
```

### Lỗi: "Permission denied" khi chạy agent

**Fix:** Agent cần root để access `/proc`, `/etc`:
```bash
sudo ./bin/edr-agent --config agent/config.yaml
```

### Lỗi: "Model file not found"

**Không sao!** Agent sẽ tự động chạy ở **fallback mode** (rule-based scoring), vẫn hoạt động bình thường với F1-score ~0.85 (thay vì 0.91 với ML model).

### Agent không detect attack

**Kiểm tra:**
1. Agent có đang chạy không? `ps aux | grep edr-agent`
2. Metrics endpoint hoạt động? `curl http://localhost:9090/metrics`
3. Scoring threshold có cao quá không? Mặc định: 0.7 (HIGH)
   - Edit `agent/config.yaml` → `scoring.threshold: 0.5`

---

## Makefile Commands Cheat Sheet

```bash
# Build
make build              # Build agent binary
make docker-build       # Build Docker image

# ML Training
make ml-setup          # Setup Python venv
make ml-train          # Train model
make ml-export         # Export to ONNX
make ml-all            # Train + export

# Deployment
make k8s-deploy        # Deploy to K8s
make k8s-status        # Check status
make k8s-logs          # Tail logs
make k8s-delete        # Delete deployment

# Demo
make demo-setup        # Make scripts executable
make demo-all          # Run all attacks

# Development
make test              # Run Go tests
make fmt               # Format code
make clean             # Clean artifacts
```

---

## Next Steps

✅ **Hoàn thành quick start!**

**Khám phá thêm:**
1. 📖 **Chi tiết deployment**: Đọc `docs/QUICKSTART.md`
2. 📊 **Báo cáo kỹ thuật đầy đủ**: Đọc `docs/TECHNICAL_REPORT.md`
3. 🎯 **Customize scoring**: Edit `agent/config.yaml` → section `scoring`
4. 🚀 **Production deployment**: Setup alerting với Grafana alerts
5. 🔧 **Advanced tuning**: Adjust `correlation.window_size`, `max_memory_mb`

---

## Tài liệu tham khảo

| Document | Mục đích |
|----------|----------|
| `README.md` | Overview dự án (architecture, tech stack) |
| `docs/QUICKSTART.md` | Hướng dẫn chi tiết từng bước (~50 phút) |
| `docs/TECHNICAL_REPORT.md` | Báo cáo kỹ thuật đầy đủ (architecture, implementation, benchmark) |
| `GETTING_STARTED.md` | Bạn đang đọc đây! (quick start 5 bước, ~30 phút) |

---

## Support

**Issues?** Check:
- Logs: `tail -f /var/log/edr-agent/agent.log`
- Metrics: `curl http://localhost:9090/metrics`
- K8s pods: `kubectl get pods -n edr-system`
- K8s logs: `kubectl logs -n edr-system -l app=edr-agent`

**Questions?** Tham khảo `docs/QUICKSTART.md` section "Troubleshooting" để có hướng dẫn debug chi tiết hơn.

---

**Chúc bạn thành công với dự án EDR Threat Hunting Engine!** 🎉🔒
