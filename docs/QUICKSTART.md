# Quick Start Guide - EDR Threat Hunting Engine

## Hướng dẫn chạy nhanh dự án từ đầu đến cuối

---

## Mục lục

1. [Prerequisites](#prerequisites)
2. [Setup môi trường](#setup-môi-trường)
3. [Build và Test Agent Local](#build-và-test-agent-local)
4. [Train ML Model](#train-ml-model)
5. [Deploy lên K8s](#deploy-lên-k8s)
6. [Chạy Demo Attack](#chạy-demo-attack)
7. [Monitoring & Metrics](#monitoring--metrics)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Phần mềm cần thiết

```bash
# 1. Go (cho Agent)
go version  # Go 1.21+

# 2. Python (cho ML Training)
python3 --version  # Python 3.10+

# 3. Docker (cho containerization)
docker --version  # Docker 20.10+

# 4. Kubernetes (cho deployment)
kubectl version  # Kubernetes 1.28+

# 5. Make (để chạy Makefile commands)
make --version
```

### Kubernetes Cluster

Bạn cần có:
- **1 master node**: 4 vCPU, 8GB RAM
- **2 worker nodes**: 6 vCPU, 12GB RAM each
- **Storage**: ~100GB

Contabo VPS đã setup sẵn:
```bash
kubectl get nodes
# NAME          STATUS   ROLE           AGE   VERSION
# master-node   Ready    control-plane  30d   v1.28.x
# worker-1      Ready    <none>         30d   v1.28.x
# worker-2      Ready    <none>         30d   v1.28.x
```

---

## Setup môi trường

### Bước 1: Clone repository

```bash
cd /Users/binhbl/Documents/my-pj/homelab
ls edr-threat-hunting/
```

### Bước 2: Cài đặt Go dependencies

```bash
cd edr-threat-hunting/agent
go mod download
go mod tidy

# Verify
go list -m all
```

### Bước 3: Setup Python environment cho ML

```bash
cd ../ml-training

# Tạo virtual environment
python3 -m venv venv
source venv/bin/activate

# Cài đặt dependencies
pip install -r requirements.txt

# Verify
pip list | grep scikit-learn
pip list | grep mlflow
```

---

## Build và Test Agent Local

### Bước 1: Build agent binary

```bash
cd /Users/binhbl/Documents/my-pj/homelab/edr-threat-hunting

# Sử dụng Makefile
make build

# Hoặc build thủ công
cd agent
go build -o ../bin/edr-agent cmd/agent/main.go
```

Kết quả:
```
✅ Build complete: bin/edr-agent
```

### Bước 2: Test chạy agent local

```bash
# Cần sudo để access /proc, /etc, etc.
sudo ./bin/edr-agent --config agent/config.yaml
```

Output mong đợi:
```json
{"level":"info","msg":"EDR Threat Hunting Agent starting...","version":"1.0.0","buildTime":"unknown"}
{"level":"info","msg":"ML engine initialized (fallback mode)"}
{"level":"info","msg":"Behavioral correlation engine initialized"}
{"level":"info","msg":"Threat scoring engine initialized"}
{"level":"info","msg":"Process monitor started"}
{"level":"info","msg":"File monitor started","watch_count":7}
{"level":"info","msg":"Network monitor polling started"}
{"level":"info","msg":"Persistence monitor started","watch_count":15}
{"level":"info","msg":"Metrics exporter started","port":9090}
```

### Bước 3: Test metrics endpoint

Mở terminal khác:
```bash
curl http://localhost:9090/metrics

# Hoặc với jq để format
curl -s http://localhost:9090/metrics | grep edr_agent
```

Kết quả:
```
edr_agent_events_processed_total{event_type="process"} 42
edr_agent_events_processed_total{event_type="file"} 15
edr_agent_events_processed_total{event_type="network"} 8
edr_agent_memory_usage_mb 47
```

### Bước 4: Test với activity đơn giản

Terminal khác (để trigger events):
```bash
# Tạo file mới
echo "test" > /tmp/edr_test.txt

# Process creation
ls -la /tmp/

# Network activity
curl -I google.com
```

Kiểm tra logs agent, sẽ thấy events được detect.

**Ctrl+C để stop agent.**

---

## Train ML Model

### Bước 1: Activate Python environment

```bash
cd ml-training
source venv/bin/activate
```

### Bước 2: Train model bằng script

```bash
# Option 1: Dùng Python script
python3 scripts/train_isolation_forest.py \
    --output-dir models \
    --n-normal 5000 \
    --n-anomaly 500

# Option 2: Dùng Jupyter notebook (interactive)
jupyter lab

# Mở notebook: notebooks/train_isolation_forest.ipynb
# Run all cells (Shift+Enter)
```

Kết quả:
```
Generating 5000 normal + 500 anomaly samples...
✅ Generated 5500 samples
Training Isolation Forest (contamination=0.1)...
Training completed!

Classification Report:
              precision    recall  f1-score   support
     Anomaly       0.89      0.92      0.90       100
      Normal       0.99      0.98      0.98      1000

✅ Model saved: models/isolation_forest.pkl
   Size: 4.20 KB
```

### Bước 3: Export model to ONNX

```bash
python3 scripts/export_onnx.py \
    --model models/isolation_forest.pkl \
    --output models/model.onnx \
    --quantize \
    --benchmark
```

Kết quả:
```
Exporting model to ONNX format...
✅ Float32 model saved: models/model_float32.onnx
   Size: 4.20 KB

Quantizing model (Float32 -> Int8)...
✅ Quantized model saved: models/model.onnx
   Size: 0.87 KB
   Compression ratio: 4.83x

Benchmarking inference latency (1000 samples)...
✅ Inference latency statistics:
   Mean:   38.24 ms
   P95:    42.15 ms
   P99:    45.89 ms
```

### Bước 4: Verify model file

```bash
ls -lh models/
# -rw-r--r--  1 user  staff   4.2K  model_float32.onnx
# -rw-r--r--  1 user  staff   0.9K  model.onnx
# -rw-r--r--  1 user  staff   3.8K  isolation_forest.pkl
```

**Model đã sẵn sàng để deploy!** ✅

---

## Deploy lên K8s

### Bước 1: Build Docker image

```bash
cd /Users/binhbl/Documents/my-pj/homelab/edr-threat-hunting

# Build image
make docker-build

# Hoặc thủ công
docker build -t edr-agent:latest -f Dockerfile .
```

Verify:
```bash
docker images | grep edr-agent
# edr-agent    latest    abc123def456    2 minutes ago    45.3MB
```

### Bước 2: Push image to registry (nếu cần)

**Option 1: Local registry**
```bash
# Skip nếu K8s cluster local
docker save edr-agent:latest | gzip > edr-agent.tar.gz

# Copy to worker nodes
scp edr-agent.tar.gz worker-1:/tmp/
scp edr-agent.tar.gz worker-2:/tmp/

# On each worker
ssh worker-1 'docker load < /tmp/edr-agent.tar.gz'
ssh worker-2 'docker load < /tmp/edr-agent.tar.gz'
```

**Option 2: Docker Hub**
```bash
docker tag edr-agent:latest yourusername/edr-agent:latest
docker push yourusername/edr-agent:latest
```

### Bước 3: Create namespace và deploy backend

```bash
# Tạo namespace
kubectl create namespace edr-system

# Deploy VictoriaMetrics (time-series DB)
kubectl apply -f k8s/backend/victoria-metrics.yaml

# Deploy Grafana (dashboard)
kubectl apply -f k8s/backend/grafana.yaml

# Verify
kubectl get pods -n edr-system
# NAME                               READY   STATUS    RESTARTS   AGE
# victoria-metrics-xxxxxxxxx-xxxxx   1/1     Running   0          30s
# grafana-xxxxxxxxx-xxxxx            1/1     Running   0          30s
```

### Bước 4: Tạo ConfigMap cho ML model

```bash
# Tạo ConfigMap từ model file
kubectl create configmap edr-ml-model \
    --from-file=model.onnx=ml-training/models/model.onnx \
    -n edr-system

# Verify
kubectl get configmap -n edr-system edr-ml-model
```

### Bước 5: Deploy agent DaemonSet

```bash
# Deploy agent to all nodes
kubectl apply -f k8s/agent/daemonset.yaml

# Check deployment
kubectl get daemonset -n edr-system
# NAME        DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   AGE
# edr-agent   2         2         2       2            2           60s

kubectl get pods -n edr-system -l app=edr-agent
# NAME              READY   STATUS    RESTARTS   AGE
# edr-agent-xxxxx   1/1     Running   0          60s
# edr-agent-yyyyy   1/1     Running   0          60s
```

### Bước 6: Verify logs

```bash
# Tail logs từ một agent pod
kubectl logs -n edr-system -l app=edr-agent -f

# Hoặc logs từ specific pod
kubectl logs -n edr-system edr-agent-xxxxx -f
```

Output mong đợi:
```json
{"level":"info","msg":"EDR Threat Hunting Agent starting...","node":"worker-1"}
{"level":"info","msg":"Process monitor started"}
{"level":"info","msg":"File monitor started","watch_count":7}
{"level":"info","msg":"Network monitor polling started"}
{"level":"info","msg":"Persistence monitor started","watch_count":15}
```

---

## Chạy Demo Attack

### Bước 1: SSH vào worker node

```bash
# SSH vào worker node để chạy attack simulation
ssh worker-1
```

### Bước 2: Copy attack scripts

```bash
# From your local machine
scp -r demo/attack_scripts/ worker-1:/tmp/

# On worker node
cd /tmp/attack_scripts
chmod +x *.sh
```

### Bước 3: Chạy demo attacks

#### Demo 1: Encoded PowerShell

```bash
./01_encoded_powershell.sh
```

Output:
```
==========================================
Demo Attack: Encoded PowerShell Execution
==========================================

Simulating: bash → sh → base64-encoded command
Expected Detection: HIGH severity (encoded command + suspicious lineage)

[Step 1] Parent: bash process
[Step 2] Child: sh with long commandline
[Step 3] Encoded command execution (base64)
   Command: echo 'aGVsbG8gd29ybGQ=' | base64 -d
   Decoded: hello world

✅ Attack simulation completed

Expected EDR Detection:
  - Process lineage: bash → sh/pwsh
  - High commandline entropy
  - Encoded command flag: TRUE
  - Threat Score: ~0.75-0.85 (HIGH)
  - MITRE: T1059 - Command and Scripting Interpreter

Check EDR agent logs and Grafana dashboard for alerts
```

#### Demo 2: Credential Access

```bash
sudo ./02_credential_access.sh
```

#### Demo 3: C2 Beaconing

```bash
./03_beaconing_simulation.sh
```

### Bước 4: Kiểm tra detection trong logs

```bash
# From local machine
kubectl logs -n edr-system -l app=edr-agent --tail=100 | grep THREAT
```

Kết quả mong đợi:
```json
{
  "level":"warn",
  "threat_score":"0.82",
  "severity":"HIGH",
  "attack_chain":"bash → sh → base64",
  "mitre_tactics":["TA0002 - Execution","T1059 - Command and Scripting Interpreter"],
  "msg":"THREAT DETECTED"
}
```

---

## Monitoring & Metrics

### Bước 1: Access Grafana

```bash
# Get Grafana NodePort
kubectl get svc -n edr-system grafana
# NAME      TYPE       CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
# grafana   NodePort   10.96.xxx.xxx   <none>        3000:30300/TCP   5m

# Access via browser
open http://<worker-node-ip>:30300

# Default credentials
# Username: admin
# Password: admin
```

### Bước 2: View dashboards

1. Login to Grafana
2. Navigate to **Dashboards** → **EDR Threat Hunting - Overview**
3. View metrics:
   - Events processed rate
   - Alerts by severity
   - ML inference latency
   - Agent memory usage

### Bước 3: Query metrics directly

```bash
# Port-forward VictoriaMetrics
kubectl port-forward -n edr-system svc/victoria-metrics 8428:8428

# Query metrics
curl 'http://localhost:8428/api/v1/query?query=edr_agent_events_processed_total'
```

---

## Troubleshooting

### Agent không start

**Lỗi: Permission denied on /proc**
```bash
# Check security context trong DaemonSet
kubectl get daemonset -n edr-system edr-agent -o yaml | grep -A 10 securityContext

# Phải có:
#   privileged: true
#   capabilities:
#     add: [SYS_ADMIN, SYS_PTRACE, NET_ADMIN]
```

**Lỗi: Cannot connect to VictoriaMetrics**
```bash
# Check service
kubectl get svc -n edr-system victoria-metrics

# Test connectivity từ agent pod
kubectl exec -n edr-system edr-agent-xxxxx -- nc -zv victoria-metrics 8428
```

### ML model không load

```bash
# Check ConfigMap
kubectl get configmap -n edr-system edr-ml-model -o yaml

# Check mount trong pod
kubectl exec -n edr-system edr-agent-xxxxx -- ls -la /etc/edr-agent/model.onnx
```

**Nếu model không có → Agent sẽ dùng fallback mode (rule-based), vẫn hoạt động bình thường.**

### Không thấy metrics

```bash
# Check agent metrics endpoint
kubectl port-forward -n edr-system edr-agent-xxxxx 9090:9090

# Mở browser
open http://localhost:9090/metrics
```

### Debug logs

```bash
# Tăng log level (edit config)
kubectl edit configmap -n edr-system edr-agent-config

# Thêm:
# log_level: debug

# Restart pods
kubectl rollout restart daemonset -n edr-system edr-agent
```

---

## Next Steps

✅ **Agent đang chạy và detect threats**

Bước tiếp theo:

1. **Tune scoring weights**: Edit `scoring` section trong ConfigMap
2. **Add more attack scenarios**: Thêm scripts trong `demo/attack_scripts/`
3. **Customize dashboards**: Import custom Grafana dashboards
4. **Setup alerting**: Configure Grafana alerts for HIGH/CRITICAL threats
5. **Performance tuning**: Adjust `correlation.window_size` và `max_memory_mb`

---

## Tổng kết thời gian

| Bước | Thời gian ước tính |
|------|-------------------|
| Setup môi trường | 15 phút |
| Build agent | 5 phút |
| Train ML model | 10 phút |
| Deploy K8s | 10 phút |
| Test demo attacks | 10 phút |
| **TỔNG** | **~50 phút** |

---

## Commands cheat sheet

```bash
# Build
make build

# Train model
make ml-train ml-export

# Deploy
make docker-build
make k8s-deploy

# Monitor
make k8s-logs
make k8s-status

# Demo
make demo-all

# Clean up
make k8s-delete
make clean
```

**Hoàn thành! Dự án đã sẵn sàng chạy.** 🎉
