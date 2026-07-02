# Kiến trúc Deployment - EDR Threat Hunting Engine

## Tổng quan kiến trúc triển khai

Dự án có **2 mode deployment**:

1. **Mode 1: Standalone (Test local)** - Không cần K8s, chạy trên 1 máy
2. **Mode 2: Production K8s** - Cần cụm K8s với agent DaemonSet

---

## Mode 1: Standalone Deployment (Đơn giản - Cho demo)

### Kiến trúc

```
┌─────────────────────────────────────────┐
│      MÁY MAC/LINUX CỦA BẠN              │
│  (hoặc 1 VM bất kỳ)                     │
├─────────────────────────────────────────┤
│                                         │
│  ┌───────────────────────────────┐     │
│  │  EDR Agent (Go binary)        │     │
│  │  - Process monitor            │     │
│  │  - File monitor               │     │
│  │  - Network monitor            │     │
│  │  - Correlation engine         │     │
│  │  - Threat scoring             │     │
│  │                               │     │
│  │  Expose: :9090/metrics        │     │
│  └───────────────────────────────┘     │
│            ↓                            │
│  ┌───────────────────────────────┐     │
│  │  Local Logs                   │     │
│  │  /var/log/edr-agent/agent.log│     │
│  └───────────────────────────────┘     │
│                                         │
└─────────────────────────────────────────┘
```

### Cần gì?

**Hardware:**
- 1 máy Mac/Linux (hoặc 1 VM)
- CPU: 2 cores
- RAM: 2GB
- Disk: 1GB

**Software:**
- Go 1.21+
- Python 3.10+ (chỉ cho training ML, không bắt buộc)
- Quyền sudo

### Chạy như thế nào?

```bash
# Build
make build

# Chạy
sudo ./bin/edr-agent --config agent/config.yaml

# Test
curl http://localhost:9090/metrics
```

### Use case

✅ **Phù hợp cho:**
- Demo cho giảng viên/hội đồng
- Development/testing
- Học tập, hiểu cách agent hoạt động
- Chạy demo attack scenarios

❌ **Không phù hợp cho:**
- Production (thiếu HA, monitoring, centralized logging)
- Monitor nhiều endpoints (chỉ chạy trên 1 máy)

---

## Mode 2: Production K8s Deployment (Đầy đủ)

### Kiến trúc

```
┌─────────────────────────────────────────────────────────────────┐
│                    CỤM KUBERNETES                               │
│             (Contabo VPS hoặc cluster bất kỳ)                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              MASTER NODE (4 vCPU, 8GB RAM)               │  │
│  │  - K8s Control Plane                                     │  │
│  │  - etcd, kube-apiserver, scheduler, controller-manager   │  │
│  └──────────────────────────────────────────────────────────┘  │
│                           │                                     │
│                           │ manages                             │
│          ┌────────────────┴────────────────┐                   │
│          │                                  │                   │
│  ┌───────▼────────┐              ┌─────────▼────────┐          │
│  │  WORKER NODE 1 │              │  WORKER NODE 2   │          │
│  │  (6vCPU, 12GB) │              │  (6vCPU, 12GB)   │          │
│  ├────────────────┤              ├──────────────────┤          │
│  │                │              │                  │          │
│  │ ┌────────────┐ │              │ ┌──────────────┐│          │
│  │ │ EDR Agent  │ │              │ │ EDR Agent    ││          │
│  │ │ (DaemonSet)│ │              │ │ (DaemonSet)  ││          │
│  │ │ Pod #1     │ │              │ │ Pod #2       ││          │
│  │ └────────────┘ │              │ └──────────────┘│          │
│  │       │        │              │        │        │          │
│  │       │ metrics│              │        │ metrics│          │
│  │       ▼        │              │        ▼        │          │
│  │                │              │                 │          │
│  │ ┌────────────────────────────────────────────┐ │          │
│  │ │   VictoriaMetrics (Time-Series DB)        │ │          │
│  │ │   - Central telemetry storage              │ │          │
│  │ │   - Retains data for 7 days                │ │          │
│  │ └────────────────────────────────────────────┘ │          │
│  │                    │                            │          │
│  │                    │ queries                    │          │
│  │                    ▼                            │          │
│  │ ┌────────────────────────────────────────────┐ │          │
│  │ │   Grafana Dashboard                        │ │          │
│  │ │   - Visualization                          │ │          │
│  │ │   - Alerting                               │ │          │
│  │ │   Expose: NodePort :30300                  │ │          │
│  │ └────────────────────────────────────────────┘ │          │
│  │                                                 │          │
│  │ ┌────────────────────────────────────────────┐ │          │
│  │ │   MLflow (Model Registry)                  │ │          │
│  │ │   - Store trained models                   │ │          │
│  │ │   - Versioning                             │ │          │
│  │ └────────────────────────────────────────────┘ │          │
│  │                                                 │          │
│  │ ┌────────────────────────────────────────────┐ │          │
│  │ │   MinIO (S3-compatible)                    │ │          │
│  │ │   - Store training data                    │ │          │
│  │ │   - DVC backend                            │ │          │
│  │ └────────────────────────────────────────────┘ │          │
│  │                                                 │          │
│  └─────────────────────────────────────────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

                          ▲
                          │
                          │ kubectl apply
                          │ kubectl logs
                          │
                ┌─────────┴──────────┐
                │  MÁY LAPTOP CỦA BẠN │
                │  (kubectl client)   │
                └─────────────────────┘
```

### Cần gì?

**1. Cụm Kubernetes:**

**Option A: Contabo VPS (như bạn đã có)**
- 1x Master: 4 vCPU, 8GB RAM
- 2x Worker: 6 vCPU, 12GB RAM each
- Total: 16 vCPU, 32GB RAM
- Network: Private network giữa các nodes
- Cost: ~€40-50/tháng

**Option B: Local minikube/kind (cho testing)**
```bash
# Start local cluster
minikube start --cpus=4 --memory=8192 --nodes=2
```

**2. Máy laptop/desktop của bạn:**
- kubectl installed
- Kết nối SSH đến K8s master
- Hoặc kubeconfig file để remote access

### Deployment flow

```
MÁY LAPTOP                    K8S CLUSTER
─────────                    ─────────────

1. Build Docker image
   docker build -t edr-agent:latest .
                │
                │
2. Push image   ▼
   ─────────────────────> Copy to worker nodes
                          docker load
                │
                │
3. Deploy       ▼
   kubectl apply -f k8s/
                │
                ├────────> Master schedules pods
                │
                ▼
   Pods running on Worker 1 & Worker 2
                │
                │
4. Monitor      │
   kubectl logs ...
   kubectl get pods ...
                │
                ▼
   Access Grafana: http://worker-ip:30300
```

### Components phân tán

| Component | Deployment | Resource | Purpose |
|-----------|-----------|----------|---------|
| **EDR Agent** | DaemonSet (1 pod/node) | 100m CPU, 128Mi RAM | Monitor endpoints |
| **VictoriaMetrics** | Deployment (1 replica) | 200m CPU, 512Mi RAM | Store metrics |
| **Grafana** | Deployment (1 replica) | 100m CPU, 256Mi RAM | Visualization |
| **MLflow** | Deployment (1 replica) | 200m CPU, 512Mi RAM | Model registry |
| **MinIO** | StatefulSet (1 replica) | 100m CPU, 1Gi RAM | Object storage |

### Network flow

```
EDR Agent Pod (Worker 1)
    ↓ :9090/metrics (scrape)
VictoriaMetrics Service (:8428)
    ↓ PromQL queries
Grafana Service (:3000)
    ↓ NodePort :30300
Browser (bạn truy cập dashboard)
```

### Use case

✅ **Phù hợp cho:**
- Production deployment
- Monitor nhiều endpoints (scale to 10-100 nodes)
- Centralized logging & monitoring
- High availability
- Team collaboration (nhiều người cùng xem dashboard)

❌ **Không cần thiết cho:**
- Quick demo (quá phức tạp)
- Learning (nên bắt đầu với standalone)

---

## So sánh 2 modes

| Feature | Standalone | K8s Production |
|---------|-----------|----------------|
| **Setup time** | 5 phút | 30 phút |
| **Infrastructure** | 1 máy | Cụm K8s (3 nodes) |
| **Cost** | Free | ~€40-50/tháng |
| **Monitoring** | Logs local, curl metrics | Grafana dashboard tập trung |
| **Scalability** | 1 endpoint | 2-100 endpoints |
| **HA** | ❌ | ✅ (DaemonSet tự recover) |
| **Phù hợp cho** | Demo, learning | Production, team |

---

## Khuyến nghị theo use case

### Bạn là sinh viên thực tập, cần demo cho hội đồng?

**→ Dùng Mode 1 (Standalone)**

Lý do:
- Đơn giản, setup 5 phút
- Đủ để demo detection hoạt động
- Không cần infrastructure phức tạp
- Dễ troubleshoot

**Steps:**
1. Build agent trên laptop
2. Chạy agent local
3. Chạy demo attacks
4. Show logs real-time cho hội đồng
5. ✅ Hoàn thành

### Bạn muốn deploy production, monitor nhiều servers?

**→ Dùng Mode 2 (K8s)**

**Steps:**
1. Setup K8s cluster (Contabo hoặc cloud provider)
2. Build Docker image
3. Deploy DaemonSet (agent tự động chạy trên mọi node)
4. Deploy backend (VictoriaMetrics, Grafana)
5. Access Grafana dashboard
6. ✅ Production ready

### Bạn có sẵn cụm K8s (như Contabo) nhưng muốn test trước?

**→ Kết hợp cả 2:**

1. **Local test trước** (Mode 1):
   ```bash
   make build
   sudo ./bin/edr-agent --config agent/config.yaml
   # Test xong → OK
   ```

2. **Deploy lên K8s sau** (Mode 2):
   ```bash
   make docker-build
   make k8s-deploy
   # Production ready
   ```

---

## Câu hỏi thường gặp

### 1. Agent chạy ở đâu?

**Mode 1 (Standalone):**
- Agent = 1 Go binary chạy trên máy local
- Monitor chính máy đó (localhost)

**Mode 2 (K8s):**
- Agent = Docker container trong Pod
- **DaemonSet** đảm bảo mỗi worker node có 1 agent pod
- Agent pod **mount hostPath** `/proc`, `/etc` của worker node vào container
- → Agent thực tế monitor **host worker node**, không phải container bên trong

### 2. Tôi có cụm K8s Contabo (1 master + 2 worker), agent chạy ở đâu?

**Agent chạy trên 2 worker nodes** (DaemonSet):
- Worker 1: 1 agent pod → monitor worker 1
- Worker 2: 1 agent pod → monitor worker 2
- Master: Không chạy agent (hoặc tuỳ chọn)

**Backend services chạy ở đâu?**
- VictoriaMetrics: 1 pod trên 1 trong 2 workers
- Grafana: 1 pod trên 1 trong 2 workers
- MLflow/MinIO: Tuỳ chọn, nếu cần thì deploy

### 3. Tôi cần bao nhiêu máy/VM?

**Minimum (cho demo):**
- **1 máy** - chạy standalone agent

**Recommended (cho K8s):**
- **3 máy** - 1 master + 2 workers
- Hoặc **1 máy** - chạy minikube với 2 nodes (fake)

**Bạn có Contabo cluster rồi:**
- ✅ Đã sẵn 3 máy (1 master + 2 workers)
- ✅ Chỉ cần deploy lên, không cần provision thêm

### 4. Không có K8s, có chạy được không?

✅ **CÓ** - Dùng Mode 1 (Standalone)

Deployment đơn giản nhất:
```bash
# Máy 1 (laptop)
./bin/edr-agent --config config.yaml

# Máy 2 (server khác - tuỳ chọn)
scp edr-agent server2:/usr/local/bin/
ssh server2 'edr-agent --config config.yaml'
```

Không cần K8s, Docker, hay gì phức tạp cả!

### 5. K8s cluster của tôi nên setup như thế nào?

**Với Contabo VPS:**

```bash
# Trên master node
kubeadm init --pod-network-cidr=10.244.0.0/16

# Join workers
# (command từ kubeadm init output)
kubeadm join <master-ip>:6443 --token xxx --discovery-token-ca-cert-hash sha256:xxx

# Install CNI (Calico)
kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml

# Verify
kubectl get nodes
# NAME      STATUS   ROLE           AGE
# master    Ready    control-plane  5m
# worker1   Ready    <none>         3m
# worker2   Ready    <none>         3m
```

**Bạn đã có Kubespray + Calico rồi → Skip bước này**

---

## Recommendation cuối cùng

**Cho dự án thực tập của bạn:**

### Giai đoạn 1: Development & Demo (1-2 tuần)

✅ **Dùng Standalone mode**
```bash
# Chạy trên laptop
make build
sudo ./bin/edr-agent --config agent/config.yaml

# Demo attacks
./demo/attack_scripts/01_encoded_powershell.sh

# Show logs cho hội đồng
tail -f /var/log/edr-agent/agent.log | grep THREAT
```

**Lý do:** Đơn giản, focus vào logic detection, không mất thời gian troubleshoot K8s.

### Giai đoạn 2: Production Deployment (tuỳ chọn, sau khi bảo vệ)

✅ **Deploy lên K8s Contabo**
```bash
# Build image
make docker-build

# Deploy
make k8s-deploy

# Access Grafana
open http://<worker-ip>:30300
```

**Lý do:** Showcase khả năng scale, production-ready, bonus points từ hội đồng.

---

## Tổng kết

| Scenario | Deployment | Infrastructure | Setup Time |
|----------|-----------|----------------|------------|
| **Quick demo** | Standalone | 1 laptop | 5 phút |
| **Full demo** | Standalone + ML training | 1 laptop | 30 phút |
| **Production POC** | K8s (minikube local) | 1 laptop | 20 phút |
| **Production** | K8s (Contabo) | 1 master + 2 workers | 40 phút |

**Khuyến nghị của tôi:**
1. **Bắt đầu với Standalone** - Chạy local, test detection
2. **Nếu có thời gian** - Deploy lên K8s để showcase
3. **Trong báo cáo** - Nêu rõ cả 2 mode, giải thích trade-offs

**✅ Hoàn toàn OK để demo bằng standalone mode!** K8s là bonus, không bắt buộc.
