# CI/CD Pipeline Setup - EDR Threat Hunting

## 🚀 Workflow Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  Developer Push to GitHub                                       │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  GitHub Actions CI/CD                                           │
│  ├─ Run Tests (go test, lint)                                  │
│  ├─ Build Multi-arch Docker Image (amd64, arm64)               │
│  ├─ Push to GHCR: ghcr.io/blubln7/edr-agent:v1.0.0            │
│  └─ Tag: latest, v1.0.0, v1.0, v1                              │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  GitHub Container Registry (GHCR)                               │
│  https://github.com/BLuBin7/edr-threat-hunting/pkgs/...         │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  ArgoCD Image Updater (runs every 2 min)                        │
│  ├─ Detects new semver tag: v1.0.1                             │
│  ├─ Updates home-lab-gitops/services/.../agent-daemonset.yaml  │
│  └─ Commits change to Git                                      │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  ArgoCD Auto-Sync (every 3 min)                                │
│  ├─ Detects Git change                                         │
│  ├─ Pulls new image from GHCR                                  │
│  └─ Rolling update DaemonSet on K8s cluster                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📁 CI/CD Files Created

### 1. GitHub Actions Workflows

```
edr-threat-hunting/.github/workflows/
├── docker-build.yml   # Build & push Docker images
└── test.yml           # Run tests & lint
```

### 2. GitOps Manifests Updated

```
home-lab-gitops/
├── applications/base/edr-threat-hunting.yaml  # ArgoCD Image Updater config
└── services/edr-threat-hunting/base/
    └── agent-daemonset.yaml                   # Image: ghcr.io/blubln7/edr-agent
```

---

## 🔧 Setup Steps

### Step 1: Enable GitHub Container Registry (GHCR)

GHCR is **free** and **automatic** - no extra setup needed! GitHub Actions has built-in permissions.

**Verify GHCR is enabled:**
```bash
# After first build, check package at:
# https://github.com/BLuBin7/edr-threat-hunting/pkgs/container/edr-agent
```

**Make package public** (recommended):
1. Go to: https://github.com/BLuBin7/edr-threat-hunting/pkgs/container/edr-agent
2. Click **Package settings**
3. Scroll to **Danger Zone**
4. Click **Change visibility** → **Public**

### Step 2: Configure ArgoCD Image Updater Credentials

ArgoCD Image Updater cần credentials để pull từ GHCR (nếu private package).

**Option A: Public GHCR Package (Recommended)**
```bash
# No credentials needed if package is public!
# Skip to Step 3
```

**Option B: Private GHCR Package**
```bash
# Create GitHub Personal Access Token (PAT)
# 1. Go to: https://github.com/settings/tokens/new
# 2. Scopes: read:packages
# 3. Generate token

# Create Kubernetes secret
kubectl create secret docker-registry ghcr-credentials \
  --docker-server=ghcr.io \
  --docker-username=BLuBin7 \
  --docker-password=<YOUR_GITHUB_PAT> \
  --docker-email=your-email@example.com \
  -n argocd

# Add to ArgoCD Image Updater config
kubectl edit configmap argocd-image-updater-config -n argocd
# Add:
# registries:
# - name: GitHub Container Registry
#   api_url: https://ghcr.io
#   prefix: ghcr.io
#   credentials: secret:argocd/ghcr-credentials
```

### Step 3: Commit & Push CI/CD Files

```bash
# 1. Commit CI/CD workflows to edr-threat-hunting repo
cd /Users/binhbl/Documents/my-pj/homelab/edr-threat-hunting

git add .github/workflows/
git add CI_CD_SETUP.md
git commit -m "Add CI/CD pipeline with GitHub Actions"
git push origin main

# 2. Commit GitOps manifests to home-lab-gitops repo
cd /Users/binhbl/Documents/my-pj/homelab/home-lab-gitops

git add services/edr-threat-hunting/base/agent-daemonset.yaml
git add applications/base/edr-threat-hunting.yaml
git commit -m "Update EDR to use GHCR images with semver strategy"
git push origin main
```

### Step 4: Trigger First Build

**Option A: Push a git tag (Recommended)**
```bash
cd /Users/binhbl/Documents/my-pj/homelab/edr-threat-hunting

# Create semver tag
git tag -a v1.0.0 -m "Release v1.0.0 - Initial production release"
git push origin v1.0.0

# This will trigger:
# - GitHub Actions build
# - Docker image: ghcr.io/blubln7/edr-agent:v1.0.0
# - Tags: v1.0.0, v1.0, v1, latest
```

**Option B: Push to main branch**
```bash
# Any push to main will trigger build with 'latest' tag
git commit --allow-empty -m "Trigger CI/CD build"
git push origin main
```

### Step 5: Monitor Pipeline

**GitHub Actions:**
```bash
# Check build status:
# https://github.com/BLuBin7/edr-threat-hunting/actions
```

**ArgoCD Image Updater:**
```bash
# Check Image Updater logs
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-image-updater -f

# Expected output:
# time="..." level=info msg="Processing image edr-agent" image="ghcr.io/blubln7/edr-agent"
# time="..." level=info msg="Found new version v1.0.0"
# time="..." level=info msg="Updating image to v1.0.0"
```

**ArgoCD Application:**
```bash
# Check sync status
kubectl get application edr-threat-hunting -n argocd

# Watch deployment
kubectl get pods -n edr-system -w
```

---

## 🎯 Usage Examples

### Release New Version

```bash
cd /Users/binhbl/Documents/my-pj/homelab/edr-threat-hunting

# 1. Make code changes
vim agent/internal/monitors/network.go

# 2. Commit changes
git add .
git commit -m "Fix: Add whitelist for cluster IPs"

# 3. Tag new version
git tag -a v1.0.1 -m "Release v1.0.1 - Fix network false positives"
git push origin main
git push origin v1.0.1

# 4. Wait for automation:
#    - GitHub Actions build (~5 min)
#    - Image Updater detect (~2 min)
#    - ArgoCD sync (~3 min)
# Total: ~10 minutes from commit to production
```

### Hotfix Release

```bash
# Create hotfix branch
git checkout -b hotfix/v1.0.2

# Fix critical bug
vim agent/internal/monitors/file.go
git commit -am "Hotfix: Critical security patch"

# Tag and push
git tag v1.0.2
git push origin hotfix/v1.0.2
git push origin v1.0.2

# Merge back to main
git checkout main
git merge hotfix/v1.0.2
git push origin main
```

### Rollback to Previous Version

**Option 1: Via ArgoCD UI**
```bash
# 1. Open ArgoCD UI: https://argocd.example.com
# 2. Navigate to edr-threat-hunting app
# 3. Click History
# 4. Select previous revision
# 5. Click Rollback
```

**Option 2: Via Git**
```bash
cd /Users/binhbl/Documents/my-pj/homelab/home-lab-gitops

# Find the commit before Image Updater's change
git log --oneline services/edr-threat-hunting/base/agent-daemonset.yaml

# Revert to previous image version
git revert <commit-hash>
git push origin main

# ArgoCD will auto-sync back to old version
```

**Option 3: Manual image override**
```bash
# Edit DaemonSet directly
kubectl edit daemonset edr-agent -n edr-system

# Change image from:
#   image: ghcr.io/blubln7/edr-agent:v1.0.1
# To:
#   image: ghcr.io/blubln7/edr-agent:v1.0.0

# Note: ArgoCD will revert this change on next sync
# To make permanent, update Git manifest
```

---

## 🔍 Monitoring & Troubleshooting

### Check Build Status

```bash
# GitHub Actions status
gh run list --repo BLuBin7/edr-threat-hunting

# View logs of latest run
gh run view --repo BLuBin7/edr-threat-hunting --log

# Check Docker image exists
docker pull ghcr.io/blubln7/edr-agent:latest
docker inspect ghcr.io/blubln7/edr-agent:latest
```

### Debug Image Updater

```bash
# Check Image Updater config
kubectl get configmap argocd-image-updater-config -n argocd -o yaml

# Check Image Updater logs
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-image-updater --tail=100

# Trigger manual update
kubectl annotate application edr-threat-hunting \
  argocd-image-updater.argoproj.io/update-strategy=semver \
  --overwrite -n argocd

# Check last update time
kubectl get application edr-threat-hunting -n argocd -o jsonpath='{.status.summary.images}'
```

### Debug ArgoCD Sync

```bash
# Check application health
kubectl describe application edr-threat-hunting -n argocd

# Force sync
argocd app sync edr-threat-hunting --force

# Check sync history
argocd app history edr-threat-hunting

# Check pod image version
kubectl get pods -n edr-system -o jsonpath='{.items[*].spec.containers[*].image}'
```

### Build Failed Troubleshooting

**Error: "denied: permission_denied"**
```bash
# Fix: Make package public
# Go to: https://github.com/BLuBin7/edr-threat-hunting/pkgs/container/edr-agent/settings
# Change visibility to Public
```

**Error: "buildx not found"**
```yaml
# This shouldn't happen on GitHub Actions
# If local, install Docker Buildx:
docker buildx install
```

**Error: "go.mod not found"**
```bash
# Fix Dockerfile context
# Ensure Dockerfile copies from correct path:
COPY agent/go.mod agent/go.sum ./
```

---

## 📊 CI/CD Metrics

**Typical Pipeline Times:**

| Stage | Duration |
|-------|----------|
| Tests | 2-3 min |
| Docker Build (multi-arch) | 3-5 min |
| Push to GHCR | 30-60 sec |
| **Total CI/CD** | **5-8 min** |
| Image Updater detect | 0-2 min (polling) |
| ArgoCD sync | 0-3 min (polling) |
| K8s rolling update | 1-2 min |
| **Total to Production** | **6-15 min** |

**Cost:**
- GitHub Actions: **2,000 free minutes/month** (plenty for this project)
- GHCR Storage: **500 MB free** (single image ~50 MB)
- Total: **$0/month** ✅

---

## 🔐 Security Best Practices

1. **Always use semver tags** for production releases
2. **Never push with `latest` tag** for production (use `main-<sha>` instead)
3. **Enable Dependabot** for Go dependencies:
   ```yaml
   # .github/dependabot.yml
   version: 2
   updates:
     - package-ecosystem: "gomod"
       directory: "/agent"
       schedule:
         interval: "weekly"
   ```
4. **Sign container images** (already enabled via `attest-build-provenance`)
5. **Scan for vulnerabilities**:
   ```bash
   # Add to .github/workflows/docker-build.yml
   - name: Run Trivy vulnerability scanner
     uses: aquasecurity/trivy-action@master
     with:
       image-ref: ghcr.io/blubln7/edr-agent:${{ steps.meta.outputs.version }}
       format: 'sarif'
       output: 'trivy-results.sarif'
   ```

---

## 📚 References

- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [GHCR Docs](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [ArgoCD Image Updater](https://argocd-image-updater.readthedocs.io/)
- [Semantic Versioning](https://semver.org/)

---

## 🎉 Next Steps

After CI/CD is working:

1. ✅ Setup branch protection rules (require tests to pass)
2. ✅ Add code coverage reporting (Codecov)
3. ✅ Configure Slack/Discord notifications for deployments
4. ✅ Add staging environment (overlay)
5. ✅ Implement blue-green deployments

---

**Ready to deploy?** Follow Step 3 above to commit and trigger your first build! 🚀
