.PHONY: help build run test clean docker-build docker-push k8s-deploy ml-train demo

# Variables
BINARY_NAME=edr-agent
DOCKER_IMAGE=edr-agent:latest
GO_FILES=$(shell find agent -name '*.go')

help: ## Show this help message
	@echo "EDR Threat Hunting - Makefile Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

## Agent Build & Run
build: ## Build the EDR agent binary
	@echo "Building agent..."
	cd agent && go build -o ../bin/$(BINARY_NAME) cmd/agent/main.go
	@echo "✅ Build complete: bin/$(BINARY_NAME)"

run: build ## Run the agent locally
	@echo "Running agent locally..."
	sudo ./bin/$(BINARY_NAME) --config agent/config.yaml

test: ## Run Go tests
	@echo "Running tests..."
	cd agent && go test -v ./...

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf bin/ ml-training/models/*.pkl ml-training/models/*.onnx
	@echo "✅ Clean complete"

## ML Training
ml-setup: ## Setup Python environment for ML training
	@echo "Setting up Python environment..."
	cd ml-training && python3 -m venv venv
	cd ml-training && ./venv/bin/pip install -r requirements.txt
	@echo "✅ Python environment ready. Activate with: source ml-training/venv/bin/activate"

ml-train: ## Train Isolation Forest model
	@echo "Training ML model..."
	cd ml-training && python3 scripts/train_isolation_forest.py \
		--output-dir models \
		--n-normal 5000 \
		--n-anomaly 500 \
		--mlflow-tracking-uri http://localhost:5000
	@echo "✅ Training complete"

ml-export: ## Export model to ONNX format
	@echo "Exporting model to ONNX..."
	cd ml-training && python3 scripts/export_onnx.py \
		--model models/isolation_forest.pkl \
		--output models/model.onnx \
		--quantize \
		--benchmark
	@echo "✅ Export complete: ml-training/models/model.onnx"

ml-all: ml-train ml-export ## Train and export ML model

## Docker
docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) -f Dockerfile .
	@echo "✅ Docker image built: $(DOCKER_IMAGE)"

docker-push: docker-build ## Push Docker image to registry
	@echo "Pushing to registry..."
	docker push $(DOCKER_IMAGE)

## Kubernetes
k8s-deploy: ## Deploy to Kubernetes cluster
	@echo "Deploying to Kubernetes..."
	kubectl apply -f k8s/agent/daemonset.yaml
	kubectl apply -f k8s/backend/victoria-metrics.yaml
	kubectl apply -f k8s/backend/grafana.yaml
	@echo "✅ Deployment complete"
	@echo ""
	@echo "Check status:"
	@echo "  kubectl get pods -n edr-system"
	@echo "  kubectl logs -n edr-system -l app=edr-agent -f"

k8s-status: ## Check Kubernetes deployment status
	@echo "EDR System Status:"
	@echo ""
	kubectl get pods -n edr-system
	@echo ""
	kubectl get svc -n edr-system

k8s-logs: ## Tail agent logs
	kubectl logs -n edr-system -l app=edr-agent -f

k8s-delete: ## Delete Kubernetes deployment
	kubectl delete -f k8s/agent/daemonset.yaml
	kubectl delete -f k8s/backend/victoria-metrics.yaml
	kubectl delete -f k8s/backend/grafana.yaml

## Demo
demo-setup: ## Make demo scripts executable
	chmod +x demo/attack_scripts/*.sh

demo-encoded-ps: demo-setup ## Run encoded PowerShell demo attack
	@echo "Running demo attack: Encoded PowerShell"
	./demo/attack_scripts/01_encoded_powershell.sh

demo-credential: demo-setup ## Run credential access demo attack
	@echo "Running demo attack: Credential Access"
	./demo/attack_scripts/02_credential_access.sh

demo-beaconing: demo-setup ## Run C2 beaconing demo attack
	@echo "Running demo attack: C2 Beaconing"
	./demo/attack_scripts/03_beaconing_simulation.sh

demo-all: demo-encoded-ps demo-credential demo-beaconing ## Run all demo attacks

## Benchmark
benchmark: ## Run performance benchmark
	@echo "Running benchmark..."
	@echo "Not implemented yet - manual testing required"
	@echo "Check docs/BENCHMARK.md for instructions"

## Development
dev-deps: ## Install development dependencies
	@echo "Installing Go dependencies..."
	cd agent && go mod download
	@echo "✅ Go dependencies installed"

fmt: ## Format Go code
	cd agent && go fmt ./...

lint: ## Lint Go code (requires golangci-lint)
	cd agent && golangci-lint run ./...

all: clean build test ## Clean, build, and test
