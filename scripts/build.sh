#!/bin/bash
# Build script for EDR Agent

set -e  # Exit on error

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================="
echo "EDR Agent Build Script"
echo "=========================================="
echo ""

# Check Go installation
if ! command -v go &> /dev/null; then
    echo "❌ Go not found. Please install Go 1.21+"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}')
echo "✓ Go detected: $GO_VERSION"

# Create bin directory
mkdir -p bin

# Build agent
echo ""
echo "Building EDR agent..."
cd agent

# Download dependencies if needed
if [ ! -d "vendor" ]; then
    echo "  Downloading Go dependencies..."
    go mod download
    go mod tidy
fi

# Build
echo "  Compiling binary..."
CGO_ENABLED=0 go build \
    -ldflags="-w -s -X main.version=1.0.0 -X main.buildTime=$(date -u '+%Y-%m-%d_%H:%M:%S')" \
    -o ../bin/edr-agent \
    cmd/agent/main.go

# Verify binary
if [ -f "../bin/edr-agent" ]; then
    FILE_SIZE=$(du -h ../bin/edr-agent | awk '{print $1}')
    echo ""
    echo "✅ Build successful!"
    echo "   Binary: bin/edr-agent"
    echo "   Size: $FILE_SIZE"
    echo ""
    echo "Run with:"
    echo "  sudo ./bin/edr-agent --config agent/config.yaml"
else
    echo ""
    echo "❌ Build failed!"
    exit 1
fi
