# Multi-stage build for EDR Agent
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /build

# Copy go mod files
COPY agent/go.mod agent/go.sum ./
RUN go mod download

# Copy source code
COPY agent/ ./

# Build binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o edr-agent \
    cmd/agent/main.go

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    bash \
    netcat-openbsd

# Create non-root user (will run as root in DaemonSet for host access)
RUN addgroup -g 1000 edr && \
    adduser -D -u 1000 -G edr edr

# Create necessary directories
RUN mkdir -p /etc/edr-agent /var/log/edr-agent && \
    chown -R edr:edr /var/log/edr-agent

# Copy binary from builder
COPY --from=builder /build/edr-agent /usr/local/bin/edr-agent
RUN chmod +x /usr/local/bin/edr-agent

# Copy default config
COPY agent/config.yaml /etc/edr-agent/config.yaml

# Expose metrics port
EXPOSE 9090

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD nc -z localhost 9090 || exit 1

# Run as edr user (overridden in K8s DaemonSet to run as root)
USER edr

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/edr-agent"]
CMD ["--config", "/etc/edr-agent/config.yaml"]
