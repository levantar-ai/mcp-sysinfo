# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o mcp-sysinfo \
    ./cmd/mcp-sysinfo

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies for system diagnostics
RUN apk add --no-cache \
    ca-certificates \
    procps \
    lsof \
    iproute2 \
    util-linux \
    coreutils

# Create non-root user
RUN adduser -D -u 1000 mcp

# Copy binary from builder
COPY --from=builder /build/mcp-sysinfo /usr/local/bin/mcp-sysinfo

# Set permissions
RUN chmod +x /usr/local/bin/mcp-sysinfo

# Switch to non-root user (can be overridden for privileged queries)
USER mcp

# Default to stdio mode for MCP clients
ENTRYPOINT ["/usr/local/bin/mcp-sysinfo"]

# Labels
LABEL org.opencontainers.image.title="MCP System Info"
LABEL org.opencontainers.image.description="Read-only AI diagnostics plane via Model Context Protocol"
LABEL org.opencontainers.image.source="https://github.com/levantar-ai/mcp-sysinfo"
LABEL org.opencontainers.image.licenses="MIT"
