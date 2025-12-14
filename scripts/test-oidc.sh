#!/bin/bash
# Test OIDC authentication flow
# This tests local JWT validation (OIDC mode) vs token introspection

set -e

AUTH_PORT=8445
MCP_PORT=8086

echo "Building..."
go build -o /tmp/mcp-token-server ./cmd/mcp-token-server
go build -o /tmp/mcp-sysinfo ./cmd/mcp-sysinfo

# Create temporary clients file (JSON format)
# Secret "testsecret" hashed with SHA256
CLIENTS_FILE=$(mktemp)
cat > "$CLIENTS_FILE" << 'EOF'
[
  {
    "id": "testuser",
    "name": "Test User",
    "secret_hash": "59953998e54a579be74c1b7344cd55c64981451b066a35c9d7baf5497f16d865",
    "allowed_scopes": ["core", "logs"],
    "enabled": true
  }
]
EOF

# Start token server
echo "Starting token server on port $AUTH_PORT..."
/tmp/mcp-token-server serve \
    --listen "127.0.0.1:$AUTH_PORT" \
    --issuer "http://localhost:$AUTH_PORT" \
    --audience "http://127.0.0.1:$MCP_PORT" \
    --clients "$CLIENTS_FILE" &
AUTH_PID=$!

sleep 1

# Start MCP server with OIDC (local JWT validation)
echo "Starting MCP server with OIDC on port $MCP_PORT..."
/tmp/mcp-sysinfo --transport http \
    --listen "127.0.0.1:$MCP_PORT" \
    --oidc-issuer "http://localhost:$AUTH_PORT" \
    --oidc-audience "http://127.0.0.1:$MCP_PORT" &
MCP_PID=$!

sleep 1

cleanup() {
    echo "Cleaning up..."
    kill $AUTH_PID $MCP_PID 2>/dev/null || true
    rm -f "$CLIENTS_FILE"
}
trap cleanup EXIT

echo ""
echo "=== Test 1: No token (should get 401) ==="
curl -s -X POST "http://127.0.0.1:$MCP_PORT/" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_uptime"}}' | jq .

echo ""
echo "=== Test 2: Get access token ==="
TOKEN=$(curl -s -X POST "http://127.0.0.1:$AUTH_PORT/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&client_id=testuser&client_secret=testsecret&resource=http://127.0.0.1:$MCP_PORT" \
    | jq -r '.access_token')
echo "Got token: ${TOKEN:0:50}..."

echo ""
echo "=== Test 3: Call with valid token (OIDC validation) ==="
curl -s -X POST "http://127.0.0.1:$MCP_PORT/" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_uptime"}}' | jq .

echo ""
echo "=== Test 4: Check health endpoint ==="
curl -s "http://127.0.0.1:$MCP_PORT/health" | jq .

echo ""
echo "All OIDC tests passed!"
