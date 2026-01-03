#!/bin/bash
# End-to-End PQC Testing Script for Tailscale/Headscale
#
# This script tests the complete PQC key generation and handshake flow:
# 1. Starts a Headscale server
# 2. Registers multiple Tailscale nodes
# 3. Verifies PQC keys are generated and distributed
# 4. Tests connectivity between nodes using PQC-enabled handshakes
#
# Usage: ./test-pqc-e2e.sh [--cleanup-only]

set -e

# Detect if running in CI
IN_CI=false
if [ -n "$GITHUB_ACTIONS" ] || [ -n "$CI" ]; then
    IN_CI=true
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test directories
TEST_DIR="/tmp/headscale-pqc-test"
HEADSCALE_DIR="$TEST_DIR/headscale"
NODE1_DIR="$TEST_DIR/node1"
NODE2_DIR="$TEST_DIR/node2"
NODE3_DIR="$TEST_DIR/node3"

# Ports
HEADSCALE_PORT=8080
HEADSCALE_METRICS_PORT=9090

# Binaries - can be overridden via environment variables
HEADSCALE_BIN="${HEADSCALE_BIN:-$(pwd)/headscale}"
TAILSCALE_BIN="${TAILSCALE_BIN:-tailscale}"
TAILSCALED_BIN="${TAILSCALED_BIN:-tailscaled}"

# Detect Tailscale binaries
if ! command -v "$TAILSCALE_BIN" &> /dev/null; then
    # Try common locations
    if [ -f "./tailscale" ]; then
        TAILSCALE_BIN="./tailscale"
    elif [ -f "../tailscale/tailscale" ]; then
        TAILSCALE_BIN="../tailscale/tailscale"
    else
        echo -e "${RED}ERROR: tailscale binary not found. Please set TAILSCALE_BIN or ensure it's in PATH.${NC}"
        exit 1
    fi
fi

if ! command -v "$TAILSCALED_BIN" &> /dev/null; then
    # Try common locations
    if [ -f "./tailscaled" ]; then
        TAILSCALED_BIN="./tailscaled"
    elif [ -f "../tailscale/tailscaled" ]; then
        TAILSCALED_BIN="../tailscale/tailscaled"
    else
        echo -e "${RED}ERROR: tailscaled binary not found. Please set TAILSCALED_BIN or ensure it's in PATH.${NC}"
        exit 1
    fi
fi

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}$1${NC}"
    echo -e "${YELLOW}========================================${NC}"
}

cleanup() {
    log_section "Cleaning up test environment"

    # Kill all tailscaled processes
    pkill -f "tailscaled.*$TEST_DIR" || true

    # Kill headscale
    pkill -f "headscale.*$TEST_DIR" || true

    # Wait a bit for processes to die
    sleep 2

    # Force kill if still running
    pkill -9 -f "tailscaled.*$TEST_DIR" || true
    pkill -9 -f "headscale.*$TEST_DIR" || true

    # Remove test directory
    if [ -d "$TEST_DIR" ]; then
        log_info "Removing test directory: $TEST_DIR"
        rm -rf "$TEST_DIR"
    fi

    log_success "Cleanup complete"
}

# Handle cleanup-only mode
if [ "$1" == "--cleanup-only" ]; then
    cleanup
    exit 0
fi

# Trap to cleanup on exit (only if not in CI)
if [ "$IN_CI" = false ]; then
    trap cleanup EXIT INT TERM
fi

build_binaries() {
    log_section "Building binaries"

    # Build headscale
    log_info "Building Headscale..."
    cd "$(dirname "$0")"
    go build -o "$HEADSCALE_BIN" ./cmd/headscale
    log_success "Headscale built: $HEADSCALE_BIN"

    # Build tailscale with PQC-enabled wireguard-go
    # Determine tailscale source directory
    TAILSCALE_SRC="${TAILSCALE_SRC:-}"
    if [ -z "$TAILSCALE_SRC" ]; then
        # Try common locations relative to headscale
        if [ -d "../tailscale" ]; then
            TAILSCALE_SRC="../tailscale"
        elif [ -d "../../tailscale" ]; then
            TAILSCALE_SRC="../../tailscale"
        else
            log_warn "TAILSCALE_SRC not set and ../tailscale not found. Skipping Tailscale build."
            log_info "Using pre-built binaries: $TAILSCALE_BIN, $TAILSCALED_BIN"
            return 0
        fi
    fi

    log_info "Building Tailscale with PQC support from: $TAILSCALE_SRC"
    cd "$TAILSCALE_SRC"
    go build -o "$TAILSCALED_BIN" ./cmd/tailscaled
    go build -o "$TAILSCALE_BIN" ./cmd/tailscale
    log_success "Tailscale built with PQC support"
}

setup_headscale() {
    log_section "Setting up Headscale"

    mkdir -p "$HEADSCALE_DIR"

    # Create headscale config
    cat > "$HEADSCALE_DIR/config.yaml" <<EOF
server_url: http://127.0.0.1:$HEADSCALE_PORT
listen_addr: 127.0.0.1:$HEADSCALE_PORT
metrics_listen_addr: 127.0.0.1:$HEADSCALE_METRICS_PORT
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: true

private_key_path: $HEADSCALE_DIR/private.key
noise_private_key_path: $HEADSCALE_DIR/noise_private.key
base_domain: headscale.test

unix_socket: /tmp/headscale-pqc-test/headscale/headscale.sock
unix_socket_permission: "0770"

ip_prefixes:
  - fd7a:115c:a1e0::/48
  - 100.64.0.0/10

noise:
  private_key_path: /tmp/headscale-pqc-test/headscale/noise_private.key

derp:
  server:
    enabled: true
    region_id: 999
    region_code: "headscale"
    region_name: "Headscale Embedded DERP"
    stun_listen_addr: "0.0.0.0:3478"
    private_key_path: $HEADSCALE_DIR/derp_server_private.key
  urls: []
  paths: []
  auto_update_enabled: false

log:
  level: debug

database:
  type: sqlite
  sqlite:
    path: $HEADSCALE_DIR/db.sqlite

prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48

dns:
  base_domain: headscale.test
  magic_dns: true
  nameservers:
    global:
      - 1.1.1.1
      - 8.8.8.8
EOF

    log_info "Starting Headscale server..."
    "$HEADSCALE_BIN" serve --config "$HEADSCALE_DIR/config.yaml" > "$HEADSCALE_DIR/headscale.log" 2>&1 &
    HEADSCALE_PID=$!

    # Wait for headscale to start
    log_info "Waiting for Headscale to start..."
    for i in {1..30}; do
        if curl -s http://127.0.0.1:$HEADSCALE_PORT/health > /dev/null 2>&1; then
            log_success "Headscale started (PID: $HEADSCALE_PID)"
            return 0
        fi
        sleep 1
    done

    log_error "Headscale failed to start. Check logs at $HEADSCALE_DIR/headscale.log"
    cat "$HEADSCALE_DIR/headscale.log"
    exit 1
}

create_user() {
    local username=$1
    log_info "Creating user: $username"
    "$HEADSCALE_BIN" --config "$HEADSCALE_DIR/config.yaml" users create "$username" || true
}

create_preauth_key() {
    local username=$1
    log_info "Creating pre-auth key for user: $username" >&2
    local output=$("$HEADSCALE_BIN" --config "$HEADSCALE_DIR/config.yaml" preauthkeys create \
        --user "$username" \
        --reusable \
        --expiration 1h 2>&1)

    # Extract the key from output (format: hskey-auth--...)
    local key=$(echo "$output" | grep -oE 'hskey-[a-zA-Z0-9_-]+' | head -1)

    if [ -z "$key" ]; then
        log_error "Failed to create pre-auth key. Output:" >&2
        echo "$output" >&2
        return 1
    fi

    echo "$key"
}

start_tailscale_node() {
    local node_name=$1
    local node_dir=$2
    local username=$3
    local preauth_key=$4
    local port=$5

    log_info "Starting Tailscale node: $node_name on port $port"

    mkdir -p "$node_dir"

    # Start tailscaled
    log_info "Starting tailscaled for $node_name..."
    sudo "$TAILSCALED_BIN" \
        --state="$node_dir/tailscaled.state" \
        --socket="$node_dir/tailscaled.sock" \
        --tun=userspace-networking \
        --port="$port" \
        > "$node_dir/tailscaled.log" 2>&1 &

    local tailscaled_pid=$!
    echo $tailscaled_pid > "$node_dir/tailscaled.pid"

    # Wait for tailscaled to start
    sleep 3

    # Connect to headscale
    log_info "Connecting $node_name to Headscale..."
    sudo "$TAILSCALE_BIN" \
        --socket="$node_dir/tailscaled.sock" \
        up \
        --login-server=http://127.0.0.1:$HEADSCALE_PORT \
        --authkey="$preauth_key" \
        --hostname="$node_name"

    log_success "$node_name started and connected"
}

verify_pqc_keys() {
    log_section "Verifying PQC Key Generation"

    log_info "Checking if nodes generated PQC keys..."

    for node_dir in "$NODE1_DIR" "$NODE2_DIR" "$NODE3_DIR"; do
        local node_name=$(basename "$node_dir")
        local log_file="$node_dir/tailscaled.log"

        if [ -f "$log_file" ]; then
            log_info "Checking $node_name logs..."

            # Check if PQC keys were generated
            if grep -q "Generated new PQC keys" "$log_file" 2>/dev/null; then
                log_success "$node_name: PQC keys generated"
            else
                log_warn "$node_name: PQC key generation not found in logs"
            fi

            # Check if PQC seed is being set in wgcfg
            if grep -q "wgcfg:.*PQC seed" "$log_file" 2>/dev/null; then
                log_success "$node_name: PQC seed is being configured"
            else
                log_warn "$node_name: PQC seed configuration not found in logs"
            fi

            # Check if PQC keys are being set for peers
            if grep -q "wgcfg:.*peer.*PQC public key" "$log_file" 2>/dev/null; then
                log_success "$node_name: Peer PQC public keys are being configured"
            else
                log_warn "$node_name: Peer PQC key configuration not found in logs"
            fi
        else
            log_error "$node_name: Log file not found"
        fi
    done

    # Check headscale database for PQC keys
    log_info "Checking Headscale database for PQC keys..."
    local db_file="$HEADSCALE_DIR/db.sqlite"

    if [ -f "$db_file" ]; then
        local pqc_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM nodes WHERE pqc_public_key IS NOT NULL AND pqc_public_key != '';" 2>/dev/null || echo "0")
        log_info "Nodes with PQC public keys in Headscale DB: $pqc_count"

        if [ "$pqc_count" -gt "0" ]; then
            log_success "Headscale has stored PQC public keys for $pqc_count node(s)"

            # Show PQC key lengths
            log_info "PQC key lengths:"
            sqlite3 "$db_file" "SELECT hostname, LENGTH(pqc_public_key) as key_len FROM nodes WHERE pqc_public_key IS NOT NULL;" 2>/dev/null || true
        else
            log_warn "No PQC public keys found in Headscale database"
        fi
    fi
}

test_connectivity() {
    log_section "Testing Node Connectivity"

    # Get node IPs
    log_info "Getting node IP addresses..."

    local node1_ip=$(sudo "$TAILSCALE_BIN" --socket="$NODE1_DIR/tailscaled.sock" ip -4 | head -1)
    local node2_ip=$(sudo "$TAILSCALE_BIN" --socket="$NODE2_DIR/tailscaled.sock" ip -4 | head -1)
    local node3_ip=$(sudo "$TAILSCALE_BIN" --socket="$NODE3_DIR/tailscaled.sock" ip -4 | head -1)

    log_info "Node1 IP: $node1_ip"
    log_info "Node2 IP: $node2_ip"
    log_info "Node3 IP: $node3_ip"

    # Test ping from node1 to node2
    log_info "Testing ping from node1 to node2..."
    if sudo "$TAILSCALE_BIN" --socket="$NODE1_DIR/tailscaled.sock" ping --c 3 "$node2_ip"; then
        log_success "Node1 → Node2 connectivity verified"
    else
        log_error "Node1 → Node2 ping failed"
    fi

    # Test ping from node2 to node3
    log_info "Testing ping from node2 to node3..."
    if sudo "$TAILSCALE_BIN" --socket="$NODE2_DIR/tailscaled.sock" ping --c 3 "$node3_ip"; then
        log_success "Node2 → Node3 connectivity verified"
    else
        log_error "Node2 → Node3 ping failed"
    fi

    # Test ping from node1 to node3
    log_info "Testing ping from node1 to node3..."
    if sudo "$TAILSCALE_BIN" --socket="$NODE1_DIR/tailscaled.sock" ping --c 3 "$node3_ip"; then
        log_success "Node1 → Node3 connectivity verified"
    else
        log_error "Node1 → Node3 ping failed"
    fi
}

check_wireguard_config() {
    log_section "Checking WireGuard Configuration"

    for node_dir in "$NODE1_DIR" "$NODE2_DIR" "$NODE3_DIR"; do
        local node_name=$(basename "$node_dir")
        log_info "Checking WireGuard config for $node_name..."

        # The tailscale status command might show peer information
        sudo "$TAILSCALE_BIN" --socket="$node_dir/tailscaled.sock" status --json > "$node_dir/status.json" 2>/dev/null || true

        if [ -f "$node_dir/status.json" ]; then
            log_success "$node_name: Status exported to $node_dir/status.json"
        fi
    done
}

show_logs() {
    log_section "Recent Logs"

    log_info "Headscale PQC-related logs:"
    echo "---"
    grep -i "pqc" "$HEADSCALE_DIR/headscale.log" | tail -20 || echo "No PQC logs found"
    echo "---"

    log_info "Node1 PQC-related logs:"
    echo "---"
    grep -i "pqc\|wgcfg" "$NODE1_DIR/tailscaled.log" | grep -v "RAW-STDERR" | tail -30 || echo "No PQC logs found"
    echo "---"

    log_info "Full Headscale logs (last 50 lines):"
    echo "---"
    tail -50 "$HEADSCALE_DIR/headscale.log" || true
    echo "---"

    log_info "Full Node1 logs (last 30 lines):"
    echo "---"
    tail -30 "$NODE1_DIR/tailscaled.log" || true
    echo "---"
}

main() {
    log_section "PQC End-to-End Test Suite"
    log_info "Test directory: $TEST_DIR"

    # Clean up any previous test runs
    cleanup

    # Build binaries
    build_binaries

    # Setup and start Headscale
    setup_headscale

    # Create user
    create_user "testuser"

    # Create pre-auth key
    PREAUTH_KEY=$(create_preauth_key 1)
    log_info "Pre-auth key: $PREAUTH_KEY"

    # Start Tailscale nodes with specific ports
    start_tailscale_node "node1" "$NODE1_DIR" 1 "$PREAUTH_KEY" 41641
    start_tailscale_node "node2" "$NODE2_DIR" 1 "$PREAUTH_KEY" 41642
    start_tailscale_node "node3" "$NODE3_DIR" 1 "$PREAUTH_KEY" 41643

    # Wait for nodes to settle
    sleep 5

    # Verify PQC keys were generated
    verify_pqc_keys

    # Test connectivity
    test_connectivity

    # Check WireGuard configuration
    check_wireguard_config

    # Show logs
    show_logs

    log_section "Test Summary"
    log_success "End-to-end test complete!"
    log_info "Test artifacts saved in: $TEST_DIR"
    log_info ""
    log_info "To manually inspect:"
    log_info "  - Headscale logs: $HEADSCALE_DIR/headscale.log"
    log_info "  - Node logs: $NODE*_DIR/tailscaled.log"
    log_info "  - Node status: $NODE*_DIR/status.json"
    log_info "  - Database: $HEADSCALE_DIR/db.sqlite"
    log_info ""

    # Different behavior for CI vs local
    if [ "$IN_CI" = true ]; then
        log_info "Running in CI - exiting without cleanup to preserve artifacts"
        exit 0
    else
        log_warn "Test environment will remain running. Press Ctrl+C to cleanup and exit."
        log_warn "Or run: $0 --cleanup-only"
        # Keep running
        wait
    fi
}

# Run main
main
