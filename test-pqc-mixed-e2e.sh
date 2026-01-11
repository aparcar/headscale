#!/bin/bash
# End-to-End Mixed PQC Testing Script for Tailscale/Headscale
#
# This script tests connectivity between PQC-enabled and non-PQC nodes:
# 1. Starts a Headscale server
# 2. Registers Tailscale nodes with varying PQC settings
# 3. Verifies PQC keys are generated only for PQC-enabled nodes
# 4. Tests connectivity between all nodes (PQC <-> PQC, PQC <-> non-PQC)
#
# Usage: ./test-pqc-mixed-e2e.sh [--cleanup-only]
#
# Environment variables:
#   HEADSCALE_BIN    - Path to headscale binary (default: ./headscale)
#   TAILSCALE_BIN    - Path to tailscale binary (default: tailscale)
#   TAILSCALED_BIN   - Path to tailscaled binary (default: tailscaled)
#   TAILSCALE_SRC    - Path to tailscale source (for building)
#
# Node configuration:
#   By default, this script starts 3 nodes:
#   - node1: PQC enabled
#   - node2: PQC disabled (uses TS_DISABLE_PQC=1)
#   - node3: PQC enabled

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
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test directories
TEST_DIR="/tmp/headscale-pqc-mixed-test"
HEADSCALE_DIR="$TEST_DIR/headscale"
NODE1_DIR="$TEST_DIR/node1"
NODE2_DIR="$TEST_DIR/node2"
NODE3_DIR="$TEST_DIR/node3"

# Ports
HEADSCALE_PORT=8081
HEADSCALE_METRICS_PORT=9091

# Binaries - can be overridden via environment variables
HEADSCALE_BIN="${HEADSCALE_BIN:-$(pwd)/headscale}"
TAILSCALE_BIN="${TAILSCALE_BIN:-tailscale}"
TAILSCALED_BIN="${TAILSCALED_BIN:-tailscaled}"

# Node PQC configuration (1 = PQC enabled, 0 = PQC disabled)
NODE1_PQC="${NODE1_PQC:-1}"
NODE2_PQC="${NODE2_PQC:-0}"
NODE3_PQC="${NODE3_PQC:-1}"

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

log_pqc() {
    echo -e "${CYAN}[PQC]${NC} $1"
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
grpc_listen_addr: 127.0.0.1:50444
grpc_allow_insecure: true

private_key_path: $HEADSCALE_DIR/private.key
noise_private_key_path: $HEADSCALE_DIR/noise_private.key
base_domain: headscale.test

unix_socket: $HEADSCALE_DIR/headscale.sock
unix_socket_permission: "0770"

ip_prefixes:
  - fd7a:115c:a1e0::/48
  - 100.64.0.0/10

noise:
  private_key_path: $HEADSCALE_DIR/noise_private.key

derp:
  server:
    enabled: true
    region_id: 998
    region_code: "headscale"
    region_name: "Headscale Embedded DERP"
    stun_listen_addr: "0.0.0.0:3479"
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

# Start a tailscale node with optional PQC disabled
# Arguments:
#   $1: node_name
#   $2: node_dir
#   $3: username
#   $4: preauth_key
#   $5: port
#   $6: pqc_enabled (1 = enabled, 0 = disabled)
start_tailscale_node() {
    local node_name=$1
    local node_dir=$2
    local username=$3
    local preauth_key=$4
    local port=$5
    local pqc_enabled=${6:-1}

    if [ "$pqc_enabled" == "1" ]; then
        log_pqc "Starting Tailscale node: $node_name on port $port (PQC ENABLED)"
    else
        log_pqc "Starting Tailscale node: $node_name on port $port (PQC DISABLED)"
    fi

    mkdir -p "$node_dir"

    # Build environment for tailscaled
    local env_vars=""
    if [ "$pqc_enabled" == "0" ]; then
        env_vars="TS_DISABLE_PQC=1"
    fi

    # Start tailscaled with appropriate environment
    log_info "Starting tailscaled for $node_name..."
    if [ -n "$env_vars" ]; then
        sudo env $env_vars "$TAILSCALED_BIN" \
            --state="$node_dir/tailscaled.state" \
            --socket="$node_dir/tailscaled.sock" \
            --tun=userspace-networking \
            --port="$port" \
            > "$node_dir/tailscaled.log" 2>&1 &
    else
        sudo "$TAILSCALED_BIN" \
            --state="$node_dir/tailscaled.state" \
            --socket="$node_dir/tailscaled.sock" \
            --tun=userspace-networking \
            --port="$port" \
            > "$node_dir/tailscaled.log" 2>&1 &
    fi

    local tailscaled_pid=$!
    echo $tailscaled_pid > "$node_dir/tailscaled.pid"
    echo "$pqc_enabled" > "$node_dir/pqc_enabled"

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
    log_section "Verifying PQC Key Generation (Mixed Mode)"

    log_info "Checking PQC key status for each node..."

    local pqc_nodes=0
    local non_pqc_nodes=0

    for node_dir in "$NODE1_DIR" "$NODE2_DIR" "$NODE3_DIR"; do
        local node_name=$(basename "$node_dir")
        local log_file="$node_dir/tailscaled.log"
        local pqc_config_file="$node_dir/pqc_enabled"
        local expected_pqc="1"

        if [ -f "$pqc_config_file" ]; then
            expected_pqc=$(cat "$pqc_config_file")
        fi

        if [ -f "$log_file" ]; then
            log_info "Checking $node_name (expected PQC: $( [ "$expected_pqc" == "1" ] && echo "enabled" || echo "disabled" ))..."

            # Check if PQC keys were generated
            local has_pqc_keys=false
            if grep -q "generated new PQC keys" "$log_file" 2>/dev/null; then
                has_pqc_keys=true
            fi

            if [ "$expected_pqc" == "1" ]; then
                if [ "$has_pqc_keys" == "true" ]; then
                    log_success "$node_name: PQC keys generated (as expected)"
                    pqc_nodes=$((pqc_nodes + 1))
                else
                    # Check if PQC seed is being set in wgcfg
                    if grep -q "wgcfg:.*PQC seed" "$log_file" 2>/dev/null; then
                        log_success "$node_name: PQC seed is being configured"
                        pqc_nodes=$((pqc_nodes + 1))
                    else
                        log_warn "$node_name: Expected PQC but key generation not found in logs"
                    fi
                fi
            else
                if [ "$has_pqc_keys" == "true" ]; then
                    log_error "$node_name: PQC keys generated but should be DISABLED"
                else
                    log_success "$node_name: No PQC keys (as expected - PQC disabled)"
                    non_pqc_nodes=$((non_pqc_nodes + 1))
                fi

                # Verify TS_DISABLE_PQC was respected
                if grep -q "PQC disabled" "$log_file" 2>/dev/null || \
                   grep -q "TS_DISABLE_PQC" "$log_file" 2>/dev/null || \
                   ! grep -q "wgcfg:.*device has PQC seed" "$log_file" 2>/dev/null; then
                    log_success "$node_name: TS_DISABLE_PQC environment variable respected"
                fi
            fi

            # Check if PQC keys are being set for peers
            if grep -q "wgcfg:.*peer.*PQC public key" "$log_file" 2>/dev/null; then
                local peer_pqc_count=$(grep -c "wgcfg:.*peer.*has PQC public key" "$log_file" 2>/dev/null || echo "0")
                log_info "$node_name: Sees $peer_pqc_count peer(s) with PQC public keys"
            fi
        else
            log_error "$node_name: Log file not found"
        fi
    done

    log_info ""
    log_pqc "Summary: $pqc_nodes PQC-enabled nodes, $non_pqc_nodes non-PQC nodes"

    # Check headscale database for PQC keys
    log_info "Checking Headscale database for PQC keys..."
    local db_file="$HEADSCALE_DIR/db.sqlite"

    if [ -f "$db_file" ]; then
        local pqc_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM nodes WHERE pqc_public_key IS NOT NULL AND pqc_public_key != '';" 2>/dev/null || echo "0")
        local total_count=$(sqlite3 "$db_file" "SELECT COUNT(*) FROM nodes;" 2>/dev/null || echo "0")
        log_info "Nodes with PQC public keys in Headscale DB: $pqc_count / $total_count"

        if [ "$pqc_count" -gt "0" ]; then
            log_success "Headscale has stored PQC public keys for $pqc_count node(s)"

            # Show PQC key details
            log_info "Node PQC status in database:"
            sqlite3 "$db_file" "SELECT hostname, CASE WHEN pqc_public_key IS NOT NULL AND pqc_public_key != '' THEN 'PQC enabled (' || LENGTH(pqc_public_key) || ' bytes)' ELSE 'No PQC' END as pqc_status FROM nodes;" 2>/dev/null || true
        fi
    fi
}

test_connectivity() {
    log_section "Testing Node Connectivity (Mixed PQC/Non-PQC)"

    # Get node IPs
    log_info "Getting node IP addresses..."

    local node1_ip=$(sudo "$TAILSCALE_BIN" --socket="$NODE1_DIR/tailscaled.sock" ip -4 | head -1)
    local node2_ip=$(sudo "$TAILSCALE_BIN" --socket="$NODE2_DIR/tailscaled.sock" ip -4 | head -1)
    local node3_ip=$(sudo "$TAILSCALE_BIN" --socket="$NODE3_DIR/tailscaled.sock" ip -4 | head -1)

    log_info "Node1 IP: $node1_ip (PQC: $( [ "$NODE1_PQC" == "1" ] && echo "enabled" || echo "disabled" ))"
    log_info "Node2 IP: $node2_ip (PQC: $( [ "$NODE2_PQC" == "1" ] && echo "enabled" || echo "disabled" ))"
    log_info "Node3 IP: $node3_ip (PQC: $( [ "$NODE3_PQC" == "1" ] && echo "enabled" || echo "disabled" ))"

    local all_passed=true

    # Test ping from node1 (PQC) to node2 (non-PQC)
    log_pqc "Testing: node1 (PQC=$NODE1_PQC) -> node2 (PQC=$NODE2_PQC)..."
    if timeout 10 sudo "$TAILSCALE_BIN" --socket="$NODE1_DIR/tailscaled.sock" ping --c 3 --timeout=5s "$node2_ip"; then
        log_success "Node1 -> Node2 connectivity verified"
    else
        log_error "Node1 -> Node2 ping failed"
        all_passed=false
    fi

    # Test ping from node2 (non-PQC) to node3 (PQC)
    log_pqc "Testing: node2 (PQC=$NODE2_PQC) -> node3 (PQC=$NODE3_PQC)..."
    if timeout 10 sudo "$TAILSCALE_BIN" --socket="$NODE2_DIR/tailscaled.sock" ping --c 3 --timeout=5s "$node3_ip"; then
        log_success "Node2 -> Node3 connectivity verified"
    else
        log_error "Node2 -> Node3 ping failed"
        all_passed=false
    fi

    # Test ping from node1 (PQC) to node3 (PQC)
    log_pqc "Testing: node1 (PQC=$NODE1_PQC) -> node3 (PQC=$NODE3_PQC)..."
    if timeout 10 sudo "$TAILSCALE_BIN" --socket="$NODE1_DIR/tailscaled.sock" ping --c 3 --timeout=5s "$node3_ip"; then
        log_success "Node1 -> Node3 connectivity verified"
    else
        log_error "Node1 -> Node3 ping failed"
        all_passed=false
    fi

    # Test ping from node2 (non-PQC) to node1 (PQC) - reverse direction
    log_pqc "Testing: node2 (PQC=$NODE2_PQC) -> node1 (PQC=$NODE1_PQC)..."
    if timeout 10 sudo "$TAILSCALE_BIN" --socket="$NODE2_DIR/tailscaled.sock" ping --c 3 --timeout=5s "$node1_ip"; then
        log_success "Node2 -> Node1 connectivity verified"
    else
        log_error "Node2 -> Node1 ping failed"
        all_passed=false
    fi

    # Test ping from node3 (PQC) to node2 (non-PQC)
    log_pqc "Testing: node3 (PQC=$NODE3_PQC) -> node2 (PQC=$NODE2_PQC)..."
    if timeout 10 sudo "$TAILSCALE_BIN" --socket="$NODE3_DIR/tailscaled.sock" ping --c 3 --timeout=5s "$node2_ip"; then
        log_success "Node3 -> Node2 connectivity verified"
    else
        log_error "Node3 -> Node2 ping failed"
        all_passed=false
    fi

    echo ""
    if [ "$all_passed" == "true" ]; then
        log_success "All connectivity tests passed! Mixed PQC/non-PQC communication works."
    else
        log_error "Some connectivity tests failed."
    fi
}

check_wireguard_config() {
    log_section "Checking WireGuard Configuration"

    for node_dir in "$NODE1_DIR" "$NODE2_DIR" "$NODE3_DIR"; do
        local node_name=$(basename "$node_dir")
        local pqc_config_file="$node_dir/pqc_enabled"
        local pqc_status="unknown"
        if [ -f "$pqc_config_file" ]; then
            pqc_status=$( [ "$(cat $pqc_config_file)" == "1" ] && echo "enabled" || echo "disabled" )
        fi

        log_info "Checking WireGuard config for $node_name (PQC: $pqc_status)..."

        # The tailscale status command might show peer information
        sudo "$TAILSCALE_BIN" --socket="$node_dir/tailscaled.sock" status --json > "$node_dir/status.json" 2>/dev/null || true

        if [ -f "$node_dir/status.json" ]; then
            log_success "$node_name: Status exported to $node_dir/status.json"

            # Check for PQCEnabled in peer status
            local pqc_peer_count=$(cat "$node_dir/status.json" | grep -c '"PQCEnabled":true' 2>/dev/null || echo "0")
            if [ "$pqc_peer_count" -gt "0" ]; then
                log_pqc "$node_name sees $pqc_peer_count peer(s) with PQC enabled"
            fi
        fi
    done
}

show_logs() {
    log_section "Recent Logs"

    log_info "Headscale PQC-related logs:"
    echo "---"
    grep -i "pqc" "$HEADSCALE_DIR/headscale.log" 2>/dev/null | tail -20 || echo "No PQC logs found"
    echo "---"

    for node_dir in "$NODE1_DIR" "$NODE2_DIR" "$NODE3_DIR"; do
        local node_name=$(basename "$node_dir")
        local pqc_config_file="$node_dir/pqc_enabled"
        local pqc_status="unknown"
        if [ -f "$pqc_config_file" ]; then
            pqc_status=$( [ "$(cat $pqc_config_file)" == "1" ] && echo "enabled" || echo "disabled" )
        fi

        log_info "$node_name PQC-related logs (PQC: $pqc_status):"
        echo "---"
        grep -i "pqc\|wgcfg.*seed\|TS_DISABLE" "$node_dir/tailscaled.log" 2>/dev/null | grep -v "RAW-STDERR" | tail -20 || echo "No PQC logs found"
        echo "---"
    done
}

print_config() {
    log_section "Test Configuration"
    log_info "Node1: PQC = $( [ "$NODE1_PQC" == "1" ] && echo "ENABLED" || echo "DISABLED" )"
    log_info "Node2: PQC = $( [ "$NODE2_PQC" == "1" ] && echo "ENABLED" || echo "DISABLED" )"
    log_info "Node3: PQC = $( [ "$NODE3_PQC" == "1" ] && echo "ENABLED" || echo "DISABLED" )"
    log_info ""
    log_info "To customize, set environment variables:"
    log_info "  NODE1_PQC=0|1 NODE2_PQC=0|1 NODE3_PQC=0|1 $0"
}

main() {
    log_section "Mixed PQC End-to-End Test Suite"
    log_info "Test directory: $TEST_DIR"

    # Print configuration
    print_config

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

    # Start Tailscale nodes with specific ports and PQC settings
    start_tailscale_node "node1" "$NODE1_DIR" testuser "$PREAUTH_KEY" 41651 "$NODE1_PQC"
    start_tailscale_node "node2" "$NODE2_DIR" testuser "$PREAUTH_KEY" 41652 "$NODE2_PQC"
    start_tailscale_node "node3" "$NODE3_DIR" testuser "$PREAUTH_KEY" 41653 "$NODE3_PQC"

    # Wait for nodes to settle and establish connections
    log_info "Waiting for nodes to establish connections..."
    sleep 10

    # Wait for all nodes to see each other
    log_info "Checking if all nodes can see their peers..."
    for i in {1..30}; do
        # Count online peers (grep -c returns 1 if count is 0, so we need || true then check result)
        local node1_peers=$(sudo "$TAILSCALE_BIN" --socket="$NODE1_DIR/tailscaled.sock" status --json 2>/dev/null | grep -c '"Online":true' || true)
        local node2_peers=$(sudo "$TAILSCALE_BIN" --socket="$NODE2_DIR/tailscaled.sock" status --json 2>/dev/null | grep -c '"Online":true' || true)
        local node3_peers=$(sudo "$TAILSCALE_BIN" --socket="$NODE3_DIR/tailscaled.sock" status --json 2>/dev/null | grep -c '"Online":true' || true)

        # Handle empty results (when grep finds nothing)
        node1_peers=${node1_peers:-0}
        node2_peers=${node2_peers:-0}
        node3_peers=${node3_peers:-0}

        if [ "$node1_peers" -ge "2" ] && [ "$node2_peers" -ge "2" ] && [ "$node3_peers" -ge "2" ]; then
            log_success "All nodes can see their peers"
            break
        fi

        if [ "$i" -eq 30 ]; then
            log_warn "Not all nodes can see their peers yet (node1: $node1_peers, node2: $node2_peers, node3: $node3_peers)"
        fi

        sleep 2
    done

    # Verify PQC keys were generated appropriately
    verify_pqc_keys

    # Test connectivity
    test_connectivity

    # Check WireGuard configuration
    check_wireguard_config

    # Show logs
    show_logs

    log_section "Test Summary"
    log_success "Mixed PQC end-to-end test complete!"
    log_info ""
    log_pqc "Configuration tested:"
    log_info "  - Node1: PQC $( [ "$NODE1_PQC" == "1" ] && echo "enabled" || echo "disabled" )"
    log_info "  - Node2: PQC $( [ "$NODE2_PQC" == "1" ] && echo "enabled" || echo "disabled" )"
    log_info "  - Node3: PQC $( [ "$NODE3_PQC" == "1" ] && echo "enabled" || echo "disabled" )"
    log_info ""
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
