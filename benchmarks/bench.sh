#!/bin/bash
# bench.sh — Point d'entrée unique pour le benchmark IoT Security
set -euo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$BENCH_DIR/.." && pwd)"
SCENARIOS_DIR="$BENCH_DIR/scenarios"
ANSIBLE_DIR="$BENCH_DIR/ansible"
RESULTS_DIR="$BENCH_DIR/results"
SCRIPTS_DIR="$BENCH_DIR/scripts"

# Charger .env si présent
if [[ -f "$PROJECT_DIR/.env" ]]; then
    set -a; source "$PROJECT_DIR/.env"; set +a
fi

# --- Helpers ---

find_scenario() {
    local id="$1"
    local found
    # Chercher un dossier s01_* dans scenarios/
    found=$(ls -d "$SCENARIOS_DIR"/${id}*/ 2>/dev/null | head -1)
    if [[ -z "$found" ]]; then
        echo "[!] Scenario '$id' not found in $SCENARIOS_DIR/" >&2
        exit 1
    fi
    echo "$found"
}

pvm() {
    python3 "$SCRIPTS_DIR/proxmox_vms.py" --bench-dir "$BENCH_DIR" "$@"
}

# --- Commands ---

usage() {
    cat << 'EOF'
Usage: bench.sh <command> [args]

Commands:
  setup              Create VM templates on Proxmox
  deploy <id>        Deploy a scenario (create VMs + inject vulns)
  reset <id>         Restore VMs to clean snapshot
  run <id> [opts]    Run LLM benchmark on deployed scenario
  teardown <id>      Destroy all VMs for a scenario
  list               List available scenarios
  status <id>        Show VM status for a scenario

Options for 'run':
  --model <m>        LLM model (default: claude-sonnet-4-20250514)
  --provider <p>     LLM provider (default: anthropic)
  --runs <n>         Number of runs (default: 3)

Examples:
  ./bench.sh setup
  ./bench.sh deploy s01
  ./bench.sh run s01 --model claude-sonnet-4-20250514
  ./bench.sh reset s01
  ./bench.sh teardown s01
EOF
}

cmd_setup() {
    echo "[*] Installing Ansible collections..."
    ansible-galaxy collection install community.general

    echo "[*] Uploading cloud-init snippet to Proxmox..."
    local proxmox_host
    proxmox_host=$(python3 -c "import yaml; print(yaml.safe_load(open('$BENCH_DIR/config.yml'))['proxmox']['host'])")

    ssh "root@$proxmox_host" "mkdir -p /var/lib/vz/snippets"
    cat << 'CLOUDINIT' | ssh "root@$proxmox_host" "cat > /var/lib/vz/snippets/userconfig.yml"
#cloud-config
ssh_pwauth: true
chpasswd:
  expire: false
package_update: true
packages:
  - python3
  - qemu-guest-agent
runcmd:
  - systemctl enable qemu-guest-agent
  - systemctl start qemu-guest-agent
CLOUDINIT

    echo "[*] Creating Debian template (ID 9000)..."
    ssh "root@$proxmox_host" bash << 'TEMPLATE'
if qm status 9000 &>/dev/null; then
    echo "  Template 9000 already exists, skipping."
    exit 0
fi
wget -q https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2 -O /tmp/debian-12-cloud.qcow2
qm create 9000 --name tpl-debian --memory 512 --cores 1 \
  --net0 virtio,bridge=vmbr0 --scsihw virtio-scsi-pci
qm set 9000 --scsi0 local-lvm:0,import-from=/tmp/debian-12-cloud.qcow2
qm set 9000 --ide2 local-lvm:cloudinit
qm set 9000 --boot order=scsi0
qm set 9000 --serial0 socket --vga serial0
qm set 9000 --agent enabled=1
qm template 9000
rm -f /tmp/debian-12-cloud.qcow2
echo "  Template 9000 created."
TEMPLATE

    echo "[+] Setup complete."
}

cmd_deploy() {
    local scenario_id="$1"
    local scenario_dir
    scenario_dir=$(find_scenario "$scenario_id")

    echo "[*] Deploying: $(basename "$scenario_dir")"

    # 1. Create VMs
    echo "[1/5] Creating VMs..."
    pvm create "$scenario_dir"

    # 2. Start VMs
    echo "[2/5] Starting VMs..."
    pvm start "$scenario_dir"

    # 3. Wait for boot
    echo "[3/5] Waiting for VMs to boot (60s)..."
    sleep 60

    # 4. Inject vulnerabilities
    echo "[4/5] Injecting vulnerabilities..."
    local inv_file="$ANSIBLE_DIR/.inventory_tmp.ini"
    pvm inventory "$scenario_dir" > "$inv_file"

    ANSIBLE_CONFIG="$ANSIBLE_DIR/ansible.cfg" \
    ansible-playbook "$ANSIBLE_DIR/playbooks/inject_vulns.yml" -i "$inv_file"

    rm -f "$inv_file"

    # 5. Snapshot
    echo "[5/5] Creating clean snapshots..."
    pvm snapshot "$scenario_dir"

    echo "[+] Scenario $scenario_id deployed."
    echo "    Run:      ./bench.sh run $scenario_id"
    echo "    Status:   ./bench.sh status $scenario_id"
}

cmd_reset() {
    local scenario_id="$1"
    local scenario_dir
    scenario_dir=$(find_scenario "$scenario_id")

    echo "[*] Restoring snapshot for $scenario_id..."
    pvm rollback "$scenario_dir"
    echo "[+] Scenario $scenario_id restored."
}

cmd_run() {
    local scenario_id="$1"
    shift
    local model="claude-sonnet-4-20250514"
    local provider="anthropic"
    local runs=3

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --model)    model="$2"; shift 2 ;;
            --provider) provider="$2"; shift 2 ;;
            --runs)     runs="$2"; shift 2 ;;
            *)          echo "Unknown option: $1"; exit 1 ;;
        esac
    done

    local scenario_dir
    scenario_dir=$(find_scenario "$scenario_id")
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)
    local model_safe="${model//\//_}"
    local run_dir="$RESULTS_DIR/${scenario_id}/${model_safe}/$timestamp"
    mkdir -p "$run_dir"

    # Save run metadata
    cat > "$run_dir/meta.yml" << RUNMETA
scenario: $scenario_id
model: $model
provider: $provider
runs: $runs
timestamp: $timestamp
RUNMETA

    echo "[*] Benchmark: scenario=$scenario_id model=$model runs=$runs"
    echo "[*] Results dir: $run_dir"

    for i in $(seq 1 "$runs"); do
        echo ""
        echo "=== Run $i/$runs ==="

        if [[ $i -gt 1 ]]; then
            cmd_reset "$scenario_id"
            echo "[*] Waiting for VMs to reboot (30s)..."
            sleep 30
        fi

        cd "$PROJECT_DIR"
        python3 -m src.agent \
            --provider "$provider" \
            --model "$model" \
            2>&1 | tee "$run_dir/run_${i}.log" || true
        cd "$BENCH_DIR"

        local latest_output
        latest_output=$(ls -td "$PROJECT_DIR/output/agent/"*/ 2>/dev/null | head -1)
        if [[ -n "$latest_output" ]]; then
            cp -r "$latest_output" "$run_dir/run_${i}_output/"
        fi
    done

    # Evaluate
    echo ""
    echo "[*] Evaluating results..."
    local gt_file="$scenario_dir/scenario.yml"
    cd "$PROJECT_DIR"
    python3 -m src.benchmark.evaluator \
        --results-dir "$run_dir" \
        --ground-truth "$gt_file" \
        --output "$run_dir/evaluation.json" 2>/dev/null \
        || echo "[!] Evaluator not yet implemented"
    cd "$BENCH_DIR"

    echo "[+] Results saved to: $run_dir/"
}

cmd_teardown() {
    local scenario_id="$1"
    local scenario_dir
    scenario_dir=$(find_scenario "$scenario_id")

    echo "[*] Destroying scenario $scenario_id..."
    pvm destroy "$scenario_dir"
    echo "[+] Scenario $scenario_id destroyed."
}

cmd_list() {
    echo "Available scenarios:"
    echo ""
    pvm list "$SCENARIOS_DIR"
}

cmd_status() {
    local scenario_id="$1"
    local scenario_dir
    scenario_dir=$(find_scenario "$scenario_id")

    echo "VMs for scenario $scenario_id:"
    pvm status "$scenario_dir"
}

# --- Main ---
case "${1:-}" in
    setup)     cmd_setup ;;
    deploy)    cmd_deploy "${2:?Scenario ID required}" ;;
    reset)     cmd_reset "${2:?Scenario ID required}" ;;
    run)       cmd_run "${2:?Scenario ID required}" "${@:3}" ;;
    teardown)  cmd_teardown "${2:?Scenario ID required}" ;;
    list)      cmd_list ;;
    status)    cmd_status "${2:?Scenario ID required}" ;;
    *)         usage ;;
esac
