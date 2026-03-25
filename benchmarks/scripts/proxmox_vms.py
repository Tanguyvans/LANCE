#!/usr/bin/env python3
"""Manage Proxmox VMs for benchmark scenarios."""

import argparse
import glob
import os
import subprocess
import sys

import yaml


def ssh_cmd(host: str, cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command on Proxmox via SSH."""
    return subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", f"root@{host}", cmd],
        capture_output=True, text=True, check=check,
    )


def load_yaml(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def load_config(bench_dir: str) -> dict:
    """Load config.yml with defaults."""
    config_path = os.path.join(bench_dir, "config.yml")
    if os.path.exists(config_path):
        return load_yaml(config_path)
    return {
        "proxmox": {"host": "192.168.1.100", "node": "benchmark", "template_id": 9000},
        "vm_defaults": {"user": "bench", "password": "benchpass", "gateway": "192.168.1.1"},
    }


def find_scenario(scenario_path: str) -> dict:
    """Load scenario from file or directory."""
    if os.path.isdir(scenario_path):
        scenario_path = os.path.join(scenario_path, "scenario.yml")
    return load_yaml(scenario_path)


def get_gateway(scenario: dict, config: dict) -> str:
    """Get gateway from scenario networks or config defaults."""
    for net_conf in scenario.get("networks", {}).values():
        if "gateway" in net_conf:
            return net_conf["gateway"]
    return config["vm_defaults"]["gateway"]


def cmd_create(args, config):
    """Clone VMs from template and configure cloud-init."""
    scenario = find_scenario(args.scenario)
    host = config["proxmox"]["host"]
    password = config["vm_defaults"]["password"]
    gateway = get_gateway(scenario, config)

    tpl_map = {
        "tpl-debian": str(config["proxmox"]["template_id"]),
        "tpl-mikrotik": "9001",
        "tpl-openwrt": "9002",
    }

    for name, vm in scenario.get("vms", {}).items():
        vmid = vm["vmid_offset"]

        result = ssh_cmd(host, f"qm status {vmid}", check=False)
        if result.returncode == 0:
            print(f"  VM {vmid} ({name}) already exists, skipping.")
            continue

        tpl_id = tpl_map.get(vm.get("template", "tpl-debian"), str(config["proxmox"]["template_id"]))

        dns_name = name.replace("_", "-")
        print(f"  Creating VM {vmid} ({name})...")
        cmds = [
            f"qm clone {tpl_id} {vmid} --name bench-{dns_name} --full",
            f"qm set {vmid} --cores {vm.get('cores', 1)} --memory {vm.get('memory', 512)}",
            f"qm set {vmid} --ciuser {config['vm_defaults']['user']} --cipassword {password}",
            f'qm set {vmid} --cicustom "user=local:snippets/userconfig.yml"',
        ]

        for idx, nic in enumerate(vm.get("networks", [])):
            bridge = nic.get("bridge", "vmbr0")
            tag = nic.get("vlan", "")
            tag_opt = f",tag={tag}" if tag else ""
            cmds.append(f"qm set {vmid} --net{idx} virtio,bridge={bridge}{tag_opt}")

        ip = vm.get("ip", "")
        if ip:
            cmds.append(f"qm set {vmid} --ipconfig0 ip={ip}/24,gw={gateway}")

        for cmd in cmds:
            ssh_cmd(host, cmd)

    print("  VMs created.")


def cmd_start(args, config):
    scenario = find_scenario(args.scenario)
    host = config["proxmox"]["host"]
    for name, vm in scenario.get("vms", {}).items():
        vmid = vm["vmid_offset"]
        print(f"  Starting VM {vmid} ({name})...")
        ssh_cmd(host, f"qm start {vmid}")


def cmd_snapshot(args, config):
    scenario = find_scenario(args.scenario)
    host = config["proxmox"]["host"]
    for name, vm in scenario.get("vms", {}).items():
        vmid = vm["vmid_offset"]
        print(f"  Snapshot VM {vmid} ({name})...")
        ssh_cmd(host, f'qm snapshot {vmid} clean --description "Initial state with vulns"')


def cmd_rollback(args, config):
    scenario = find_scenario(args.scenario)
    host = config["proxmox"]["host"]
    for name, vm in scenario.get("vms", {}).items():
        vmid = vm["vmid_offset"]
        print(f"  Restoring VM {vmid} ({name})...")
        ssh_cmd(host, f"qm rollback {vmid} clean --start")


def cmd_destroy(args, config):
    scenario = find_scenario(args.scenario)
    host = config["proxmox"]["host"]
    for name, vm in scenario.get("vms", {}).items():
        vmid = vm["vmid_offset"]
        print(f"  Destroying VM {vmid} ({name})...")
        ssh_cmd(host, f"qm stop {vmid}", check=False)
        ssh_cmd(host, f"qm destroy {vmid} --purge")


def cmd_status(args, config):
    scenario = find_scenario(args.scenario)
    host = config["proxmox"]["host"]
    print(f"  {'Name':20s} {'VMID':>6s} {'IP':>18s} {'Status':>10s}")
    print(f"  {'----':20s} {'----':>6s} {'--':>18s} {'------':>10s}")
    for name, vm in scenario.get("vms", {}).items():
        vmid = vm["vmid_offset"]
        ip = vm.get("ip", "N/A")
        result = ssh_cmd(host, f"qm status {vmid}", check=False)
        status = result.stdout.strip().split(":")[-1].strip() if result.returncode == 0 else "not found"
        print(f"  {name:20s} {vmid:6d} {ip:>18s} {status:>10s}")


def cmd_inventory(args, config):
    """Generate Ansible inventory from scenario."""
    scenario = find_scenario(args.scenario)
    password = config["vm_defaults"]["password"]
    user = config["vm_defaults"]["user"]

    print("[all]")
    for name, vm in scenario.get("vms", {}).items():
        ip = vm.get("ip", "")
        if not ip or "mikrotik" in vm.get("template", ""):
            continue
        vuln_roles = " ".join(vm.get("vuln_roles", []))
        print(
            f'{ip} vm_name={name} vuln_roles="{vuln_roles}" '
            f"ansible_user={user} ansible_password={password}"
        )
    print()
    print("[all:vars]")
    print("ansible_python_interpreter=/usr/bin/python3")


def cmd_list(args, _config):
    """List scenarios from a directory."""
    scenarios_dir = args.scenarios_dir
    print(f"  {'ID':8s} {'Name':40s} {'Difficulty':12s} {'Packs'}")
    print(f"  {'---':8s} {'----':40s} {'----------':12s} {'-----'}")

    for d in sorted(glob.glob(os.path.join(scenarios_dir, "s*"))):
        scenario_file = os.path.join(d, "scenario.yml") if os.path.isdir(d) else d
        if not os.path.exists(scenario_file):
            continue
        s = load_yaml(scenario_file)
        meta = s["meta"]
        vulns = len(s.get("ground_truth", {}).get("vulnerabilities", []))
        paths = len(s.get("ground_truth", {}).get("attack_paths", []))
        print(
            f"  {meta['id']:8s} {meta['name']:40s} "
            f"{meta['difficulty']:12s} {','.join(meta['packs']):12s} "
            f"{vulns}V {paths}P"
        )


def main():
    parser = argparse.ArgumentParser(description="Proxmox VM manager for benchmarks")
    parser.add_argument("--bench-dir", default=os.path.join(os.path.dirname(__file__), ".."),
                        help="Path to benchmarks/ directory")

    sub = parser.add_subparsers(dest="command", required=True)

    for cmd_name in ["create", "start", "snapshot", "rollback", "destroy", "status", "inventory"]:
        p = sub.add_parser(cmd_name)
        p.add_argument("scenario", help="Path to scenario directory or YAML file")

    p_list = sub.add_parser("list")
    p_list.add_argument("scenarios_dir", help="Path to scenarios directory")

    args = parser.parse_args()
    config = load_config(os.path.abspath(args.bench_dir))

    commands = {
        "create": cmd_create,
        "start": cmd_start,
        "snapshot": cmd_snapshot,
        "rollback": cmd_rollback,
        "destroy": cmd_destroy,
        "status": cmd_status,
        "inventory": cmd_inventory,
        "list": cmd_list,
    }
    commands[args.command](args, config)


if __name__ == "__main__":
    main()
