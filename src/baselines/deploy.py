"""Deployment helpers for the isolated baseline VM."""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


DEFAULT_INVENTORY = Path("benchmarks/ansible/inventory.yml")
DEFAULT_PLAYBOOK = Path("benchmarks/ansible/playbooks/deploy_baseline_vm.yml")
DEFAULT_VAULT_PASSWORD = Path.home() / ".vault_pass"


def deploy_baseline_vm(
    inventory: Path = DEFAULT_INVENTORY,
    playbook: Path = DEFAULT_PLAYBOOK,
    vault_password_file: Path = DEFAULT_VAULT_PASSWORD,
    check: bool = False,
    extra_vars: list[str] | None = None,
) -> None:
    """Run the Ansible playbook that provisions the isolated baseline VM."""
    cmd = [
        "ansible-playbook",
        str(playbook),
        "-i",
        str(inventory),
        "--vault-password-file",
        str(vault_password_file),
    ]
    if check:
        cmd.append("--check")
    for item in extra_vars or []:
        cmd.extend(["--extra-vars", item])
    subprocess.run(cmd, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy the isolated baseline VM with Ansible")
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--playbook", type=Path, default=DEFAULT_PLAYBOOK)
    parser.add_argument("--vault-password-file", type=Path, default=DEFAULT_VAULT_PASSWORD)
    parser.add_argument("--check", action="store_true", help="Run Ansible in check mode")
    parser.add_argument(
        "--extra-vars",
        action="append",
        default=[],
        help='Extra vars passed to Ansible, e.g. --extra-vars "baseline_memory=4096"',
    )
    args = parser.parse_args()

    deploy_baseline_vm(
        inventory=args.inventory,
        playbook=args.playbook,
        vault_password_file=args.vault_password_file,
        check=args.check,
        extra_vars=args.extra_vars,
    )


if __name__ == "__main__":
    main()

