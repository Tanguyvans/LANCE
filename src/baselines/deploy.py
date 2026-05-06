"""Deployment helpers for the isolated baseline VM."""
from __future__ import annotations

import argparse
import subprocess
from pathlib import Path


DEFAULT_INVENTORY = Path("benchmarks/ansible/inventory.yml")
DEFAULT_PLAYBOOK = Path("benchmarks/ansible/playbooks/deploy_baseline_vm.yml")
DEFAULT_VAULT_PASSWORD = Path.home() / ".vault_pass"
PLAYBOOK_DIR = Path("benchmarks/ansible/playbooks")


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


def run_playbook(
    playbook: Path,
    inventory: Path = DEFAULT_INVENTORY,
    vault_password_file: Path = DEFAULT_VAULT_PASSWORD,
    extra_vars: list[str] | None = None,
    check: bool = False,
) -> None:
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


def deploy_scenario(
    scenario_id: str,
    inventory: Path = DEFAULT_INVENTORY,
    vault_password_file: Path = DEFAULT_VAULT_PASSWORD,
    populate: bool = True,
    verify: bool = False,
) -> None:
    """Deploy a benchmark scenario and inject its vulnerabilities."""
    extra_vars = [f"scenario_id={scenario_id}"]
    run_playbook(PLAYBOOK_DIR / "03_deploy_scenario.yml", inventory, vault_password_file, extra_vars)
    run_playbook(PLAYBOOK_DIR / "04_inject_vulns.yml", inventory, vault_password_file, extra_vars)
    if populate:
        run_playbook(PLAYBOOK_DIR / "05_populate_services.yml", inventory, vault_password_file, extra_vars)
    if verify:
        run_playbook(PLAYBOOK_DIR / "06_verify.yml", inventory, vault_password_file, extra_vars)


def inject_vulnerabilities(
    scenario_id: str,
    inventory: Path = DEFAULT_INVENTORY,
    vault_password_file: Path = DEFAULT_VAULT_PASSWORD,
) -> None:
    """Inject vulnerabilities into an already deployed benchmark scenario."""
    run_playbook(
        PLAYBOOK_DIR / "04_inject_vulns.yml",
        inventory=inventory,
        vault_password_file=vault_password_file,
        extra_vars=[f"scenario_id={scenario_id}"],
    )


def populate_services(
    scenario_id: str,
    inventory: Path = DEFAULT_INVENTORY,
    vault_password_file: Path = DEFAULT_VAULT_PASSWORD,
) -> None:
    """Populate benchmark services after vulnerability injection."""
    run_playbook(
        PLAYBOOK_DIR / "05_populate_services.yml",
        inventory=inventory,
        vault_password_file=vault_password_file,
        extra_vars=[f"scenario_id={scenario_id}"],
    )


def verify_scenario(
    scenario_id: str,
    inventory: Path = DEFAULT_INVENTORY,
    vault_password_file: Path = DEFAULT_VAULT_PASSWORD,
) -> None:
    """Verify that the expected vulnerabilities are present."""
    run_playbook(
        PLAYBOOK_DIR / "06_verify.yml",
        inventory=inventory,
        vault_password_file=vault_password_file,
        extra_vars=[f"scenario_id={scenario_id}"],
    )


def reset_scenario(
    scenario_id: str,
    inventory: Path = DEFAULT_INVENTORY,
    vault_password_file: Path = DEFAULT_VAULT_PASSWORD,
) -> None:
    """Reset a deployed scenario back to the vulnerable benchmark state."""
    run_playbook(
        PLAYBOOK_DIR / "08_reset_scenario.yml",
        inventory=inventory,
        vault_password_file=vault_password_file,
        extra_vars=[f"scenario_id={scenario_id}"],
    )


def teardown_scenario(
    scenario_id: str,
    inventory: Path = DEFAULT_INVENTORY,
    vault_password_file: Path = DEFAULT_VAULT_PASSWORD,
) -> None:
    run_playbook(
        PLAYBOOK_DIR / "99_teardown.yml",
        inventory=inventory,
        vault_password_file=vault_password_file,
        extra_vars=[f"scenario_id={scenario_id}"],
    )


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
