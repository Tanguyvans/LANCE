"""Interactive terminal interface for baseline benchmark runs."""
from __future__ import annotations

import getpass
import os
from dataclasses import dataclass
from pathlib import Path

from src.baselines import compare, deploy, install_tools, runner


DEFAULT_BASELINE_HOST = "root@192.168.88.36"
DEFAULT_SCENARIO = "3"
DEFAULT_SCOPE = "192.168.100.0/24"
DEFAULT_MODEL = install_tools.DEFAULT_MODEL


@dataclass
class WizardState:
    baseline_host: str = DEFAULT_BASELINE_HOST
    scenario_id: str = DEFAULT_SCENARIO
    scope: str = DEFAULT_SCOPE
    model: str = DEFAULT_MODEL
    max_turns: int = 40
    last_run_dir: Path | None = None


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")


def _ask_yes_no(prompt: str, default: bool = True) -> bool:
    label = "Y/n" if default else "y/N"
    value = input(f"{prompt} [{label}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "o", "oui"}


def _pause() -> None:
    input("\nPress Enter to continue...")


def _print_header(state: WizardState) -> None:
    print("\n" + "=" * 72)
    print("NATO Smart City IoT - Baseline Terminal")
    print("=" * 72)
    print(f"Baseline host : {state.baseline_host}")
    print(f"Scenario      : {state.scenario_id}")
    print(f"Scope         : {state.scope}")
    print(f"Model         : {state.model}")
    print(f"Max turns     : {state.max_turns}")
    print(f"Last run      : {state.last_run_dir or '-'}")
    print("-" * 72)


def _configure(state: WizardState) -> None:
    state.baseline_host = _ask("Baseline SSH host", state.baseline_host)
    state.scenario_id = _ask("Scenario id", state.scenario_id)
    state.scope = _ask("CIDR scope", state.scope)
    state.model = _ask("Model", state.model)
    raw_turns = _ask("Max turns per target", str(state.max_turns))
    try:
        state.max_turns = int(raw_turns)
    except ValueError:
        print("Invalid max turns, keeping previous value.")


def _setup_cai(state: WizardState) -> None:
    api_key = os.environ.get(install_tools.DEFAULT_API_KEY_ENV)
    if not api_key:
        print(f"{install_tools.DEFAULT_API_KEY_ENV} is not set locally.")
        api_key = getpass.getpass("Paste MiniMax API key (hidden): ").strip()
    if not api_key:
        print("No API key provided; setup cancelled.")
        return
    install_tools.setup_cai(
        baseline_host=state.baseline_host,
        api_key=api_key,
        model=state.model,
    )
    print("CAI setup completed.")


def _deploy_scenario(state: WizardState) -> None:
    populate = _ask_yes_no("Populate services after vulnerability injection?", True)
    verify = _ask_yes_no("Run verification playbook after deployment?", False)
    deploy.deploy_scenario(state.scenario_id, populate=populate, verify=verify)
    print(f"Scenario {state.scenario_id} deployed.")


def _run_cai(state: WizardState) -> None:
    state.last_run_dir = runner.run_baseline(
        tool="cai",
        scenario_id=state.scenario_id,
        baseline_host=state.baseline_host,
        variant="A",
        scope=state.scope,
        max_turns=state.max_turns,
        model=state.model,
    )
    print(f"Run completed: {state.last_run_dir}")


def _compare(state: WizardState) -> None:
    run_dir = Path(_ask("Run directory", str(state.last_run_dir or "")))
    if not run_dir:
        print("No run directory selected.")
        return
    result = compare.evaluate_baseline_run(run_dir)
    print(
        f"S{result['scenario_id']} recall={result['recall']:.3f} "
        f"precision={result['precision']:.3f} f1={result['f1_score']:.3f} "
        f"score={result['score_pct']:.1f}%"
    )


def _full_pilot(state: WizardState) -> None:
    if _ask_yes_no(f"Deploy scenario {state.scenario_id} first?", True):
        _deploy_scenario(state)
    if _ask_yes_no("Install/update CAI adapter first?", False):
        _setup_cai(state)
    _run_cai(state)
    _compare(state)


def run_wizard() -> None:
    state = WizardState()
    while True:
        _print_header(state)
        print("1. Configure")
        print("2. Deploy baseline VM")
        print("3. Setup CAI on baseline VM")
        print("4. Deploy benchmark scenario")
        print("5. Run CAI baseline")
        print("6. Compare last/run directory")
        print("7. Full CAI pilot (deploy scenario -> run CAI -> compare)")
        print("8. Teardown benchmark scenario")
        print("0. Quit")
        choice = input("\nChoice: ").strip()
        try:
            if choice == "1":
                _configure(state)
            elif choice == "2":
                deploy.deploy_baseline_vm()
            elif choice == "3":
                _setup_cai(state)
            elif choice == "4":
                _deploy_scenario(state)
            elif choice == "5":
                _run_cai(state)
            elif choice == "6":
                _compare(state)
            elif choice == "7":
                _full_pilot(state)
            elif choice == "8":
                deploy.teardown_scenario(state.scenario_id)
            elif choice == "0":
                return
            else:
                print("Unknown choice.")
        except KeyboardInterrupt:
            print("\nInterrupted.")
        except Exception as exc:
            print(f"\nError: {exc}")
        _pause()


if __name__ == "__main__":
    run_wizard()
