"""Interactive terminal interface for baseline benchmark runs."""
from __future__ import annotations

import getpass
import os
from dataclasses import dataclass
from pathlib import Path

from src.baselines import compare, deploy, install_tools, runner
from src.baselines.scenarios import list_ground_truth_scenarios


DEFAULT_BASELINE_HOST = "root@192.168.88.36"
DEFAULT_SCENARIO = "3"
DEFAULT_SCOPE = "192.168.100.0/24"
DEFAULT_MODEL = install_tools.DEFAULT_MODEL
SUPPORTED_TOOLS = ("cai", "pentgpt", "vulnbot")


@dataclass
class WizardState:
    baseline_host: str = DEFAULT_BASELINE_HOST
    tool: str = "cai"
    scenario_id: str = DEFAULT_SCENARIO
    scope: str = DEFAULT_SCOPE
    model: str = DEFAULT_MODEL
    max_turns: int = 40
    last_run_dir: Path | None = None
    last_suite_dir: Path | None = None


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [current: {default}; Enter = keep]" if default else ""
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
    print(f"Tool          : {state.tool}")
    print(f"Scenario      : {state.scenario_id}")
    print(f"Scope         : {state.scope}")
    print(f"Model         : {state.model}")
    print(f"Max turns     : {state.max_turns}")
    print(f"Last run      : {state.last_run_dir or '-'}")
    print(f"Last suite    : {state.last_suite_dir or '-'}")
    print("-" * 72)


def _configure(state: WizardState) -> None:
    state.baseline_host = _ask("Baseline SSH host", state.baseline_host)
    tool = _ask("Tool (cai/pentgpt/vulnbot)", state.tool).lower()
    if tool in SUPPORTED_TOOLS:
        state.tool = tool
    else:
        print(f"Unknown tool {tool!r}; keeping {state.tool}.")
    state.scenario_id = _ask("Scenario id", state.scenario_id)
    state.scope = _ask("CIDR scope", state.scope)
    state.model = _ask("Model", state.model)
    raw_turns = _ask("Max turns per target", str(state.max_turns))
    try:
        state.max_turns = int(raw_turns)
    except ValueError:
        print("Invalid max turns, keeping previous value.")


def _change_scenario(state: WizardState) -> None:
    scenarios = list_ground_truth_scenarios()
    if scenarios:
        print("Available scenarios: " + ", ".join(f"S{sid}" for sid in scenarios))
    state.scenario_id = _ask("Scenario id", state.scenario_id)
    state.last_run_dir = None
    state.last_suite_dir = None
    print(f"Scenario set to S{state.scenario_id}.")


def _switch_scenario(state: WizardState) -> None:
    current = state.scenario_id
    scenarios = list_ground_truth_scenarios()
    if scenarios:
        print("Available scenarios: " + ", ".join(f"S{sid}" for sid in scenarios))
    next_scenario = _ask("Next scenario id", current)
    populate = _ask_yes_no("Populate services after vulnerability injection?", True)
    verify = _ask_yes_no("Run verification playbook after deployment?", True)
    if not _ask_yes_no(f"Teardown S{current}, then deploy/inject S{next_scenario}?", False):
        print("Switch cancelled.")
        return

    labels = {
        "teardown": "Teardown",
        "deploy": "Clone/deploy VMs",
        "inject": "Inject vulnerabilities",
        "populate": "Populate services",
        "verify": "Verify vulnerabilities",
    }

    def on_event(event: dict) -> None:
        name = event["event"]
        step = event.get("step")
        scenario_id = event.get("scenario_id")
        if name == "switch_start":
            print(f"Switching S{event['current_scenario_id']} -> S{event['next_scenario_id']}")
        elif name == "switch_step_start":
            print(f"{labels.get(step, step)} for S{scenario_id}...")
        elif name == "switch_step_done":
            print(f"{labels.get(step, step)} done for S{scenario_id}.")
        elif name == "switch_done":
            print(f"Scenario S{event['next_scenario_id']} is deployed, injected and ready.")

    deploy.switch_scenario(
        current_scenario_id=current,
        next_scenario_id=next_scenario,
        populate=populate,
        verify=verify,
        event_callback=on_event,
    )
    state.scenario_id = next_scenario
    state.last_run_dir = None
    state.last_suite_dir = None


def _setup_baseline_tools(state: WizardState) -> None:
    api_key = os.environ.get(install_tools.DEFAULT_API_KEY_ENV)
    if not api_key:
        print(f"{install_tools.DEFAULT_API_KEY_ENV} is not set locally.")
        api_key = getpass.getpass("Paste MiniMax API key (hidden): ").strip()
    if not api_key:
        print("No API key provided; setup cancelled.")
        return
    install_tools.setup_baseline_adapters(
        baseline_host=state.baseline_host,
        api_key=api_key,
        model=state.model,
    )
    print("Baseline tools setup completed.")


def _deploy_scenario(state: WizardState) -> None:
    populate = _ask_yes_no("Populate services after vulnerability injection?", True)
    verify = _ask_yes_no("Run verification playbook after deployment?", True)
    deploy.deploy_scenario(state.scenario_id, populate=populate, verify=verify)
    print(f"Scenario {state.scenario_id} deployed, injected and ready.")


def _inject_vulnerabilities(state: WizardState) -> None:
    populate = _ask_yes_no("Populate services after injection?", True)
    verify = _ask_yes_no("Verify vulnerabilities after injection?", True)
    deploy.inject_vulnerabilities(state.scenario_id)
    if populate:
        deploy.populate_services(state.scenario_id)
    if verify:
        deploy.verify_scenario(state.scenario_id)
    print(f"Scenario {state.scenario_id} is ready.")


def _reset_scenario(state: WizardState) -> None:
    verify = _ask_yes_no("Verify after reset?", True)
    deploy.reset_scenario(state.scenario_id)
    if verify:
        deploy.verify_scenario(state.scenario_id)
    print(f"Scenario {state.scenario_id} reset to vulnerable state.")


def _run_selected_tool(state: WizardState) -> None:
    state.last_run_dir = runner.run_baseline(
        tool=state.tool,
        scenario_id=state.scenario_id,
        baseline_host=state.baseline_host,
        variant="A",
        scope=state.scope,
        max_turns=state.max_turns,
        model=state.model,
    )
    print(f"Run completed: {state.last_run_dir}")


def _run_suite(state: WizardState) -> None:
    state.last_suite_dir = runner.run_suite(
        scenario_id=state.scenario_id,
        baseline_host=state.baseline_host,
        variant="A",
        scope=state.scope,
        max_turns=state.max_turns,
        model=state.model,
    )
    print(f"Suite completed: {state.last_suite_dir}")


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
    if _ask_yes_no("Install/update baseline adapters first?", False):
        _setup_baseline_tools(state)
    _run_selected_tool(state)
    _compare(state)


def run_wizard() -> None:
    state = WizardState()
    while True:
        _print_header(state)
        print("1. Configure")
        print("s. Change scenario")
        print("x. Teardown current and deploy another scenario")
        print("2. Deploy baseline VM")
        print("3. Setup baseline tools on baseline VM")
        print("4. Deploy full scenario (deploy + inject + populate + verify)")
        print("5. Run selected baseline")
        print("6. Run CAI + PentestGPT + VulnBot suite")
        print("7. Compare last/run directory")
        print("i. Inject/populate/verify vulnerabilities")
        print("r. Reset scenario to vulnerable state")
        print("8. Full selected-tool pilot (deploy scenario -> run selected tool -> compare)")
        print("9. Teardown benchmark scenario")
        print("0. Quit")
        choice = input("\nChoice: ").strip()
        try:
            if choice == "1":
                _configure(state)
            elif choice == "s":
                _change_scenario(state)
            elif choice == "x":
                _switch_scenario(state)
            elif choice == "2":
                deploy.deploy_baseline_vm()
            elif choice == "3":
                _setup_baseline_tools(state)
            elif choice == "4":
                _deploy_scenario(state)
            elif choice == "5":
                _run_selected_tool(state)
            elif choice == "6":
                _run_suite(state)
            elif choice == "7":
                _compare(state)
            elif choice == "i":
                _inject_vulnerabilities(state)
            elif choice == "r":
                _reset_scenario(state)
            elif choice == "8":
                _full_pilot(state)
            elif choice == "9":
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
