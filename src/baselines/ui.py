"""Rich terminal dashboard for baseline runs."""
from __future__ import annotations

import getpass
import os
import subprocess
import sys
import termios
import time
import tty
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.baselines import compare, deploy, external_benchmarks, install_tools, runner
from src.baselines.scenarios import list_ground_truth_scenarios

try:
    from rich.align import Align
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
except ImportError:  # pragma: no cover
    Console = None  # type: ignore


DEFAULT_BASELINE_HOST = "root@192.168.88.36"
DEFAULT_SCENARIO = "3"
DEFAULT_SCOPE = "192.168.100.0/24"
DEFAULT_MODEL = install_tools.DEFAULT_MODEL
SUPPORTED_TOOLS = ("cai", "pentgpt", "vulnbot")
EXTERNAL_REPOS = {
    "vulhub": ("https://github.com/vulhub/vulhub", "../vulhub"),
    "autopenbench": ("https://github.com/lucagioacchini/auto-pen-bench", "../auto-pen-bench"),
    "xbow": ("", "../validation-benchmarks"),
    "ai-pentest": ("", "../ai-pentest-benchmark"),
}
MENU_ACTIONS = [
    ("1", "Configure"),
    ("s", "Change scenario"),
    ("x", "Teardown current and deploy another scenario"),
    ("2", "Deploy baseline VM"),
    ("3", "Setup baseline tools on baseline VM"),
    ("4", "Deploy full scenario (deploy + inject + populate + verify)"),
    ("5", "Run selected baseline with live remote status"),
    ("6", "Run CAI + PentestGPT + VulnBot suite"),
    ("e", "Run our agent on external benchmark suite"),
    ("7", "Compare last/run directory"),
    ("i", "Inject/populate/verify vulnerabilities"),
    ("r", "Reset scenario to vulnerable state"),
    ("8", "Full selected-tool pilot"),
    ("9", "Teardown benchmark scenario"),
    ("0", "Quit"),
]


@dataclass
class DashboardState:
    baseline_host: str = DEFAULT_BASELINE_HOST
    tool: str = "cai"
    scenario_id: str = DEFAULT_SCENARIO
    scope: str = DEFAULT_SCOPE
    model: str = DEFAULT_MODEL
    max_turns: int = 40
    jobs: int = 1
    last_run_dir: Path | None = None
    last_suite_dir: Path | None = None
    last_external_dir: Path | None = None
    external_suite: str = "vulhub"
    external_repo: str = "../vulhub"
    external_case: str = ""
    external_dry_run: bool = True
    status: str = "Idle"
    current_target: str = "-"
    current_index: int = 0
    target_count: int = 0
    started_at: float = field(default_factory=time.monotonic)
    logs: list[str] = field(default_factory=list)
    score: dict[str, Any] | None = None


def _fallback() -> None:
    from src.baselines.wizard import run_wizard

    print("Rich is not installed; falling back to the simple wizard.")
    run_wizard()


def _ask(console: Console, prompt: str, default: str | None = None) -> str:
    suffix = f" [dim](current: {default}; Enter = keep)[/dim]" if default else ""
    value = console.input(f"[bold cyan]{prompt}[/bold cyan]{suffix}: ").strip()
    return value or (default or "")


def _push_log(state: DashboardState, message: str) -> None:
    state.logs.append(message)
    state.logs = state.logs[-8:]


def _render_header(state: DashboardState, compact: bool = False):
    if compact:
        line = (
            f"[bold]S{state.scenario_id}[/bold]  "
            f"[cyan]{state.tool}[/cyan]  "
            f"jobs={state.jobs}  "
            f"{state.baseline_host}  "
            f"[dim]{state.model}[/dim]"
        )
        last = (
            f"Last run: {state.last_run_dir or '-'} | "
            f"Last suite: {state.last_suite_dir or '-'} | "
            f"Last external: {state.last_external_dir or '-'}"
        )
        return Panel(f"{line}\n[dim]{last}[/dim]", title="NATO Smart City IoT Baseline", border_style="cyan")

    table = Table.grid(expand=True)
    table.add_column(ratio=1)
    table.add_column(ratio=1)
    table.add_row("[bold]Baseline[/bold]", state.baseline_host)
    table.add_row("[bold]Tool[/bold]", state.tool)
    table.add_row("[bold]Scenario[/bold]", state.scenario_id)
    table.add_row("[bold]Scope[/bold]", state.scope)
    table.add_row("[bold]Model[/bold]", state.model)
    table.add_row("[bold]Max turns[/bold]", str(state.max_turns))
    table.add_row("[bold]Parallel jobs[/bold]", str(state.jobs))
    table.add_row("[bold]Last run[/bold]", str(state.last_run_dir or "-"))
    table.add_row("[bold]Last suite[/bold]", str(state.last_suite_dir or "-"))
    table.add_row("[bold]Last external[/bold]", str(state.last_external_dir or "-"))
    return Panel(table, title="NATO Smart City IoT Baseline", border_style="cyan")


def _render_menu(selected: int = 0):
    menu = Table(show_header=False, box=None, expand=True)
    menu.add_column("cursor", width=2)
    menu.add_column("key", width=4)
    menu.add_column("action")
    for index, (key, action) in enumerate(MENU_ACTIONS):
        if index == selected:
            menu.add_row("[bold cyan]>[/bold cyan]", f"[bold cyan]{key}[/bold cyan]", f"[bold reverse]{action}[/bold reverse]")
        else:
            menu.add_row("", f"[dim]{key}[/dim]", action)
    return Panel(menu, title="Actions - use ↑/↓ then Enter, q to quit", border_style="magenta")


def _render_choice_menu(title: str, options: list[tuple[str, str]], selected: int):
    menu = Table(show_header=False, box=None, expand=True)
    menu.add_column("cursor", width=2)
    menu.add_column("label")
    menu.add_column("description")
    for index, (label, description) in enumerate(options):
        if index == selected:
            menu.add_row("[bold cyan]>[/bold cyan]", f"[bold reverse]{label}[/bold reverse]", description)
        else:
            menu.add_row("", label, f"[dim]{description}[/dim]")
    return Panel(menu, title=f"{title} - use ↑/↓ then Enter", border_style="cyan")


def _read_key() -> str:
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        first = sys.stdin.read(1)
        if first == "\x1b":
            rest = sys.stdin.read(2)
            return first + rest
        return first
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def _render_dashboard_shell(state: DashboardState, selected: int, compact: bool = False) -> Group:
    return Group(
        Align.center("[bold cyan]NATO Smart City IoT[/bold cyan] [white]Baseline Terminal[/white]"),
        _render_header(state, compact=compact),
        _render_menu(selected),
    )


def _clear_console(console: Console) -> None:
    console.file.write("\033[2J\033[H")
    console.file.flush()


def _select_action(console: Console, state: DashboardState, selected: int) -> tuple[str, int]:
    """Return (menu key, selected index), using arrows when stdin is interactive."""
    if not sys.stdin.isatty():
        choice = console.input("\n[bold cyan]Choice[/bold cyan]: ").strip()
        for index, (key, _) in enumerate(MENU_ACTIONS):
            if key == choice:
                return key, index
        return choice, selected

    while True:
        _clear_console(console)
        console.print(_render_dashboard_shell(state, selected, compact=console.height < 34))
        key = _read_key()
        if key in {"\x1b[A", "k"}:
            selected = (selected - 1) % len(MENU_ACTIONS)
        elif key in {"\x1b[B", "j"}:
            selected = (selected + 1) % len(MENU_ACTIONS)
        elif key in {"\r", "\n"}:
            return MENU_ACTIONS[selected][0], selected
        elif key.lower() == "q":
            return "0", selected
        else:
            for index, (menu_key, _) in enumerate(MENU_ACTIONS):
                if key == menu_key:
                    return menu_key, index


def _select_choice(
    console: Console,
    title: str,
    options: list[tuple[str, str, Any]],
    current: Any,
) -> Any:
    selected = next((index for index, (_, _, value) in enumerate(options) if value == current), 0)
    if not sys.stdin.isatty():
        rendered = "/".join(label for label, _, _ in options)
        raw = console.input(f"[bold cyan]{title}[/bold cyan] [{rendered}; current={current}]: ").strip().lower()
        if not raw:
            return current
        for label, _, value in options:
            if raw in {str(value).lower(), label.lower()}:
                return value
        return current

    def render_choice() -> Panel:
        return _render_choice_menu(title, [(label, description) for label, description, _ in options], selected)

    while True:
        _clear_console(console)
        console.print(render_choice())
        key = _read_key()
        if key in {"\x1b[A", "k"}:
            selected = (selected - 1) % len(options)
        elif key in {"\x1b[B", "j"}:
            selected = (selected + 1) % len(options)
        elif key in {"\r", "\n"}:
            return options[selected][2]
        elif key.lower() == "q":
            return current


def _ask_yes_no(console: Console, prompt: str, default: bool = True) -> bool:
    return bool(
        _select_choice(
            console,
            prompt,
            [
                ("Yes", "Run this step", True),
                ("No", "Skip this step", False),
            ],
            default,
        )
    )


def _change_scenario(console: Console, state: DashboardState) -> None:
    state.scenario_id = _select_scenario_id(console, state.scenario_id)
    state.last_run_dir = None
    state.last_suite_dir = None
    state.score = None
    console.print(f"[green]Scenario set to S{state.scenario_id}.[/green]")


def _select_scenario_id(console: Console, current: str) -> str:
    scenarios = list_ground_truth_scenarios()
    if scenarios:
        return str(
            _select_choice(
                console,
                "Scenario",
                [(f"S{sid}", f"Use scenario {sid}", sid) for sid in scenarios],
                current,
            )
        )
    return _ask(console, "Scenario id", current)


def _switch_scenario(console: Console, state: DashboardState) -> None:
    current = state.scenario_id
    next_scenario = _select_scenario_id(console, current)
    if not next_scenario:
        console.print("[red]No scenario selected.[/red]")
        return
    populate = _ask_yes_no(console, "Populate services after vulnerability injection?", True)
    verify = _ask_yes_no(console, "Run verification playbook after deployment?", True)
    if not _ask_yes_no(console, f"Teardown S{current}, then deploy/inject S{next_scenario}?", False):
        console.print("[yellow]Switch cancelled.[/yellow]")
        return

    def on_event(event: dict[str, Any]) -> None:
        name = event["event"]
        step = event.get("step")
        scenario_id = event.get("scenario_id")
        labels = {
            "teardown": "Teardown",
            "deploy": "Clone/deploy VMs",
            "inject": "Inject vulnerabilities",
            "populate": "Populate services",
            "verify": "Verify vulnerabilities",
        }
        if name == "switch_start":
            console.print(f"[cyan]Switching S{event['current_scenario_id']} -> S{event['next_scenario_id']}[/cyan]")
        elif name == "switch_step_start":
            console.print(f"[cyan]{labels.get(step, step)} for S{scenario_id}...[/cyan]")
        elif name == "switch_step_done":
            console.print(f"[green]{labels.get(step, step)} done for S{scenario_id}.[/green]")
        elif name == "switch_done":
            console.print(f"[green]Scenario S{event['next_scenario_id']} is deployed, injected and ready.[/green]")

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
    state.score = None


def _render_live(state: DashboardState, progress: Progress | None = None):
    status = Table.grid(expand=True)
    status.add_column(ratio=1)
    status.add_column(ratio=2)
    status.add_row("[bold]Status[/bold]", state.status)
    status.add_row("[bold]Current target[/bold]", state.current_target)
    status.add_row("[bold]Progress[/bold]", f"{state.current_index}/{state.target_count}")
    status.add_row("[bold]Elapsed[/bold]", f"{int(time.monotonic() - state.started_at)}s")

    log_text = Text("\n".join(state.logs) or "No events yet.")
    panels = [
        Panel(status, title="Live Remote Run", border_style="green"),
    ]
    if progress:
        panels.append(progress)
    if state.score:
        score = state.score
        score_table = Table.grid(expand=True)
        score_table.add_column()
        score_table.add_column(justify="right")
        score_table.add_row("Recall", f"{score['recall']:.3f}")
        score_table.add_row("Precision", f"{score['precision']:.3f}")
        score_table.add_row("F1", f"{score['f1']:.3f}")
        score_table.add_row("Score", f"{score['score_pct']:.1f}%")
        panels.append(Panel(score_table, title="Score", border_style="yellow"))
    panels.append(Panel(log_text, title="Recent Events", border_style="blue"))
    return Group(*panels)


def _configure(console: Console, state: DashboardState) -> None:
    console.clear()
    console.print(_render_header(state))
    console.print("[dim]Edit a value, or press Enter to keep the current one.[/dim]\n")
    state.baseline_host = _ask(console, "Baseline SSH host", state.baseline_host)
    state.tool = _select_choice(
        console,
        "Baseline tool",
        [
            ("CAI", "CAI SDK adapter", "cai"),
            ("PentestGPT", "PentestGPT-style benchmark adapter", "pentgpt"),
            ("VulnBot", "VulnBot-style benchmark adapter", "vulnbot"),
        ],
        state.tool,
    )
    console.clear()
    console.print(_render_header(state))
    console.print("[dim]Continue editing, or press Enter to keep the current value.[/dim]\n")
    state.scenario_id = _ask(console, "Scenario id", state.scenario_id)
    state.scope = _ask(console, "CIDR scope", state.scope)
    state.model = _ask(console, "Model", state.model)
    turns = _ask(console, "Max turns per target", str(state.max_turns))
    try:
        state.max_turns = int(turns)
    except ValueError:
        console.print("[red]Invalid max turns; keeping previous value.[/red]")
    jobs = _ask(console, "Parallel jobs", str(state.jobs))
    try:
        state.jobs = max(1, int(jobs))
    except ValueError:
        console.print("[red]Invalid parallel jobs; keeping previous value.[/red]")


def _setup_baseline_tools(console: Console, state: DashboardState) -> None:
    api_key = os.environ.get(install_tools.DEFAULT_API_KEY_ENV)
    if not api_key:
        console.print(f"[yellow]{install_tools.DEFAULT_API_KEY_ENV} is not set locally.[/yellow]")
        api_key = getpass.getpass("Paste MiniMax API key (hidden): ").strip()
    if not api_key:
        console.print("[red]No API key provided; setup cancelled.[/red]")
        return
    with console.status("[cyan]Installing/updating baseline adapters on baseline VM...[/cyan]"):
        install_tools.setup_baseline_adapters(state.baseline_host, api_key, model=state.model)
    console.print("[green]Baseline tools setup completed.[/green]")


def _deploy_scenario(console: Console, state: DashboardState) -> None:
    populate = _ask_yes_no(console, "Populate services after vulnerability injection?", True)
    verify = _ask_yes_no(console, "Run verification playbook after deployment?", True)
    deploy.deploy_scenario(state.scenario_id, populate=populate, verify=verify)
    console.print(f"[green]Scenario {state.scenario_id} deployed, injected and ready.[/green]")


def _inject_vulnerabilities(console: Console, state: DashboardState) -> None:
    populate = _ask_yes_no(console, "Populate services after injection?", True)
    verify = _ask_yes_no(console, "Verify vulnerabilities after injection?", True)
    with console.status(f"[cyan]Injecting vulnerabilities for scenario {state.scenario_id}...[/cyan]"):
        deploy.inject_vulnerabilities(state.scenario_id)
    if populate:
        with console.status(f"[cyan]Populating services for scenario {state.scenario_id}...[/cyan]"):
            deploy.populate_services(state.scenario_id)
    if verify:
        with console.status(f"[cyan]Verifying scenario {state.scenario_id}...[/cyan]"):
            deploy.verify_scenario(state.scenario_id)
    console.print(f"[green]Scenario {state.scenario_id} is ready.[/green]")


def _reset_scenario(console: Console, state: DashboardState) -> None:
    verify = _ask_yes_no(console, "Verify after reset?", True)
    with console.status(f"[cyan]Resetting scenario {state.scenario_id} to vulnerable state...[/cyan]"):
        deploy.reset_scenario(state.scenario_id)
    if verify:
        with console.status(f"[cyan]Verifying scenario {state.scenario_id}...[/cyan]"):
            deploy.verify_scenario(state.scenario_id)
    console.print(f"[green]Scenario {state.scenario_id} reset to vulnerable state.[/green]")


def _run_tool_live(console: Console, state: DashboardState) -> None:
    state.status = "Starting"
    state.current_target = "-"
    state.current_index = 0
    state.target_count = 0
    state.started_at = time.monotonic()
    state.logs = []
    state.score = None

    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        expand=True,
    )
    task_id = progress.add_task("Targets", total=1)
    active_targets: set[str] = set()
    completed_targets = 0

    def on_event(event: dict[str, Any]) -> None:
        name = event["event"]
        if name == "run_start":
            state.status = "Running"
            state.target_count = int(event["target_count"])
            progress.update(task_id, total=state.target_count)
            _push_log(
                state,
                f"Run started: {event['tool']} S{event['scenario_id']} jobs={event.get('jobs', 1)} -> {event['run_dir']}",
            )
        elif name == "target_selected":
            target = event["target"]
            _push_log(state, f"Target {event['index']}/{event['total']}: {target['ip']}")
        elif name == "target_start":
            target = event["target"]
            tool = event.get("tool", state.tool)
            state.status = f"Remote {tool} running"
            active_targets.add(target["ip"])
            state.current_target = ", ".join(sorted(active_targets)) or "-"
            _push_log(state, f"Started remote {tool} on {target['ip']}")
        elif name == "target_heartbeat":
            target = event["target"]
            _push_log(state, f"{target['ip']} still running after {event['elapsed']}s")
        elif name == "target_finished":
            target = event["target"]
            active_targets.discard(target["ip"])
            state.current_target = ", ".join(sorted(active_targets)) or "-"
            _push_log(state, f"{target['ip']} finished in {event['elapsed']}s")
        elif name == "target_result_saved":
            nonlocal completed_targets
            completed_targets += 1
            state.current_index = completed_targets
            progress.update(task_id, advance=1)
            _push_log(state, f"Saved {event['output']}")
        elif name == "remote_log_saved":
            _push_log(state, f"Saved log {event['local_log']}")
        elif name == "normalizing":
            state.status = "Normalizing findings"
            _push_log(state, "Normalizing raw results")
        elif name == "evaluating":
            state.status = "Evaluating"
            _push_log(state, f"Evaluating against {event['ground_truth']}")
        elif name == "score":
            state.score = event
            _push_log(state, f"Score F1={event['f1']:.3f} Score={event['score_pct']:.1f}%")
        elif name == "run_done":
            state.status = "Done"
            state.last_run_dir = Path(event["run_dir"])
            _push_log(state, f"Done: {event['run_dir']}")
        elif name == "target_failed":
            state.status = "Failed"
            _push_log(state, f"Failed {event['target']['ip']} exit={event['returncode']}")

    with Live(
        _render_live(state, progress),
        console=console,
        refresh_per_second=2,
        screen=True,
        redirect_stdout=True,
        redirect_stderr=True,
        vertical_overflow="crop",
    ) as live:
        def wrapped_event(event: dict[str, Any]) -> None:
            on_event(event)
            live.update(_render_live(state, progress))

        state.last_run_dir = runner.run_baseline(
            tool=state.tool,
            scenario_id=state.scenario_id,
            baseline_host=state.baseline_host,
            variant="A",
            scope=state.scope,
            max_turns=state.max_turns,
            model=state.model,
            event_callback=wrapped_event,
            quiet=True,
            jobs=state.jobs,
        )
        live.update(_render_live(state, progress))


def _run_suite_live(console: Console, state: DashboardState) -> None:
    previous_tool = state.tool
    state.status = "Starting suite"
    state.current_target = "-"
    state.current_index = 0
    state.target_count = 0
    state.started_at = time.monotonic()
    state.logs = []
    state.score = None

    progress = Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        expand=True,
    )
    task_id = progress.add_task("Suite targets", total=len(runner.DEFAULT_SUITE_TOOLS))
    active_targets: set[str] = set()
    completed_targets = 0

    def on_event(event: dict[str, Any]) -> None:
        name = event["event"]
        if name == "suite_start":
            state.status = "Suite running"
            _push_log(state, f"Suite started: {', '.join(event['tools'])} -> {event['suite_dir']}")
        elif name == "suite_adapters_refresh_start":
            state.status = "Refreshing baseline adapters"
            _push_log(state, f"Refreshing adapters on {event['baseline_host']}")
        elif name == "suite_adapters_refresh_done":
            state.status = "Baseline adapters ready"
            _push_log(state, "Baseline adapters ready")
        elif name == "suite_tool_start":
            state.tool = event["tool"]
            state.status = f"Starting {state.tool}"
            state.current_index = 0
            _push_log(state, f"Tool {event['index']}/{event['total']}: {state.tool}")
        elif name == "run_start":
            state.status = f"Running {event['tool']}"
            state.target_count = int(event["target_count"])
            progress.update(task_id, total=state.target_count * len(runner.DEFAULT_SUITE_TOOLS))
            _push_log(
                state,
                f"Run started: {event['tool']} S{event['scenario_id']} jobs={event.get('jobs', 1)} -> {event['run_dir']}",
            )
        elif name == "target_selected":
            target = event["target"]
            _push_log(state, f"{state.tool} target {event['index']}/{event['total']}: {target['ip']}")
        elif name == "target_start":
            target = event["target"]
            tool = event.get("tool", state.tool)
            state.status = f"Remote {tool} running"
            active_targets.add(target["ip"])
            state.current_target = ", ".join(sorted(active_targets)) or "-"
            _push_log(state, f"Started remote {tool} on {target['ip']}")
        elif name == "target_heartbeat":
            target = event["target"]
            _push_log(state, f"{state.tool} {target['ip']} still running after {event['elapsed']}s")
        elif name == "target_finished":
            target = event["target"]
            active_targets.discard(target["ip"])
            state.current_target = ", ".join(sorted(active_targets)) or "-"
            _push_log(state, f"{state.tool} {target['ip']} finished in {event['elapsed']}s")
        elif name == "target_result_saved":
            nonlocal completed_targets
            completed_targets += 1
            state.current_index = completed_targets
            progress.update(task_id, advance=1)
            _push_log(state, f"Saved {event['output']}")
        elif name == "remote_log_saved":
            _push_log(state, f"Saved log {event['local_log']}")
        elif name == "normalizing":
            state.status = f"Normalizing {state.tool}"
            _push_log(state, "Normalizing raw results")
        elif name == "evaluating":
            state.status = f"Evaluating {state.tool}"
            _push_log(state, f"Evaluating against {event['ground_truth']}")
        elif name == "score":
            state.score = event
            _push_log(state, f"{state.tool} F1={event['f1']:.3f} Score={event['score_pct']:.1f}%")
        elif name == "run_done":
            state.last_run_dir = Path(event["run_dir"])
            _push_log(state, f"Done: {event['run_dir']}")
        elif name == "suite_tool_done":
            _push_log(state, f"Finished {event['tool']}: {event['run_dir']}")
        elif name == "suite_done":
            state.status = "Suite done"
            state.last_suite_dir = Path(event["suite_dir"])
            _push_log(state, f"Suite done: {event['suite_dir']}")
        elif name == "target_failed":
            state.status = "Failed"
            _push_log(state, f"Failed {event['target']['ip']} exit={event['returncode']}")

    with Live(
        _render_live(state, progress),
        console=console,
        refresh_per_second=2,
        screen=True,
        redirect_stdout=True,
        redirect_stderr=True,
        vertical_overflow="crop",
    ) as live:
        def wrapped_event(event: dict[str, Any]) -> None:
            on_event(event)
            live.update(_render_live(state, progress))

        state.last_suite_dir = runner.run_suite(
            scenario_id=state.scenario_id,
            baseline_host=state.baseline_host,
            variant="A",
            scope=state.scope,
            max_turns=state.max_turns,
            model=state.model,
            event_callback=wrapped_event,
            quiet=True,
            jobs=state.jobs,
        )
        state.tool = previous_tool
        live.update(_render_live(state, progress))


def _compare(console: Console, state: DashboardState) -> None:
    run_dir = Path(_ask(console, "Run directory", str(state.last_run_dir or "")))
    if not str(run_dir):
        console.print("[red]No run directory selected.[/red]")
        return
    result = compare.evaluate_baseline_run(run_dir)
    table = Table(title=f"Scenario S{result['scenario_id']} Score")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for name, value in [
        ("Recall", f"{result['recall']:.3f}"),
        ("Precision", f"{result['precision']:.3f}"),
        ("F1", f"{result['f1_score']:.3f}"),
        ("Score", f"{result['score_pct']:.1f}%"),
        ("TP", str(result["true_positives"])),
        ("FP", str(result["false_positives"])),
        ("FN", str(result["false_negatives"])),
    ]:
        table.add_row(name, value)
    console.print(table)


def _full_pilot(console: Console, state: DashboardState) -> None:
    if _ask_yes_no(console, f"Deploy scenario {state.scenario_id} first?", True):
        _deploy_scenario(console, state)
    if _ask_yes_no(console, "Install/update baseline adapters first?", False):
        _setup_baseline_tools(console, state)
    _run_tool_live(console, state)
    _compare(console, state)


def _default_external_repo(suite: str) -> str:
    return EXTERNAL_REPOS.get(suite, ("", f"../{suite}"))[1]


def _external_repo_url(suite: str) -> str:
    return EXTERNAL_REPOS.get(suite, ("", ""))[0]


def _ensure_external_repo(console: Console, suite: str, repo: Path) -> bool:
    if repo.exists():
        return True
    url = _external_repo_url(suite)
    if not url:
        console.print(f"[red]Repository not found:[/red] {repo}")
        return False
    if not _ask_yes_no(console, f"{suite} repo not found at {repo}. Clone it now?", True):
        return False
    repo.parent.mkdir(parents=True, exist_ok=True)
    with console.status(f"[cyan]Cloning {suite} into {repo}...[/cyan]"):
        subprocess.run(["git", "clone", url, str(repo)], check=True)
    return True


def _select_external_case(
    console: Console,
    suite: str,
    repo: Path,
    current: str,
) -> external_benchmarks.ExternalBenchmarkCase | None:
    with console.status(f"[cyan]Discovering {suite} cases...[/cyan]"):
        cases = external_benchmarks.discover_cases(suite, repo)
    if not cases:
        console.print(f"[red]No cases discovered for {suite} in {repo}.[/red]")
        return None

    console.print(f"[green]{len(cases)} cases discovered.[/green]")
    query = _ask(console, "Filter cases (Enter = show first cases)", current)
    filtered = cases
    if query:
        needle = query.lower()
        filtered = [
            case
            for case in cases
            if needle in case.case_id.lower()
            or needle in case.name.lower()
            or needle in case.description.lower()
            or needle in " ".join(case.tags).lower()
        ]
    if not filtered:
        console.print(f"[red]No case matched {query!r}.[/red]")
        return None

    visible = filtered[:80]
    if len(filtered) > len(visible):
        console.print(f"[yellow]Showing first {len(visible)} of {len(filtered)} matches. Add a filter to narrow it.[/yellow]")

    selected = _select_choice(
        console,
        f"{suite} case",
        [
            (
                case.case_id,
                case.description or case.target_url or case.notes or "-",
                case.case_id,
            )
            for case in visible
        ],
        current if any(case.case_id == current for case in visible) else visible[0].case_id,
    )
    for case in visible:
        if case.case_id == selected:
            return case
    return None


def _external_agent_command(state: DashboardState, case: external_benchmarks.ExternalBenchmarkCase) -> str:
    hint = "{task}"
    if case.suite == "vulhub":
        hint = "Vulhub case {case_id}. Vulnerability: {vulnerability}"
    elif case.suite == "autopenbench":
        hint = "Task: {task}. Target service: {target_name}. Vulnerability: {vulnerability}"
    return (
        "python3 -m src.agent_external "
        "--target {target_url} "
        f"--hint {hint!r} "
        "--output-dir {output_dir} "
        "--provider minimax "
        f"--model {state.model} "
        f"--max-turns {state.max_turns}"
    )


def _run_external_benchmark(console: Console, state: DashboardState) -> None:
    state.external_suite = _select_choice(
        console,
        "External benchmark suite",
        [
            ("Vulhub", "Docker Compose vulnerable environments", "vulhub"),
            ("AutoPenBench", "Generative-agent pentest tasks with flags", "autopenbench"),
            ("XBOW", "Flag-style validation benchmarks", "xbow"),
            ("AI-Pentest", "Manual VulnHub/VM metadata", "ai-pentest"),
        ],
        state.external_suite,
    )
    if state.external_repo == _default_external_repo("vulhub") and state.external_suite != "vulhub":
        state.external_repo = _default_external_repo(state.external_suite)
    state.external_repo = _ask(console, "External repo path", state.external_repo or _default_external_repo(state.external_suite))
    repo = Path(state.external_repo).expanduser()
    if not _ensure_external_repo(console, state.external_suite, repo):
        return

    case = _select_external_case(console, state.external_suite, repo, state.external_case)
    if not case:
        return
    state.external_case = case.case_id
    state.external_dry_run = _ask_yes_no(console, "Dry-run first?", state.external_dry_run)
    command = _external_agent_command(state, case)

    details = Table.grid(expand=True)
    details.add_column(ratio=1)
    details.add_column(ratio=2)
    details.add_row("[bold]Suite[/bold]", state.external_suite)
    details.add_row("[bold]Repo[/bold]", str(repo))
    details.add_row("[bold]Case[/bold]", case.case_id)
    details.add_row("[bold]Target[/bold]", case.target_url or case.target or "-")
    details.add_row("[bold]Mode[/bold]", "dry-run" if state.external_dry_run else "real run")
    console.print(Panel(details, title="External Benchmark Run", border_style="cyan"))
    if not _ask_yes_no(console, "Start this external benchmark run?", True):
        console.print("[yellow]External run cancelled.[/yellow]")
        return

    with console.status(f"[cyan]Running {state.external_suite}/{case.case_id}...[/cyan]"):
        state.last_external_dir = external_benchmarks.run_case(
            suite=state.external_suite,
            repo=repo,
            case_id=case.case_id,
            agent_command=command,
            dry_run=state.external_dry_run,
            timeout_seconds=state.max_turns * 90,
        )
    console.print(f"[green]External run saved:[/green] {state.last_external_dir}")


def run_dashboard() -> None:
    if Console is None:
        _fallback()
        return

    console = Console()
    state = DashboardState()
    selected = 0
    while True:
        choice, selected = _select_action(console, state, selected)
        try:
            if choice == "1":
                _configure(console, state)
            elif choice == "s":
                _change_scenario(console, state)
            elif choice == "x":
                _switch_scenario(console, state)
            elif choice == "2":
                with console.status("[cyan]Deploying baseline VM...[/cyan]"):
                    deploy.deploy_baseline_vm()
            elif choice == "3":
                _setup_baseline_tools(console, state)
            elif choice == "4":
                _deploy_scenario(console, state)
            elif choice == "5":
                _run_tool_live(console, state)
            elif choice == "6":
                _run_suite_live(console, state)
            elif choice == "e":
                _run_external_benchmark(console, state)
            elif choice == "7":
                _compare(console, state)
            elif choice == "i":
                _inject_vulnerabilities(console, state)
            elif choice == "r":
                _reset_scenario(console, state)
            elif choice == "8":
                _full_pilot(console, state)
            elif choice == "9":
                if _ask_yes_no(console, f"Destroy scenario {state.scenario_id}?", False):
                    deploy.teardown_scenario(state.scenario_id)
            elif choice == "0":
                return
            else:
                console.print("[red]Unknown choice.[/red]")
        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/yellow]")
        except Exception as exc:
            console.print(f"\n[red]Error:[/red] {exc}")
        console.input("\n[dim]Press Enter to continue...[/dim]")


if __name__ == "__main__":
    run_dashboard()
