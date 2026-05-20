"""Rich terminal dashboard for baseline runs."""
from __future__ import annotations

import getpass
import os
import sys
import termios
import time
import tty
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.baselines import compare, deploy, external_benchmarks, fleet, install_tools, runner, store
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
    "vulhub": ("https://github.com/vulhub/vulhub", "/opt/external-benchmarks/vulhub"),
    "autopenbench": ("https://github.com/lucagioacchini/auto-pen-bench", "/opt/external-benchmarks/auto-pen-bench"),
    "xbow": ("", "/opt/external-benchmarks/validation-benchmarks"),
    "ai-pentest": ("", "/opt/external-benchmarks/ai-pentest-benchmark"),
}
MENU_SECTIONS: list[tuple[str, list[tuple[str, str]]]] = [
    (
        "Configuration",
        [
            ("1", "Configure tool / scope / model / hosts"),
            ("s", "Change scenario"),
        ],
    ),
    (
        "Provisioning & scenarios",
        [
            ("2", "Deploy single baseline VM (Ansible)"),
            ("3", "Setup baseline tools on baseline VM"),
            ("4", "Deploy full scenario (deploy + inject + populate + verify)"),
            ("x", "Teardown current scenario and deploy another"),
        ],
    ),
    (
        "Single-VM benchmark runs",
        [
            ("5", "Run selected baseline tool with live remote status"),
            ("6", "Run CAI + PentestGPT + VulnBot suite"),
            ("8", "Full selected-tool pilot (scenario_3 paper plan)"),
            ("e", "Run our agent on external benchmark suite"),
            ("j", "Manage external detached jobs on single VM"),
        ],
    ),
    (
        "Fleet (multi-VM distributed)",
        [
            ("f", "Fleet: configure / start / monitor / fetch"),
        ],
    ),
    (
        "Analysis & maintenance",
        [
            ("7", "Compare last run or other directories"),
            ("h", "History (SQLite-backed: jobs, runs, breakdown)"),
            ("i", "Inject / populate / verify vulnerabilities"),
            ("r", "Reset scenario to vulnerable state"),
            ("9", "Teardown benchmark scenario"),
        ],
    ),
    (
        "Exit",
        [("0", "Quit")],
    ),
]
# Flat view for iteration and compatibility with existing _select_action loop.
MENU_ACTIONS: list[tuple[str, str]] = [(key, label) for _section, items in MENU_SECTIONS for key, label in items]


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
    external_repo: str = "/opt/external-benchmarks/vulhub"
    external_case: str = ""
    external_dry_run: bool = True
    external_context_mode: str = "blind"
    baseline_hosts: list[str] = field(default_factory=list)
    active_distributed_job_id: str | None = None
    status: str = "Idle"
    current_target: str = "-"
    current_index: int = 0
    target_count: int = 0
    started_at: float = field(default_factory=time.monotonic)
    logs: list[str] = field(default_factory=list)
    score: dict[str, Any] | None = None

    @property
    def effective_hosts(self) -> list[str]:
        return list(self.baseline_hosts) if self.baseline_hosts else [self.baseline_host]


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


def _render_single_vm_panel(state: DashboardState) -> Panel:
    table = Table.grid(expand=True, padding=(0, 1))
    table.add_column(style="bold cyan", no_wrap=True, ratio=1)
    table.add_column(ratio=2)
    table.add_row("Host", state.baseline_host)
    table.add_row("Tool", f"[white]{state.tool}[/white]")
    table.add_row("Scenario", f"S{state.scenario_id}")
    table.add_row("Scope", state.scope)
    table.add_row("Model", f"[dim]{state.model}[/dim]")
    table.add_row("Max turns", str(state.max_turns))
    table.add_row("Parallel jobs", str(state.jobs))
    return Panel(table, title="Single VM", border_style="cyan")


def _render_fleet_panel(state: DashboardState) -> Panel:
    table = Table.grid(expand=True, padding=(0, 1))
    table.add_column(style="bold magenta", no_wrap=True, ratio=1)
    table.add_column(ratio=2)
    hosts = state.baseline_hosts or list(fleet.DEFAULT_FLEET_HOSTS)
    hosts_status = "[dim]not configured (using defaults)[/dim]" if not state.baseline_hosts else f"[white]{len(hosts)} host(s)[/white]"
    table.add_row("Hosts", hosts_status)
    table.add_row("Configured", "\n".join(hosts) if hosts else "-")
    table.add_row(
        "Active job",
        f"[white]{state.active_distributed_job_id}[/white]" if state.active_distributed_job_id else "[dim]none[/dim]",
    )
    return Panel(table, title="Fleet", border_style="magenta")


def _render_last_runs_panel(state: DashboardState) -> Panel:
    table = Table.grid(expand=True, padding=(0, 1))
    table.add_column(style="bold yellow", no_wrap=True, ratio=1)
    table.add_column(ratio=3)
    table.add_row("Last run", str(state.last_run_dir or "-"))
    table.add_row("Last suite", str(state.last_suite_dir or "-"))
    table.add_row("Last external", str(state.last_external_dir or "-"))
    db_path = store.DEFAULT_DB_PATH
    db_state = "[green]ready[/green]" if db_path.exists() else "[dim]not yet initialized[/dim]"
    table.add_row("History DB", f"{db_path}  {db_state}")
    return Panel(table, title="Last artifacts", border_style="yellow")


def _render_header(state: DashboardState, compact: bool = False):
    if compact:
        line = (
            f"[bold]S{state.scenario_id}[/bold]  "
            f"[cyan]{state.tool}[/cyan]  "
            f"jobs={state.jobs}  "
            f"[white]{state.baseline_host}[/white]  "
            f"[magenta]fleet={len(state.baseline_hosts) or 0}[/magenta]  "
            f"[dim]{state.model}[/dim]"
        )
        last = (
            f"Last run: {state.last_run_dir or '-'} | "
            f"Last suite: {state.last_suite_dir or '-'} | "
            f"Last external: {state.last_external_dir or '-'}"
        )
        active = (
            f"\n[magenta]Active distributed job:[/magenta] {state.active_distributed_job_id}"
            if state.active_distributed_job_id
            else ""
        )
        return Panel(f"{line}\n[dim]{last}[/dim]{active}", title="NATO Smart City IoT Baseline", border_style="cyan")

    top = Table.grid(expand=True, padding=(0, 1))
    top.add_column(ratio=1)
    top.add_column(ratio=1)
    top.add_row(_render_single_vm_panel(state), _render_fleet_panel(state))
    return Group(top, _render_last_runs_panel(state))


def _render_menu(selected: int = 0):
    grid = Table(show_header=False, box=None, expand=True, padding=(0, 1))
    grid.add_column("cursor", width=2)
    grid.add_column("key", width=4)
    grid.add_column("action")
    flat_index = 0
    for section_title, items in MENU_SECTIONS:
        grid.add_row("", "", f"[bold magenta]── {section_title} ──[/bold magenta]")
        for key, action in items:
            if flat_index == selected:
                grid.add_row(
                    "[bold cyan]>[/bold cyan]",
                    f"[bold cyan]{key}[/bold cyan]",
                    f"[bold reverse]{action}[/bold reverse]",
                )
            else:
                grid.add_row("", f"[dim]{key}[/dim]", action)
            flat_index += 1
    return Panel(grid, title="Actions  ↑/↓ + Enter   q to quit   shortcut keys also work", border_style="magenta")


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
    if not _external_repo_url(suite) and suite in {"xbow", "ai-pentest"}:
        console.print(f"[yellow]{suite} has no default public clone URL. Expecting it on the VM at {repo}.[/yellow]")
    return True


def _select_external_case(
    console: Console,
    baseline_host: str,
    suite: str,
    repo: Path,
    current: str,
) -> tuple[list[external_benchmarks.ExternalBenchmarkCase], external_benchmarks.ExternalBenchmarkCase | None] | None:
    with console.status(f"[cyan]Preparing {suite} on {baseline_host} and discovering cases...[/cyan]"):
        cases = external_benchmarks.discover_remote_cases(
            baseline_host=baseline_host,
            suite=suite,
            repo=repo,
        )
    if not cases:
        console.print(f"[red]No cases discovered for {suite} in {repo}.[/red]")
        return None

    console.print(f"[green]{len(cases)} cases discovered.[/green]")
    query = _ask(console, "Filter cases (Enter = show first cases)", "")
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

    if _ask_yes_no(console, f"Run all {len(filtered)} filtered runnable cases?", False):
        raw_limit = _ask(console, "Max cases to run (Enter = all)", "")
        if raw_limit:
            try:
                filtered = filtered[: max(1, int(raw_limit))]
            except ValueError:
                console.print("[yellow]Invalid limit; running all filtered cases.[/yellow]")
        return filtered, None

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
            return [case], case
    return None


def _external_agent_command(state: DashboardState, case: external_benchmarks.ExternalBenchmarkCase) -> str:
    model = state.model
    if model.startswith("openai/"):
        model = model.split("/", 1)[1]
    if state.external_context_mode == "blind":
        return external_benchmarks.external_agent_command(
            provider="minimax",
            model=model,
            max_turns=state.max_turns,
            context_mode="blind",
        )
    hint = (
        "Benchmark context policy: {context_policy}. "
        "Task: {task}. Target service label: {target_name}. "
        "Known vulnerability label: {vulnerability}. Primary exposed service: {service_context}. "
        "Do not use repository README, docker-compose, scripts, or challenge source; rely only on target interaction."
    )
    if case.suite == "vulhub":
        hint = (
            "Benchmark context policy: {context_policy}. Vulhub case id: {case_id}. "
            "Known CVE label from case path: {vulnerability}. Primary exposed service: {service_context}. "
            "Vulhub has no universal flag; produce target-derived evidence when no flag exists. "
            "Do not use repository README, docker-compose, scripts, or challenge source; rely only on target interaction."
        )
    elif case.suite == "autopenbench":
        hint = (
            "Benchmark context policy: {context_policy}. Task: {task}. Target service label: {target_name}. "
            "Known vulnerability label: {vulnerability}. Primary exposed service: {service_context}. "
            "Do not use repository README, docker-compose, scripts, or challenge source; rely only on target interaction."
        )
    return (
        "python -m src.agent_external "
        "--target {target_or_url} "
        f"--hint {hint!r} "
        "--output-dir {output_dir} "
        "--provider minimax "
        f"--model {model} "
        f"--max-turns {state.max_turns}"
    )


def _run_external_benchmark(console: Console, state: DashboardState) -> None:
    previous_suite = state.external_suite
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
    if state.external_suite != previous_suite:
        state.external_case = ""
    if state.external_repo == _default_external_repo("vulhub") and state.external_suite != "vulhub":
        state.external_repo = _default_external_repo(state.external_suite)
    state.external_repo = _ask(console, "External repo path", state.external_repo or _default_external_repo(state.external_suite))
    repo = Path(state.external_repo).expanduser()
    if not _ensure_external_repo(console, state.external_suite, repo):
        return

    selection = _select_external_case(console, state.baseline_host, state.external_suite, repo, state.external_case)
    if not selection:
        return
    cases, case = selection
    if case:
        state.external_case = case.case_id
    state.external_context_mode = _select_choice(
        console,
        "External context mode",
        [
            ("Blind network only", "Target and exposed service only; no case id or CVE label", "blind"),
            ("Benchmark-informed", "Include benchmark case id and vulnerability/CVE label, but no repo oracle", "informed"),
        ],
        state.external_context_mode,
    )
    state.external_dry_run = _ask_yes_no(console, "Dry-run first?", state.external_dry_run)
    command = _external_agent_command(state, case or cases[0])
    run_mode = _select_choice(
        console,
        "External execution mode",
        [
            ("Start detached on VM", "Run in tmux; your PC can disconnect safely", "detached"),
            ("Run now attached", "Keep this TUI waiting until the run finishes", "attached"),
        ],
        "detached",
    )

    details = Table.grid(expand=True)
    details.add_column(ratio=1)
    details.add_column(ratio=2)
    details.add_row("[bold]Suite[/bold]", state.external_suite)
    details.add_row("[bold]VM[/bold]", state.baseline_host)
    details.add_row("[bold]Repo on VM[/bold]", str(repo))
    details.add_row("[bold]Cases[/bold]", case.case_id if case else f"{len(cases)} filtered cases")
    details.add_row("[bold]Target[/bold]", (case.target_url or case.target) if case else "batch")
    details.add_row("[bold]Context[/bold]", state.external_context_mode)
    details.add_row("[bold]Mode[/bold]", "dry-run" if state.external_dry_run else "real run")
    details.add_row("[bold]Execution[/bold]", run_mode)
    console.print(Panel(details, title="External Benchmark Run", border_style="cyan"))
    if not _ask_yes_no(console, "Start this external benchmark run?", True):
        console.print("[yellow]External run cancelled.[/yellow]")
        return

    if run_mode == "detached":
        with console.status("[cyan]Starting detached tmux job on baseline VM...[/cyan]"):
            job = external_benchmarks.start_detached_job(
                baseline_host=state.baseline_host,
                suite=state.external_suite,
                repo=repo,
                cases=[selected.case_id for selected in cases],
                agent_command=command,
                dry_run=state.external_dry_run,
                timeout_seconds=state.max_turns * 90,
                sync_project=False,
                model=state.model.split("/", 1)[1] if state.model.startswith("openai/") else state.model,
                max_turns=state.max_turns,
                context_mode=state.external_context_mode,
            )
        info = Table.grid(expand=True)
        info.add_column(ratio=1)
        info.add_column(ratio=2)
        info.add_row("[bold]Job id[/bold]", job["job_id"])
        info.add_row("[bold]tmux[/bold]", job["session"])
        info.add_row("[bold]Remote log[/bold]", job["job_log"])
        info.add_row("[bold]Status[/bold]", f"python -m src.baselines external status --remote-host {state.baseline_host} --job-id {job['job_id']}")
        info.add_row("[bold]Logs[/bold]", f"python -m src.baselines external logs --remote-host {state.baseline_host} --job-id {job['job_id']}")
        info.add_row("[bold]Fetch[/bold]", f"python -m src.baselines external fetch --remote-host {state.baseline_host} --job-id {job['job_id']}")
        console.print(Panel(info, title="Detached Job Started", border_style="green"))
        return

    summary: list[dict[str, Any]] = []
    for index, selected_case in enumerate(cases, start=1):
        with console.status(f"[cyan]Running {state.external_suite}/{selected_case.case_id} ({index}/{len(cases)})...[/cyan]"):
            try:
                run_dir = external_benchmarks.run_remote_case(
                    baseline_host=state.baseline_host,
                    suite=state.external_suite,
                    repo=repo,
                    case_id=selected_case.case_id,
                    agent_command=command,
                    dry_run=state.external_dry_run,
                    timeout_seconds=state.max_turns * 90,
                    sync_project=False,
                    prepare_environment=False,
                )
                state.last_external_dir = run_dir
                summary.append({"case_id": selected_case.case_id, "status": "ok", "run_dir": str(run_dir)})
                console.print(f"[green]{index}/{len(cases)} saved:[/green] {run_dir}")
            except Exception as exc:
                summary.append({"case_id": selected_case.case_id, "status": "failed", "error": str(exc)})
                console.print(f"[red]{index}/{len(cases)} failed:[/red] {selected_case.case_id}: {exc}")
    if len(cases) > 1:
        batch_dir = external_benchmarks.DEFAULT_OUTPUT_DIR / "batches"
        batch_dir.mkdir(parents=True, exist_ok=True)
        summary_path = batch_dir / f"{state.external_suite}_{int(time.time())}_summary.json"
        import json

        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        console.print(f"[green]Batch summary saved:[/green] {summary_path}")


def _manage_external_jobs(console: Console, state: DashboardState) -> None:
    with console.status("[cyan]Loading external jobs from baseline VM...[/cyan]"):
        jobs = external_benchmarks.list_detached_jobs(state.baseline_host)
    if not jobs:
        console.print("[yellow]No detached external jobs found on the VM.[/yellow]")
        return

    def job_description(job: dict[str, Any]) -> str:
        progress = f"{job.get('completed', 0)}/{job.get('total', '?')}"
        status = job.get("status", "-")
        updated = job.get("updated_at", job.get("created_at", "-"))
        useful = job.get("useful_findings")
        cost = job.get("estimated_cost_usd")
        extra = []
        if useful is not None:
            extra.append(f"useful={useful}")
        if cost is not None:
            extra.append(f"${float(cost):.4f}")
        suffix = f" | {' '.join(extra)}" if extra else ""
        return f"{status} | {progress} | {updated}{suffix}"

    jobs = sorted(jobs, key=lambda item: str(item.get("updated_at", item.get("created_at", ""))), reverse=True)
    visible = jobs[:80]
    if len(jobs) > len(visible):
        console.print(f"[yellow]Showing latest {len(visible)} of {len(jobs)} jobs.[/yellow]")
    selected_job_id = _select_choice(
        console,
        "Select external job",
        [
            (
                str(job.get("job_id", "-")),
                job_description(job),
                str(job.get("job_id", "")),
            )
            for job in visible
            if job.get("job_id")
        ],
        str(visible[0].get("job_id", "")),
    )
    if not selected_job_id:
        return

    action = _select_choice(
        console,
        f"External job {selected_job_id}",
        [
            ("Show status", "Read one job status.json", "status"),
            ("Tail logs", "Read the latest job.log lines", "logs"),
            ("Fetch results", "Copy job metadata and run results back to this PC", "fetch"),
            ("Organize batch", "Create one local folder containing this job's fetched runs", "organize"),
            ("Generate report", "Aggregate fetched external results with stats and cost", "report"),
            ("Resume missing", "Start a new tmux job for missing/failed cases from this job", "resume"),
            ("Attach tmux", "Attach interactively to the remote tmux session", "attach"),
            ("Stop job", "Kill the tmux session and mark stopped", "stop"),
            ("Prune Docker", "Free unused Docker images on the VM", "prune"),
            ("Back", "Return to the main menu", "back"),
        ],
        "status",
    )
    if action == "back":
        return
    if action == "status":
        console.print_json(data=external_benchmarks.detached_job_status(state.baseline_host, selected_job_id))
    elif action == "logs":
        tail = int(_ask(console, "Tail lines", "100"))
        console.print(external_benchmarks.detached_job_logs(state.baseline_host, selected_job_id, tail))
    elif action == "fetch":
        fetched = external_benchmarks.fetch_detached_job(state.baseline_host, selected_job_id)
        console.print(f"[green]Fetched job metadata:[/green] {fetched}")
        console.print(f"[green]Fetched run results root:[/green] {external_benchmarks.DEFAULT_OUTPUT_DIR}")
        console.print(f"[green]Batch view:[/green] {external_benchmarks.DEFAULT_OUTPUT_DIR / 'batches' / selected_job_id}")
    elif action == "organize":
        batch = external_benchmarks.organize_fetched_job(selected_job_id)
        console.print(f"[green]Batch view:[/green] {batch}")
    elif action == "report":
        root = Path(_ask(console, "Results root", str(external_benchmarks.DEFAULT_OUTPUT_DIR))).expanduser()
        report_dir = root / "reports"
        report_path = report_dir / f"{selected_job_id}_report.json"
        markdown_path = report_dir / f"{selected_job_id}_report.md"
        report = external_benchmarks.generate_report(root, report_path, markdown_path)
        table = Table(title="External Benchmark Report")
        table.add_column("Metric")
        table.add_column("Value", justify="right")
        table.add_row("Runs", str(report["total_runs"]))
        table.add_row("Unique cases", str(report["unique_cases"]))
        table.add_row("Useful findings", str(report["useful_findings"]))
        table.add_row("Environment failed", str(report["environment_failed"]))
        table.add_row("Agent failed", str(report["agent_failed"]))
        table.add_row("Max turns", str(report["max_turns"]))
        table.add_row("Tokens", str(report["total_tokens"]))
        table.add_row("Estimated cost", f"${report['estimated_cost_usd']:.6f}")
        console.print(table)
        console.print(f"[green]Report:[/green] {report_path}")
        console.print(f"[green]Markdown:[/green] {markdown_path}")
    elif action == "resume":
        with console.status("[cyan]Starting resume job for missing cases...[/cyan]"):
            job = external_benchmarks.resume_detached_job(
                baseline_host=state.baseline_host,
                job_id=selected_job_id,
                sync_project=False,
            )
        console.print_json(data=job)
    elif action == "attach":
        external_benchmarks.attach_detached_job(state.baseline_host, selected_job_id)
    elif action == "stop":
        external_benchmarks.stop_detached_job(state.baseline_host, selected_job_id)
        console.print(f"[yellow]Stopped {selected_job_id}[/yellow]")
    elif action == "prune":
        if _ask_yes_no(console, "Prune unused Docker images/volumes on the VM?", True):
            console.print(external_benchmarks.prune_remote_docker(state.baseline_host))


def _render_fleet_grid(status: fleet.FleetStatus) -> Panel:
    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Host")
    table.add_column("Job")
    table.add_column("State")
    table.add_column("Done/Total", justify="right")
    table.add_column("Useful", justify="right")
    table.add_column("Current case")
    for hj in status.hosts:
        payload = hj.last_status_payload or {}
        total = len(hj.cases)
        done = int(payload.get("completed") or 0)
        useful = int(payload.get("useful_findings") or 0)
        current = str(payload.get("current_case") or "-")[:48]
        state_style = {
            "running": "[green]running[/green]",
            "completed": "[bold green]completed[/bold green]",
            "failed": "[red]failed[/red]",
            "unreachable": "[red]unreachable[/red]",
            "stopped": "[yellow]stopped[/yellow]",
            "pending": "[dim]pending[/dim]",
            "dry_run": "[blue]dry_run[/blue]",
            "skipped": "[dim]skipped[/dim]",
        }.get(hj.status, hj.status)
        table.add_row(hj.baseline_host, hj.job_id[-24:] or "-", state_style, f"{done}/{total}", str(useful), current)
    agg = status.aggregate
    summary = (
        f"[bold]Aggregate[/bold]  "
        f"cases {agg.get('cases_completed', 0)}/{agg.get('cases_total', 0)}  "
        f"useful {agg.get('useful_findings', 0)}  "
        f"cost ${agg.get('estimated_cost_usd', 0):.4f}  "
        f"tokens {agg.get('total_tokens', 0)}"
    )
    return Panel(Group(table, Text.from_markup(summary)), title=f"Fleet {status.distributed_job_id}", border_style="cyan")


def _fleet_configure_hosts(console: Console, state: DashboardState) -> None:
    persisted = fleet.load_provisioned_hosts()
    if persisted and not state.baseline_hosts:
        console.print(
            f"[green]Loaded {len(persisted)} host(s) from {fleet.FLEET_HOSTS_FILE} "
            "(written by deploy_fleet.yml).[/green]"
        )
        state.baseline_hosts = list(persisted)
    base_default = state.baseline_hosts or persisted or list(fleet.DEFAULT_FLEET_HOSTS)
    default = ",".join(base_default) if base_default else ""
    raw = _ask(console, "Fleet hosts (comma-separated)", default)
    parsed = fleet.parse_hosts_arg(raw)
    if not parsed:
        console.print("[red]No hosts parsed; keeping previous list.[/red]")
        return
    state.baseline_hosts = parsed
    console.print(f"[green]Fleet configured with {len(parsed)} host(s).[/green]")


def _fleet_pick_cases(console: Console, state: DashboardState, suite: str, repo: str) -> list[str]:
    """Interactive helper: pick cases for a distributed run via auto-discover, file, or inline."""
    cache_path = Path("output/baselines") / f"{suite}_all_cases.txt"
    cache_count = 0
    if cache_path.exists():
        cache_count = sum(1 for line in cache_path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#"))

    source = _select_choice(
        console,
        f"Cases source ({suite})",
        [
            ("all_remote", f"Auto-discover ALL cases from one fleet VM (recommended)", "all_remote"),
            ("cached", f"Use cached file {cache_path} ({cache_count} cases)" if cache_count else "Use cached file (none yet)", "cached"),
            ("file", "Custom file path (one case_id per line)", "file"),
            ("inline", "Inline (comma-separated)", "inline"),
        ],
        "all_remote" if state.effective_hosts else "cached",
    )

    cases: list[str] = []
    if source == "all_remote":
        if not state.effective_hosts:
            console.print("[red]Need at least one fleet SSH host configured.[/red]")
            return []
        host = state.effective_hosts[0]
        with console.status(f"[cyan]Discovering {suite} cases from {host}...[/cyan]"):
            try:
                cases = fleet.discover_cases_remote(host=host, suite=suite, remote_repo=repo)
            except Exception as exc:
                console.print(f"[red]Discovery failed:[/red] {exc}")
                return []
        if cases:
            fleet.write_cases_file(cases, cache_path)
            console.print(f"[green]Discovered {len(cases)} case(s); cached to {cache_path}.[/green]")
    elif source == "cached":
        if not cache_path.exists():
            console.print(f"[yellow]No cache at {cache_path}. Run 'Auto-discover' once first.[/yellow]")
            return []
        cases = fleet.load_cases_from_file(cache_path)
    elif source == "file":
        raw = _ask(console, "Path to cases file", "")
        if not raw:
            return []
        cases = fleet.load_cases_from_file(Path(raw))
    elif source == "inline":
        raw = _ask(console, "Cases (comma-separated)", "")
        cases = [c.strip() for c in raw.split(",") if c.strip()]

    if not cases:
        console.print("[yellow]Empty case list.[/yellow]")
        return []

    if _ask_yes_no(console, f"Apply a regex filter on {len(cases)} cases?", False):
        import re
        pattern = _ask(console, "Regex (matches case_id)", ".*")
        try:
            rx = re.compile(pattern)
        except re.error as exc:
            console.print(f"[red]Invalid regex:[/red] {exc}")
            return cases
        filtered = [c for c in cases if rx.search(c)]
        console.print(f"[dim]Filter kept {len(filtered)} / {len(cases)} cases.[/dim]")
        cases = filtered

    if _ask_yes_no(console, f"Exclude families known to be slow (ofbiz, activemq)?", False):
        cases = [c for c in cases if not any(c.startswith(prefix) for prefix in ("ofbiz/", "activemq/"))]
        console.print(f"[dim]After exclusion: {len(cases)} case(s).[/dim]")

    return cases


def _fleet_start_distributed(console: Console, state: DashboardState) -> None:
    hosts = state.effective_hosts
    if len(hosts) < 1:
        console.print("[red]Configure fleet hosts first (option Configure hosts).[/red]")
        return
    suite = _select_choice(
        console,
        "External suite",
        [(name, f"Use {name}", name) for name in external_benchmarks.SUPPORTED_SUITES],
        state.external_suite,
    )
    repo = _ask(console, "Remote repo path", EXTERNAL_REPOS.get(suite, ("", state.external_repo))[1])
    cases = _fleet_pick_cases(console, state, suite, repo)
    if not cases:
        console.print("[red]No cases supplied. Aborting.[/red]")
        return
    console.print(f"[green]{len(cases)} case(s) selected -> {len(hosts)} fleet host(s) (~{len(cases) // max(1, len(hosts))} cases each).[/green]")
    state.external_context_mode = _select_choice(
        console,
        "External context mode",
        [
            ("Blind network only", "Target and exposed service only; no case id or CVE label", "blind"),
            ("Benchmark-informed", "Include benchmark case id and vulnerability/CVE label, but no repo oracle", "informed"),
        ],
        state.external_context_mode,
    )
    strategy = _select_choice(
        console,
        "Shard strategy",
        [(s, f"Use {s}", s) for s in fleet.SHARD_STRATEGIES],
        "round-robin",
    )
    dry_run = _ask_yes_no(console, "Dry-run (no SSH dispatch)?", False)
    with console.status(f"[cyan]Sharding {len(cases)} cases across {len(hosts)} host(s)...[/cyan]"):
        job = fleet.start_distributed_job(
            hosts=hosts,
            suite=suite,
            cases=cases,
            repo=Path(repo),
            shard_strategy=strategy,
            dry_run=dry_run,
            model=state.model,
            max_turns=state.max_turns,
            context_mode=state.external_context_mode,
        )
    state.active_distributed_job_id = job.distributed_job_id
    state.external_suite = suite
    state.external_repo = repo
    console.print(f"[green]Distributed job started:[/green] {job.distributed_job_id}")
    console.print(f"[dim]Shards:[/dim]")
    for hj in job.host_jobs:
        console.print(f"  {hj.baseline_host}: {len(hj.cases)} case(s) -> job_id={hj.job_id or '-'} status={hj.status}")


def _fleet_monitor(console: Console, state: DashboardState) -> None:
    if not state.active_distributed_job_id:
        console.print("[red]No active distributed job. Start one first.[/red]")
        return
    job_id = state.active_distributed_job_id
    console.print(f"[cyan]Monitoring {job_id} — press Ctrl+C to stop.[/cyan]")
    try:
        with Live(_render_fleet_grid(fleet.fleet_status(job_id)), console=console, refresh_per_second=2) as live:
            while True:
                time.sleep(5)
                try:
                    status = fleet.fleet_status(job_id)
                except Exception as exc:
                    _push_log(state, f"fleet_status error: {exc}")
                    continue
                live.update(_render_fleet_grid(status))
                if all(hj.status in {"completed", "failed", "stopped", "skipped", "dry_run"} for hj in status.hosts):
                    break
    except KeyboardInterrupt:
        pass


def _fleet_stop_all(console: Console, state: DashboardState) -> None:
    if not state.active_distributed_job_id:
        console.print("[red]No active distributed job.[/red]")
        return
    if not _ask_yes_no(console, f"Stop all hosts of {state.active_distributed_job_id}?", False):
        return
    outcomes = fleet.fleet_stop(state.active_distributed_job_id)
    console.print_json(data=outcomes)


def _fleet_fetch_all(console: Console, state: DashboardState) -> None:
    if not state.active_distributed_job_id:
        console.print("[red]No active distributed job.[/red]")
        return
    with console.status("[cyan]Fetching per-host results and merging...[/cyan]"):
        merged = fleet.fleet_fetch(state.active_distributed_job_id)
    console.print(f"[green]Distributed summary:[/green] {merged}")


def _fleet_select_existing(console: Console, state: DashboardState) -> None:
    """List distributed jobs from BOTH the filesystem and the SQLite store.

    The filesystem source is the authoritative one (has full host_jobs),
    but the SQLite store is a robust fallback when the TUI was launched
    with a stale cwd or a different copy of the project.
    """
    fs_jobs = fleet.list_distributed_jobs()
    db_jobs = []
    try:
        db_jobs = store.list_distributed_jobs()
    except Exception as exc:
        console.print(f"[dim]DB lookup skipped: {exc}[/dim]")

    by_id: dict[str, dict] = {}
    for entry in fs_jobs:
        by_id[entry["distributed_job_id"]] = {
            "source": "fs",
            "suite": entry.get("suite") or "",
            "cases_total": entry.get("cases_total") or 0,
            "hosts": entry.get("hosts") or [],
            "status": "",
        }
    for entry in db_jobs:
        jid = entry.get("distributed_job_id")
        if not jid:
            continue
        merged = by_id.get(jid, {})
        merged.setdefault("source", "db")
        if merged.get("source") == "fs" and entry.get("source") != "fs":
            merged["source"] = "fs+db"
        merged["suite"] = merged.get("suite") or (entry.get("suite") or "")
        merged["cases_total"] = merged.get("cases_total") or entry.get("cases_total") or 0
        merged["status"] = entry.get("status") or merged.get("status", "")
        merged["useful"] = int(entry.get("useful") or 0)
        merged["run_count"] = int(entry.get("run_count") or 0)
        by_id[jid] = merged

    if not by_id:
        console.print(f"[yellow]No distributed jobs found in {fleet.DEFAULT_FLEET_OUTPUT} or {store.DEFAULT_DB_PATH}.[/yellow]")
        return

    options = []
    for jid, entry in sorted(by_id.items(), reverse=True):
        suffix = []
        if entry.get("status"):
            suffix.append(f"status={entry['status']}")
        if entry.get("run_count"):
            suffix.append(f"runs={entry['run_count']}")
        if entry.get("useful"):
            suffix.append(f"useful={entry['useful']}")
        suffix.append(f"src={entry['source']}")
        desc = f"suite={entry['suite']} cases={entry['cases_total']}  " + "  ".join(suffix)
        options.append((jid[-30:], desc, jid))
    options.append(("[cancel]", "Keep current selection", None))
    chosen = _select_choice(console, f"Pick a distributed job ({len(by_id)} found)", options, state.active_distributed_job_id)
    if chosen:
        state.active_distributed_job_id = chosen
        console.print(f"[green]Active job set to {chosen}.[/green]")


FLEET_ACTIONS = [
    ("provision", "Provision the fleet via Ansible (choose size + storage)"),
    ("configure", "Configure fleet SSH hosts (current: dynamic)"),
    ("prepare", "Sync project + prepare environment on all fleet hosts"),
    ("env", "Deploy API keys (.env) on all fleet hosts"),
    ("start", "Start a distributed run on the fleet"),
    ("monitor", "Live monitor the active distributed job"),
    ("stop", "Stop all hosts of the active distributed job"),
    ("fetch", "Fetch all results + merge into distributed_summary.json"),
    ("select", "Select an existing distributed job"),
    ("back", "Back to main menu"),
]


def _fleet_deploy_env(console: Console, state: DashboardState) -> None:
    import os
    hosts = state.effective_hosts
    if not hosts:
        console.print("[red]Configure fleet hosts first.[/red]")
        return

    source = _select_choice(
        console,
        "API key source",
        [
            ("env", "From shell env var (e.g. MINIMAX_API_KEY)", "env"),
            ("prompt", "Type the key now (hidden input, not echoed)", "prompt"),
            ("file", "Read from a local file path", "file"),
        ],
        "env",
    )

    api_key = None
    if source == "env":
        key_env_name = _ask(console, "Env var holding the API key", "MINIMAX_API_KEY")
        api_key = os.environ.get(key_env_name)
        if not api_key:
            console.print(f"[red]{key_env_name} is not set in your shell.[/red]")
            return
    elif source == "prompt":
        api_key = getpass.getpass("MiniMax API key (hidden): ").strip()
        if not api_key:
            console.print("[red]Empty key, aborting.[/red]")
            return
    elif source == "file":
        raw = _ask(console, "Path to file containing only the key", "")
        if not raw:
            return
        try:
            api_key = Path(raw).expanduser().read_text(encoding="utf-8").strip()
        except OSError as exc:
            console.print(f"[red]Cannot read file:[/red] {exc}")
            return
        if not api_key:
            console.print("[red]File is empty, aborting.[/red]")
            return

    with console.status(f"[cyan]Pushing .env on {len(hosts)} host(s)...[/cyan]"):
        outcomes = fleet.deploy_env_on_fleet(hosts, api_key=api_key)
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Host")
    table.add_column("Status")
    for host, status in outcomes.items():
        style = "green" if status == "ok" else "red"
        table.add_row(host, f"[{style}]{status}[/{style}]")
    console.print(table)


def _fleet_provision(console: Console, state: DashboardState) -> None:
    """Build a custom fleet plan and run deploy_fleet.yml with --extra-vars."""
    size_raw = _ask(console, "Number of fleet VMs", "4")
    try:
        size = max(1, int(size_raw))
    except ValueError:
        console.print("[red]Invalid number; aborting.[/red]")
        return
    base_vmid_raw = _ask(console, "Base VMID (will use base, base+1, ...)", "1000")
    try:
        base_vmid = int(base_vmid_raw)
    except ValueError:
        console.print("[red]Invalid base VMID; aborting.[/red]")
        return
    base_bench_ip_raw = _ask(console, "Base benchmark IPv4 (will increment last octet)", "192.168.100.240")
    bench_parts = base_bench_ip_raw.split(".")
    if len(bench_parts) != 4 or not bench_parts[-1].isdigit():
        console.print("[red]Invalid IPv4; aborting.[/red]")
        return
    bench_prefix = ".".join(bench_parts[:3]) + "."
    bench_start = int(bench_parts[-1])
    hostname_prefix = _ask(console, "Hostname prefix", "nato-baseline-")
    storage = _ask(console, "Default Proxmox storage pool (Enter = group_vars default)", "")
    per_host_storage = _ask_yes_no(console, "Override storage per VM individually?", False)

    fleet_list = []
    for index in range(size):
        item = {
            "vmid": base_vmid + index,
            "hostname": f"{hostname_prefix}{index + 1}",
            "benchmark_ip": f"{bench_prefix}{bench_start + index}",
        }
        if per_host_storage:
            override = _ask(console, f"Storage for VM {item['hostname']} (vmid={item['vmid']})", storage or "")
            if override:
                item["storage"] = override
        elif storage:
            item["storage"] = storage
        fleet_list.append(item)

    table = Table(show_header=True, header_style="bold magenta", expand=False)
    table.add_column("VMID", justify="right")
    table.add_column("Hostname")
    table.add_column("Benchmark IP")
    table.add_column("Storage")
    for item in fleet_list:
        table.add_row(str(item["vmid"]), item["hostname"], item["benchmark_ip"], item.get("storage", "[dim]default[/dim]"))
    console.print(table)

    if not _ask_yes_no(console, f"Provision these {size} VM(s) now? (runs ansible-playbook deploy_fleet.yml)", False):
        console.print("[yellow]Cancelled.[/yellow]")
        return

    try:
        deploy.deploy_fleet(fleet_list=fleet_list)
    except Exception as exc:
        console.print(f"[red]Ansible run failed:[/red] {exc}")
        return
    persisted = fleet.load_provisioned_hosts()
    if persisted:
        state.baseline_hosts = persisted
        console.print(f"[green]Auto-loaded {len(persisted)} mgmt host(s) from {fleet.FLEET_HOSTS_FILE}:[/green]")
        for host in persisted:
            console.print(f"  {host}")
    else:
        console.print(
            f"[yellow]No fleet_hosts.json found at {fleet.FLEET_HOSTS_FILE}. "
            "Run 'Configure fleet SSH hosts' manually with the IPs printed by Ansible.[/yellow]"
        )


def _fleet_prepare(console: Console, state: DashboardState) -> None:
    hosts = state.effective_hosts
    if not hosts:
        console.print("[red]Configure fleet hosts first.[/red]")
        return
    # Clone every suite that has a known upstream URL (vulhub + autopenbench);
    # the default would only clone vulhub, leaving autopenbench discovery broken.
    suites = tuple(external_benchmarks.REMOTE_REPO_URLS)
    with console.status(f"[cyan]Syncing project + preparing env on {len(hosts)} host(s)...[/cyan]"):
        outcomes = fleet.fleet_prepare(hosts, suites=suites)
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Host")
    table.add_column("Status")
    for host, status in outcomes.items():
        style = "green" if status == "ok" else "red"
        table.add_row(host, f"[{style}]{status}[/{style}]")
    console.print(table)


def _manage_fleet(console: Console, state: DashboardState) -> None:
    while True:
        selected = _select_choice(
            console,
            f"Fleet management (active: {state.active_distributed_job_id or '-'}, hosts: {len(state.effective_hosts)})",
            [(key, desc, key) for key, desc in FLEET_ACTIONS],
            "configure",
        )
        if selected == "back":
            return
        if selected == "provision":
            _fleet_provision(console, state)
        elif selected == "configure":
            _fleet_configure_hosts(console, state)
        elif selected == "prepare":
            _fleet_prepare(console, state)
        elif selected == "env":
            _fleet_deploy_env(console, state)
        elif selected == "start":
            _fleet_start_distributed(console, state)
        elif selected == "monitor":
            _fleet_monitor(console, state)
        elif selected == "stop":
            _fleet_stop_all(console, state)
        elif selected == "fetch":
            _fleet_fetch_all(console, state)
        elif selected == "select":
            _fleet_select_existing(console, state)
        console.input("\n[dim]Press Enter to continue...[/dim]")


HISTORY_ACTIONS = [
    ("list", "List distributed jobs"),
    ("breakdown", "Outcome breakdown (counts, cost, tokens)"),
    ("runs", "Runs of a selected job (last 50)"),
    ("import", "Import existing output/external_benchmarks/ tree"),
    ("query", "Run a custom SQL SELECT"),
    ("back", "Back to main menu"),
]


def _history_list_jobs(console: Console) -> None:
    jobs = store.list_distributed_jobs()
    if not jobs:
        console.print("[yellow]No distributed jobs recorded yet.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("distributed_job_id")
    table.add_column("suite")
    table.add_column("strategy")
    table.add_column("cases", justify="right")
    table.add_column("runs", justify="right")
    table.add_column("useful", justify="right")
    table.add_column("cost ($)", justify="right")
    table.add_column("status")
    for job in jobs:
        table.add_row(
            str(job.get("distributed_job_id"))[-32:],
            str(job.get("suite") or ""),
            str(job.get("shard_strategy") or ""),
            str(job.get("cases_total") or 0),
            str(int(job.get("run_count") or 0)),
            str(int(job.get("useful") or 0)),
            f"{float(job.get('total_cost') or 0):.4f}",
            str(job.get("status") or "-"),
        )
    console.print(table)


def _history_breakdown(console: Console) -> None:
    rows = store.outcome_breakdown()
    if not rows:
        console.print("[yellow]No runs in the store.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("outcome")
    table.add_column("count", justify="right")
    table.add_column("cost ($)", justify="right")
    table.add_column("tokens", justify="right")
    table.add_column("avg duration (s)", justify="right")
    for row in rows:
        table.add_row(
            str(row.get("outcome") or ""),
            str(int(row.get("count") or 0)),
            f"{float(row.get('cost_usd') or 0):.4f}",
            str(int(row.get("tokens") or 0)),
            f"{float(row.get('avg_duration_seconds') or 0):.1f}",
        )
    console.print(table)


def _history_runs(console: Console) -> None:
    job_id = _ask(console, "distributed_job_id (Enter = all)", "")
    rows = store.list_runs(distributed_job_id=job_id or None, limit=50)
    if not rows:
        console.print("[yellow]No matching runs.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("case_id")
    table.add_column("host")
    table.add_column("outcome")
    table.add_column("blocked_by")
    table.add_column("cost ($)", justify="right")
    table.add_column("tokens", justify="right")
    table.add_column("duration", justify="right")
    for row in rows:
        table.add_row(
            str(row.get("case_id") or "")[:60],
            str(row.get("baseline_host") or "")[:24],
            str(row.get("outcome") or ""),
            str(row.get("blocked_by") or ""),
            f"{float(row.get('estimated_cost_usd') or 0):.4f}",
            str(int(row.get("total_tokens") or 0)),
            f"{float(row.get('duration_seconds') or 0):.0f}s",
        )
    console.print(table)


def _history_import(console: Console) -> None:
    root = _ask(console, "Root directory to import", str(external_benchmarks.DEFAULT_OUTPUT_DIR))
    label = _ask(console, "distributed_job_id label", "legacy-import")
    if not _ask_yes_no(console, f"Import all result.json under {root} into the store?", False):
        return
    count = store.import_existing_external_runs(Path(root), distributed_job_id=label)
    console.print(f"[green]Imported {count} run(s) under label {label}.[/green]")


def _history_query(console: Console) -> None:
    console.print("[dim]Tables: distributed_jobs, host_jobs, runs[/dim]")
    sql = _ask(console, "SQL SELECT", "SELECT outcome, COUNT(*) c FROM runs GROUP BY outcome ORDER BY c DESC")
    if not sql.strip().lower().startswith("select"):
        console.print("[red]Only SELECT is allowed in this view.[/red]")
        return
    try:
        rows = store.run_sql(sql)
    except Exception as exc:
        console.print(f"[red]SQL error:[/red] {exc}")
        return
    if not rows:
        console.print("[yellow]No rows.[/yellow]")
        return
    table = Table(show_header=True, header_style="bold cyan", expand=True)
    for col in rows[0].keys():
        table.add_column(col)
    for row in rows[:200]:
        table.add_row(*[str(row.get(col, "")) for col in rows[0].keys()])
    console.print(table)
    if len(rows) > 200:
        console.print(f"[dim]({len(rows) - 200} more rows truncated)[/dim]")


def _manage_history(console: Console, state: DashboardState) -> None:
    store.init_db()  # ensure schema exists before showing
    while True:
        choice = _select_choice(
            console,
            f"History (DB: {store.DEFAULT_DB_PATH})",
            [(key, desc, key) for key, desc in HISTORY_ACTIONS],
            "list",
        )
        if choice == "back":
            return
        if choice == "list":
            _history_list_jobs(console)
        elif choice == "breakdown":
            _history_breakdown(console)
        elif choice == "runs":
            _history_runs(console)
        elif choice == "import":
            _history_import(console)
        elif choice == "query":
            _history_query(console)
        console.input("\n[dim]Press Enter to continue...[/dim]")


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
            elif choice == "j":
                _manage_external_jobs(console, state)
            elif choice == "f":
                _manage_fleet(console, state)
            elif choice == "h":
                _manage_history(console, state)
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
