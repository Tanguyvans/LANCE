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

from src.baselines import compare, deploy, install_tools, runner

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
MENU_ACTIONS = [
    ("1", "Configure"),
    ("2", "Deploy baseline VM"),
    ("3", "Setup CAI on baseline VM"),
    ("4", "Deploy benchmark scenario"),
    ("5", "Run CAI baseline with live remote status"),
    ("6", "Compare last/run directory"),
    ("7", "Full CAI pilot"),
    ("8", "Teardown benchmark scenario"),
    ("0", "Quit"),
]


@dataclass
class DashboardState:
    baseline_host: str = DEFAULT_BASELINE_HOST
    scenario_id: str = DEFAULT_SCENARIO
    scope: str = DEFAULT_SCOPE
    model: str = DEFAULT_MODEL
    max_turns: int = 40
    last_run_dir: Path | None = None
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
    suffix = f" [{default}]" if default else ""
    value = console.input(f"[bold cyan]{prompt}[/bold cyan]{suffix}: ").strip()
    return value or (default or "")


def _ask_yes_no(console: Console, prompt: str, default: bool = True) -> bool:
    label = "Y/n" if default else "y/N"
    value = console.input(f"[bold cyan]{prompt}[/bold cyan] [{label}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "o", "oui"}


def _push_log(state: DashboardState, message: str) -> None:
    state.logs.append(message)
    state.logs = state.logs[-10:]


def _render_header(state: DashboardState):
    table = Table.grid(expand=True)
    table.add_column(ratio=1)
    table.add_column(ratio=1)
    table.add_row("[bold]Baseline[/bold]", state.baseline_host)
    table.add_row("[bold]Scenario[/bold]", state.scenario_id)
    table.add_row("[bold]Scope[/bold]", state.scope)
    table.add_row("[bold]Model[/bold]", state.model)
    table.add_row("[bold]Max turns[/bold]", str(state.max_turns))
    table.add_row("[bold]Last run[/bold]", str(state.last_run_dir or "-"))
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


def _render_dashboard_shell(console: Console, state: DashboardState, selected: int) -> None:
    console.clear()
    console.print(Align.center("[bold cyan]NATO Smart City IoT[/bold cyan] [white]Baseline Terminal[/white]"))
    console.print(_render_header(state))
    console.print(_render_menu(selected))


def _select_action(console: Console, state: DashboardState, selected: int) -> tuple[str, int]:
    """Return (menu key, selected index), using arrows when stdin is interactive."""
    if not sys.stdin.isatty():
        choice = console.input("\n[bold cyan]Choice[/bold cyan]: ").strip()
        for index, (key, _) in enumerate(MENU_ACTIONS):
            if key == choice:
                return key, index
        return choice, selected

    while True:
        _render_dashboard_shell(console, state, selected)
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
    state.baseline_host = _ask(console, "Baseline SSH host", state.baseline_host)
    state.scenario_id = _ask(console, "Scenario id", state.scenario_id)
    state.scope = _ask(console, "CIDR scope", state.scope)
    state.model = _ask(console, "Model", state.model)
    turns = _ask(console, "Max turns per target", str(state.max_turns))
    try:
        state.max_turns = int(turns)
    except ValueError:
        console.print("[red]Invalid max turns; keeping previous value.[/red]")


def _setup_cai(console: Console, state: DashboardState) -> None:
    api_key = os.environ.get(install_tools.DEFAULT_API_KEY_ENV)
    if not api_key:
        console.print(f"[yellow]{install_tools.DEFAULT_API_KEY_ENV} is not set locally.[/yellow]")
        api_key = getpass.getpass("Paste MiniMax API key (hidden): ").strip()
    if not api_key:
        console.print("[red]No API key provided; setup cancelled.[/red]")
        return
    with console.status("[cyan]Installing/updating CAI adapter on baseline VM...[/cyan]"):
        install_tools.setup_cai(state.baseline_host, api_key, model=state.model)
    console.print("[green]CAI setup completed.[/green]")


def _deploy_scenario(console: Console, state: DashboardState) -> None:
    populate = _ask_yes_no(console, "Populate services after vulnerability injection?", True)
    verify = _ask_yes_no(console, "Run verification playbook after deployment?", False)
    deploy.deploy_scenario(state.scenario_id, populate=populate, verify=verify)
    console.print(f"[green]Scenario {state.scenario_id} deployed.[/green]")


def _run_cai_live(console: Console, state: DashboardState) -> None:
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

    def on_event(event: dict[str, Any]) -> None:
        name = event["event"]
        if name == "run_start":
            state.status = "Running"
            state.target_count = int(event["target_count"])
            progress.update(task_id, total=state.target_count)
            _push_log(state, f"Run started: {event['tool']} S{event['scenario_id']} -> {event['run_dir']}")
        elif name == "target_selected":
            target = event["target"]
            state.current_index = int(event["index"])
            state.current_target = f"{target['ip']} ({target['name']})"
            _push_log(state, f"Target {state.current_index}/{event['total']}: {target['ip']}")
        elif name == "target_start":
            target = event["target"]
            state.status = "Remote CAI running"
            _push_log(state, f"Started remote CAI on {target['ip']}")
        elif name == "target_heartbeat":
            target = event["target"]
            _push_log(state, f"{target['ip']} still running after {event['elapsed']}s")
        elif name == "target_finished":
            target = event["target"]
            _push_log(state, f"{target['ip']} finished in {event['elapsed']}s")
        elif name == "target_result_saved":
            progress.update(task_id, advance=1)
            _push_log(state, f"Saved {event['output']}")
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

    with Live(_render_live(state, progress), console=console, refresh_per_second=4) as live:
        def wrapped_event(event: dict[str, Any]) -> None:
            on_event(event)
            live.update(_render_live(state, progress))

        state.last_run_dir = runner.run_baseline(
            tool="cai",
            scenario_id=state.scenario_id,
            baseline_host=state.baseline_host,
            variant="A",
            scope=state.scope,
            max_turns=state.max_turns,
            model=state.model,
            event_callback=wrapped_event,
            quiet=True,
        )
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
    if _ask_yes_no(console, "Install/update CAI adapter first?", False):
        _setup_cai(console, state)
    _run_cai_live(console, state)
    _compare(console, state)


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
            elif choice == "2":
                with console.status("[cyan]Deploying baseline VM...[/cyan]"):
                    deploy.deploy_baseline_vm()
            elif choice == "3":
                _setup_cai(console, state)
            elif choice == "4":
                _deploy_scenario(console, state)
            elif choice == "5":
                _run_cai_live(console, state)
            elif choice == "6":
                _compare(console, state)
            elif choice == "7":
                _full_pilot(console, state)
            elif choice == "8":
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
