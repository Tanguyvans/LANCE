"""NATO Smart City IoT — Streamlit pentest orchestrator UI.

Run with:
    streamlit run src/ui/app.py --server.port 8501
"""
from __future__ import annotations

import json
import queue
import re
import sys
import threading
import time
from pathlib import Path

import streamlit as st

# Ensure project root is on sys.path when launched directly
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── Constants ────────────────────────────────────────────────────────────────

OPENROUTER_MODELS = [
    "anthropic/claude-sonnet-4",
    "anthropic/claude-opus-4",
    "google/gemini-2.5-flash-preview",
    "google/gemini-2.5-pro-preview",
    "openai/gpt-4o",
    "meta-llama/llama-3.3-70b-instruct",
    "deepseek/deepseek-r1",
]

PHASE_NAMES = {
    1: "Graph Analysis",
    2: "Recon",
    3: "Vuln Analysis",
    4: "Exploitation",
    5: "Report",
}

EVENT_COLORS = {
    "tool_call":   "#f0ad4e",
    "tool_result": "#5bc0de",
    "text_chunk":  "#e8e8e8",
    "phase_start": "#5cb85c",
    "phase_done":  "#5cb85c",
    "pipeline_start": "#337ab7",
    "pipeline_done":  "#337ab7",
}

# ── Page config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="NATO IoT Pentest",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Session state init ────────────────────────────────────────────────────────

def _init_state():
    defaults = {
        "running":    False,
        "events":     [],
        "hosts":      {},       # ip -> {services, phase}
        "phases":     {},       # phase_num -> "pending"|"running"|"done"|"failed"
        "cost":       0.0,
        "run_dir":    None,
        "eq":         queue.Queue(),
        "thread":     None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

_init_state()

# ── Pipeline thread ───────────────────────────────────────────────────────────

def _pipeline_thread(provider_name: str, model: str, phases: list[int] | None,
                     scenario_id: int | None, eq: queue.Queue):
    try:
        from src.agent.provider import LLMProvider
        from src.agent.pipeline import Pipeline

        provider = LLMProvider(provider=provider_name, model=model)
        pipeline = Pipeline(provider=provider, phases=phases or None, scenario_id=scenario_id)
        pipeline.run(stream_callback=eq.put)
    except Exception as exc:
        eq.put({"type": "error", "message": str(exc)})


# ── Nmap result parser ────────────────────────────────────────────────────────

def _parse_nmap_result(raw: str) -> dict[str, dict]:
    """Extract {ip: {ports: [...], hostnames: [...]}} from nmap text output."""
    hosts: dict[str, dict] = {}
    current_ip = None
    for line in raw.splitlines():
        ip_match = re.search(r"Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?", line)
        if ip_match:
            hostname = ip_match.group(1) or ""
            current_ip = ip_match.group(2)
            hosts[current_ip] = {"hostname": hostname, "ports": []}
            continue
        if current_ip:
            port_match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", line.strip())
            if port_match:
                hosts[current_ip]["ports"].append(
                    f"{port_match.group(1)}/{port_match.group(2)} {port_match.group(3)}"
                )
    return hosts


# ── Event processing ──────────────────────────────────────────────────────────

def _drain_queue():
    """Drain pending events from queue into session_state."""
    drained = False
    while not st.session_state.eq.empty():
        try:
            event = st.session_state.eq.get_nowait()
        except queue.Empty:
            break
        st.session_state.events.append(event)
        _process_event(event)
        drained = True
    return drained


def _process_event(event: dict):
    t = event.get("type")

    if t == "phase_start":
        st.session_state.phases[event["phase"]] = "running"

    elif t == "phase_done":
        st.session_state.phases[event["phase"]] = (
            "done" if event["status"] == "completed" else "failed"
        )
        st.session_state.cost += event.get("cost_usd", 0)

    elif t == "pipeline_done":
        st.session_state.running = False
        st.session_state.run_dir = event.get("run_dir")
        st.session_state.cost = event.get("total_cost_usd", st.session_state.cost)

    elif t == "error":
        st.session_state.running = False

    elif t == "tool_result" and event.get("name") == "nmap_scan":
        parsed = _parse_nmap_result(event.get("result", ""))
        for ip, info in parsed.items():
            if ip not in st.session_state.hosts:
                st.session_state.hosts[ip] = info
            else:
                # merge ports
                existing = set(st.session_state.hosts[ip]["ports"])
                existing.update(info["ports"])
                st.session_state.hosts[ip]["ports"] = sorted(existing)


# ── Sidebar ───────────────────────────────────────────────────────────────────

def _sidebar():
    st.sidebar.title("🛡️ NATO IoT Pentest")
    st.sidebar.markdown("---")

    st.sidebar.subheader("Provider")
    model = st.sidebar.selectbox("Model", OPENROUTER_MODELS, index=0)

    st.sidebar.subheader("Phases")
    all_phases = st.sidebar.checkbox("All phases", value=True)
    selected_phases = None
    if not all_phases:
        selected_phases = [
            p for p in PHASE_NAMES
            if st.sidebar.checkbox(f"Phase {p}: {PHASE_NAMES[p]}", value=True)
        ]
        if not selected_phases:
            selected_phases = None

    st.sidebar.subheader("Benchmark scenario")
    scenario_opt = st.sidebar.selectbox(
        "Scenario (optional)",
        ["None", "S1 — Réseau plat", "S2 — Gateway exposée", "S3 — NATO Lab",
         "S4 — Réseau segmenté", "S5 — Smart Building", "S6 — Domotique", "S7 — Edge-Cloud"],
        index=0,
    )
    scenario_id = None if scenario_opt == "None" else int(scenario_opt[1])

    st.sidebar.markdown("---")
    can_run = not st.session_state.running
    run_clicked = st.sidebar.button(
        "▶ Lancer le pentest",
        disabled=not can_run,
        use_container_width=True,
        type="primary",
    )
    if st.sidebar.button("🗑 Reset", disabled=st.session_state.running, use_container_width=True):
        _init_state()
        for k in ["events", "hosts", "phases", "cost", "run_dir", "running"]:
            del st.session_state[k]
        st.rerun()

    # Cost display
    if st.session_state.cost > 0:
        st.sidebar.markdown("---")
        st.sidebar.metric("Coût estimé", f"${st.session_state.cost:.4f}")

    return run_clicked, "openrouter", model, selected_phases, scenario_id


# ── Phase progress bar ────────────────────────────────────────────────────────

def _render_phases():
    cols = st.columns(len(PHASE_NAMES))
    icons = {"pending": "⬜", "running": "🔄", "done": "✅", "failed": "❌"}
    for col, (num, name) in zip(cols, PHASE_NAMES.items()):
        state = st.session_state.phases.get(num, "pending")
        icon = icons[state]
        col.markdown(
            f"<div style='text-align:center; padding:8px; border-radius:6px; "
            f"background:{'#1e3a1e' if state=='done' else '#3a1e1e' if state=='failed' else '#1e2a3a' if state=='running' else '#1e1e2e'}'>"
            f"<b>{icon} Phase {num}</b><br/><small>{name}</small></div>",
            unsafe_allow_html=True,
        )


# ── Discovered hosts table ────────────────────────────────────────────────────

def _render_hosts():
    if not st.session_state.hosts:
        st.info("Aucun hôte découvert pour l'instant.")
        return
    rows = []
    for ip, info in sorted(st.session_state.hosts.items()):
        rows.append({
            "IP": ip,
            "Hostname": info.get("hostname", ""),
            "Services": ", ".join(info.get("ports", [])) or "—",
        })
    st.dataframe(rows, use_container_width=True, hide_index=True)


# ── Live event log ────────────────────────────────────────────────────────────

def _render_log():
    if not st.session_state.events:
        st.markdown("*En attente du démarrage...*")
        return

    # Show last 80 events to avoid performance issues
    events_to_show = st.session_state.events[-80:]
    lines = []
    for ev in events_to_show:
        t = ev.get("type", "")
        color = EVENT_COLORS.get(t, "#aaaaaa")

        if t == "phase_start":
            lines.append(
                f"<div style='color:{color}; margin-top:12px;'>"
                f"<b>━━ Phase {ev['phase']}: {ev['name'].upper()} ━━</b></div>"
            )
        elif t == "phase_done":
            status_icon = "✅" if ev["status"] == "completed" else "❌"
            lines.append(
                f"<div style='color:{color};'>{status_icon} Phase {ev['phase']} terminée "
                f"— {ev['turns']} tours, ${ev['cost_usd']:.4f}</div>"
            )
        elif t == "tool_call":
            args_str = json.dumps(ev.get("args", {}), ensure_ascii=False)[:120]
            lines.append(
                f"<div style='color:{color}; padding-left:16px;'>"
                f"🔧 <b>{ev['name']}</b>({args_str})</div>"
            )
        elif t == "tool_result":
            result_preview = ev.get("result", "")[:200].replace("<", "&lt;").replace(">", "&gt;")
            lines.append(
                f"<div style='color:{color}; padding-left:16px; font-size:0.85em;'>"
                f"↩ {result_preview}</div>"
            )
        elif t == "text_chunk":
            text = ev.get("text", "").replace("<", "&lt;").replace(">", "&gt;")
            lines.append(
                f"<div style='color:{color}; padding:4px 0;'>{text}</div>"
            )
        elif t == "pipeline_start":
            lines.append(
                f"<div style='color:{color};'><b>🚀 Pipeline démarré</b> — "
                f"{ev['device_count']} devices, {ev['link_count']} liens, "
                f"{ev['cve_count']} CVEs</div>"
            )
        elif t == "pipeline_done":
            lines.append(
                f"<div style='color:{color};'><b>🏁 Pipeline terminé</b> — "
                f"coût total ${ev.get('total_cost_usd', 0):.4f}</div>"
            )
        elif t == "error":
            lines.append(
                f"<div style='color:#ff4444;'><b>❌ Erreur:</b> {ev.get('message', '')}</div>"
            )

    st.markdown(
        f"<div style='height:400px; overflow-y:auto; background:#0e1117; "
        f"padding:12px; border-radius:8px; font-family:monospace; font-size:0.85em;'>"
        + "".join(lines)
        + "</div>",
        unsafe_allow_html=True,
    )


# ── Deliverables viewer ───────────────────────────────────────────────────────

def _render_deliverables():
    run_dir = st.session_state.run_dir
    if not run_dir:
        st.info("Les deliverables seront disponibles à la fin du pentest.")
        return
    path = Path(run_dir)
    files = sorted(f for f in path.glob("*") if f.suffix in (".md", ".json"))
    if not files:
        st.info("Aucun deliverable généré pour l'instant.")
        return
    selected = st.selectbox("Fichier", [f.name for f in files])
    content = (path / selected).read_text(encoding="utf-8")
    if selected.endswith(".json"):
        try:
            st.json(json.loads(content))
        except json.JSONDecodeError:
            st.code(content)
    else:
        st.markdown(content)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    run_clicked, provider_name, model, selected_phases, scenario_id = _sidebar()

    # Start pipeline on button click
    if run_clicked and not st.session_state.running:
        # Reset state for new run
        st.session_state.events = []
        st.session_state.hosts = {}
        st.session_state.phases = {p: "pending" for p in PHASE_NAMES}
        st.session_state.cost = 0.0
        st.session_state.run_dir = None
        st.session_state.eq = queue.Queue()
        st.session_state.running = True

        t = threading.Thread(
            target=_pipeline_thread,
            args=(provider_name, model, selected_phases, scenario_id, st.session_state.eq),
            daemon=True,
        )
        st.session_state.thread = t
        t.start()

    # Drain events from running pipeline
    if st.session_state.running:
        _drain_queue()

    # ── Layout ───────────────────────────────────────────────────────────────
    st.markdown("## 🛡️ NATO Smart City IoT — Pentest Orchestrator")

    # Phase progress
    _render_phases()
    st.markdown("---")

    # Two-column layout: log | hosts
    col_log, col_hosts = st.columns([3, 2])

    with col_log:
        st.subheader("📡 Live output")
        _render_log()

    with col_hosts:
        st.subheader("🖥️ Hôtes découverts")
        _render_hosts()

    st.markdown("---")

    # Deliverables (only when done)
    if st.session_state.run_dir or not st.session_state.running:
        st.subheader("📄 Deliverables")
        _render_deliverables()

    # Auto-refresh while pipeline is running
    if st.session_state.running:
        time.sleep(0.4)
        st.rerun()


if __name__ == "__main__":
    main()
