"""Fact-only reconnaissance document; model prose never supplies inventory."""
import html


def cell(value):
    return html.escape(str(value)).replace("|", "&#124;").replace("\n", " ").replace("\r", " ")


def render_recon(projection: dict, progress: dict) -> str:
    if projection.get("source_issues") or not projection.get("devices"):
        raise ValueError("Recon observations are missing or invalid")
    if not progress.get("ready_to_save"):
        raise ValueError("Recon minimum evidence requirements are incomplete")
    lines = [
        "# Phase 2: Reconnaissance",
        "Source: recorded tool_calls.jsonl observations, rendered by the pipeline.",
        "## 1. Summary",
        f"Observed inventory entries: {len(projection['devices'])}.",
        "Minimum evidence requirements satisfied. This is not a claim of exhaustive "
        "network coverage or proof that unobserved services are absent. Failed probes "
        "remain failures, even when repeated attempts satisfy the execution contract.",
        "## 2. Discovered Services per Device",
        "| Device | IP | Open Ports | Key Services |",
        "|--------|----|------------|--------------|",
    ]
    for row in projection["devices"]:
        services = ", ".join(
            f"{s['service']}:{s['port']}/{s['protocol']} {s['version']}" for s in row["services"]
        ) or "none observed"
        ports = ",".join(map(str, row["open_ports"])) or "none observed (not proof of absence)"
        lines.append("| " + " | ".join(map(cell, [row.get("device") or "undocumented", row["ip"], ports, services])) + " |")
    lines += ["## 3. Key Findings", "These are observations, not vulnerability confirmations."]
    for row in projection["devices"]:
        for failure in row.get("failures", []):
            lines.append(f"- Failed probe on {cell(row['ip'])}: {cell(failure)}")
    for target in progress.get("targets", []):
        if target.get("failed_ports"):
            lines.append(f"- Incomplete observations on {cell(target['target'])}: failed ports {cell(target['failed_ports'])}.")
    lines.append("Raw results and attribution remain in tool_calls.jsonl; structured inventory remains in 02_recon_evidence.json. No model narrative is required to establish these facts.")
    return "\n\n".join(lines[:6]) + "\n\n" + "\n".join(lines[6:]) + "\n"
