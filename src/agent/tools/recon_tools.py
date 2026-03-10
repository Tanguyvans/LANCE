"""Network reconnaissance tools — YAML-defined with Python handlers.

Subprocess tools (nmap, ssh-audit, curl, mosquitto_sub) are loaded from
YAML definitions in definitions/. Python-only tools (nvd_lookup) are
defined here and registered as handlers.

All subprocess tools return {stdout, stderr, return_code} as JSON.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess

from src.cve_lookup import query_nvd


def _run(cmd: list[str], timeout: int = 30) -> dict:
    """Run a command and return structured output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout}s: {shlex.join(cmd)}",
            "return_code": -1,
        }
    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": f"Command not found: {cmd[0]}",
            "return_code": -1,
        }


def nvd_lookup(query: str) -> str:
    """Search NIST NVD for known CVEs by CPE string or keyword."""
    api_key = os.environ.get("NVD_API_KEY")
    try:
        results = query_nvd(query, api_key)
        return json.dumps(
            [
                {
                    "cve_id": r.cve_id,
                    "description": r.description,
                    "cvss_score": r.cvss_score,
                    "severity": r.severity,
                    "attack_vector": r.attack_vector,
                }
                for r in results
            ]
        )
    except Exception as e:
        return json.dumps({"error": str(e)})


# ── Tool definitions (generated from YAML) ───────────────────────

def _load_recon_tools() -> list[dict]:
    """Load recon tools from YAML definitions, attach Python handlers."""
    from src.agent.tools.tool_loader import load_all_tools, register_python_handler

    tools = load_all_tools()
    register_python_handler(tools, "nvd_lookup", nvd_lookup)
    return tools


RECON_TOOLS = _load_recon_tools()
