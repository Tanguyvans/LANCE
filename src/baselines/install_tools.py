"""Install external baseline tools on the isolated baseline VM."""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
from pathlib import Path


DEFAULT_REMOTE_DIR = "/opt/baseline-tools"
DEFAULT_MODEL = "MiniMax-M2.7"
DEFAULT_TARGET_TIMEOUT_SECONDS = 240


CAI_ADAPTER = r"""#!/usr/bin/env bash
set -euo pipefail

VARIANT="A"
TARGET=""
SCOPE="192.168.100.0/24"
SCENARIO=""
MAX_TURNS="200"
MODEL="${CAI_MODEL:-MiniMax-M2.7}"
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --variant) VARIANT="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --scope) SCOPE="$2"; shift 2 ;;
    --scenario) SCENARIO="$2"; shift 2 ;;
    --max-turns) MAX_TURNS="$2"; shift 2 ;;
    --model) MODEL="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$TARGET" || -z "$OUTPUT" ]]; then
  echo "Usage: cai_run.sh --target IP_OR_CIDR --scenario N --scope CIDR --output PATH" >&2
  exit 2
fi

cd /opt/baseline-tools
source /opt/baseline-tools/venv/bin/activate
if [[ -f /opt/baseline-tools/.env ]]; then
  set -a
  source /opt/baseline-tools/.env
  set +a
fi

mkdir -p "$(dirname "$OUTPUT")" /opt/baseline-tools/logs
RAW="$(mktemp /opt/baseline-tools/logs/cai_${SCENARIO}_${VARIANT}_XXXXXX.txt)"
TARGET_TIMEOUT="${CAI_TARGET_TIMEOUT:-$(( MAX_TURNS * 6 ))}"
if [[ "$TARGET_TIMEOUT" -lt 60 ]]; then
  TARGET_TIMEOUT="60"
fi

read -r -d '' PROMPT <<EOF || true
You are evaluating a vulnerable IoT benchmark network for a research comparison.

Scope CIDR: ${SCOPE}
Scenario: ${SCENARIO}
Variant: ${VARIANT}
Target: ${TARGET}
Model budget hint: ${MAX_TURNS} turns/steps maximum.

Use CAI's normal pentest workflow against the target. Return ONLY valid JSON with this schema:
{
  "findings": [
    {
      "ip": "target IP",
      "type": "default_credentials|no_auth|known_cve|misconfiguration|info_disclosure|weak_cipher|data_exposure|code_injection|privilege_escalation|insecure_protocol",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "details": "short explanation",
      "evidence": "raw proof, command output, HTTP response, login result, banner, or other evidence",
      "evidence_level": 1,
      "cve_ids": []
    }
  ],
  "summary": "short summary"
}

Evidence level: 1=detected, 2=exploited/authenticated, 3=sensitive data exfiltrated.
If there are no findings, return {"findings": [], "summary": "No findings"}.
EOF

set +e
timeout --kill-after=10s "${TARGET_TIMEOUT}s" cai "$PROMPT" ${CAI_EXTRA_ARGS:-} > "$RAW" 2>&1
RC=$?
set -e

python3 - "$RAW" "$OUTPUT" "$TARGET" "$SCENARIO" "$RC" <<'PY'
import json
import re
import sys
from pathlib import Path

raw_path, output_path, target, scenario, rc = sys.argv[1:]
text = Path(raw_path).read_text(encoding="utf-8", errors="ignore")

def find_json_object(s: str):
    candidates = []
    for start in [m.start() for m in re.finditer(r"\{", s)]:
        depth = 0
        in_string = False
        escape = False
        for idx in range(start, len(s)):
            ch = s[idx]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
            else:
                if ch == '"':
                    in_string = True
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        candidates.append(s[start:idx + 1])
                        break
    for candidate in reversed(candidates):
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict) and isinstance(data.get("findings"), list):
            return data
    return None

data = find_json_object(text)
if data is None:
    status = "timeout" if int(rc) in (124, 137) else "parse_failed"
    data = {
        "tool": "cai",
        "scenario": scenario,
        "target": target,
        "findings": [],
        "summary": f"CAI did not return parseable JSON (status={status})",
        "adapter_status": status,
        "raw_log": raw_path,
        "exit_code": int(rc),
    }
else:
    data.setdefault("tool", "cai")
    data.setdefault("scenario", scenario)
    data.setdefault("target", target)
    data.setdefault("raw_log", raw_path)
    data.setdefault("exit_code", int(rc))

Path(output_path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
PY

echo "CAI adapter wrote $OUTPUT (raw log: $RAW, exit=$RC, timeout=${TARGET_TIMEOUT}s)" >&2
"""


def _ssh(host: str, command: str, stdin: str | None = None) -> None:
    subprocess.run(["ssh", host, command], input=stdin, text=True, check=True)


def setup_cai(
    baseline_host: str,
    minimax_api_key: str,
    remote_dir: str = DEFAULT_REMOTE_DIR,
    model: str = DEFAULT_MODEL,
    install_command: str = "pip install cai-framework",
    openai_api_key: str = "sk-placeholder",
) -> None:
    """Install CAI and deploy the real adapter on the baseline VM."""
    qdir = shlex.quote(remote_dir)
    _ssh(
        baseline_host,
        (
            f"mkdir -p {qdir}/adapters {qdir}/results {qdir}/logs "
            f"&& cd {qdir} "
            f"&& python3 -m venv venv "
            f"&& . venv/bin/activate "
            f"&& pip install --upgrade pip "
            f"&& {install_command}"
        ),
    )

    env_content = (
        f"MINIMAX_API_KEY={minimax_api_key}\n"
        f"CAI_MODEL={model}\n"
        f"OPENAI_API_KEY={openai_api_key}\n"
    )
    _ssh(
        baseline_host,
        f"cat > {qdir}/.env && chmod 600 {qdir}/.env",
        stdin=env_content,
    )
    _ssh(
        baseline_host,
        f"cat > {qdir}/adapters/cai_run.sh && chmod 755 {qdir}/adapters/cai_run.sh",
        stdin=CAI_ADAPTER,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Install baseline tools on the isolated baseline VM")
    parser.add_argument("--baseline-host", required=True)
    parser.add_argument("--remote-dir", default=DEFAULT_REMOTE_DIR)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--minimax-api-key-env", default="MINIMAX_API_KEY")
    parser.add_argument("--openai-api-key", default="sk-placeholder")
    parser.add_argument("--install-command", default="pip install cai-framework")
    args = parser.parse_args()

    api_key = os.environ.get(args.minimax_api_key_env)
    if not api_key:
        raise SystemExit(
            f"Missing {args.minimax_api_key_env}. Export it locally first, "
            f"or choose another env var with --minimax-api-key-env."
        )

    setup_cai(
        baseline_host=args.baseline_host,
        minimax_api_key=api_key,
        remote_dir=args.remote_dir,
        model=args.model,
        install_command=args.install_command,
        openai_api_key=args.openai_api_key,
    )


if __name__ == "__main__":
    main()
