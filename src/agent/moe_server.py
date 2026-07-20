#!/usr/bin/env python3
"""
NATO Smart City IoT — Hybrid Mixture of Experts (HMoE) Server

This server acts as an OpenAI-compatible API endpoint.
It loads a single base model in 4-bit (via bitsandbytes) and dynamically swaps
LoRA adapters (experts) using PEFT based on the requested model name or by
automatically analyzing the system prompt.

Usage:
    python3 src/agent/moe_server.py --base-model Qwen/Qwen2.5-0.5B-Instruct --adapters-dir output/adapters/lance-qlora_moe
"""

import os
import re
import json
import uuid
import time
import gc
import argparse
import logging
import threading
from contextlib import nullcontext
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
log = logging.getLogger("moe-server")

app = FastAPI(title="LANCE HMoE Server", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# --- Global State ---
_MODEL = None
_TOKENIZER = None
_ADAPTERS = []
_GENERATION_LOCK = threading.Lock()
_CUDA_CLEANUP_LOCK = threading.Lock()
_CUDA_CLEANUP_TIMER = None
_CUDA_IDLE_CLEANUP_SECONDS = float(os.environ.get("MOE_CUDA_IDLE_CLEANUP_SECONDS", "120"))
_ADAPTER_CONTEXT_TOKENS = int(os.environ.get("MOE_ADAPTER_CONTEXT_TOKENS", "6144"))

_CONTRACT_RECOVERY_TOOLS = frozenset({
    "arp_scan", "nmap_discovery", "nmap_scan", "read_deliverable",
})
_RECON_CORE_MODEL_TOOLS = frozenset({
    "arp_scan", "nmap_discovery", "nmap_scan", "read_deliverable",
    "save_deliverable",
})

_MODEL_IDS = [
    "lance-moe",
    "expert-recon",
    "expert-vuln",
    "expert-exploit",
    "expert-secretary",
]


def _release_cuda_memory(torch_module) -> None:
    """Return unused PyTorch CUDA allocations to the driver."""
    if not torch_module.cuda.is_available():
        return

    allocated_before = torch_module.cuda.memory_allocated()
    reserved_before = torch_module.cuda.memory_reserved()
    gc.collect()
    torch_module.cuda.empty_cache()
    allocated_after = torch_module.cuda.memory_allocated()
    reserved_after = torch_module.cuda.memory_reserved()
    log.info(
        "CUDA idle cleanup: allocated %.1f -> %.1f MiB, reserved %.1f -> %.1f MiB",
        allocated_before / 1024**2,
        allocated_after / 1024**2,
        reserved_before / 1024**2,
        reserved_after / 1024**2,
    )


def _cancel_scheduled_cuda_cleanup() -> None:
    """Cancel a pending idle cleanup when a new generation starts."""
    global _CUDA_CLEANUP_TIMER
    with _CUDA_CLEANUP_LOCK:
        timer = _CUDA_CLEANUP_TIMER
        _CUDA_CLEANUP_TIMER = None
        if timer is not None:
            timer.cancel()


def _run_scheduled_cuda_cleanup(torch_module, timer) -> None:
    """Clean CUDA only if this timer is still the latest idle timer."""
    global _CUDA_CLEANUP_TIMER
    with _GENERATION_LOCK:
        with _CUDA_CLEANUP_LOCK:
            if _CUDA_CLEANUP_TIMER is not timer:
                return
            _CUDA_CLEANUP_TIMER = None
        _release_cuda_memory(torch_module)


def _schedule_cuda_cleanup(torch_module) -> None:
    """Release cached CUDA memory after a configurable idle period."""
    global _CUDA_CLEANUP_TIMER
    _cancel_scheduled_cuda_cleanup()
    if _CUDA_IDLE_CLEANUP_SECONDS <= 0:
        _release_cuda_memory(torch_module)
        return

    timer = threading.Timer(
        _CUDA_IDLE_CLEANUP_SECONDS,
        lambda: _run_scheduled_cuda_cleanup(torch_module, timer),
    )
    timer.daemon = True
    with _CUDA_CLEANUP_LOCK:
        _CUDA_CLEANUP_TIMER = timer
    timer.start()
    log.debug("CUDA cleanup scheduled after %.1f seconds of inactivity", _CUDA_IDLE_CLEANUP_SECONDS)

# --- API Models ---
class Message(BaseModel):
    role: str
    content: str | List[Dict[str, Any]] | None = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[Message]
    tools: Optional[List[Dict[str, Any]]] = None
    max_tokens: Optional[int] = 4096
    temperature: Optional[float] = 0.0
    stream: bool = False

# --- Router Logic ---
def _route_expert(messages: List[Message]) -> str:
    """Determine the expert based on exact LANCE system prompt roles."""
    sys_prompt = next((m.content for m in messages if m.role == "system"), "")
    if not isinstance(sys_prompt, str):
        sys_prompt = json.dumps(sys_prompt)
    sys_prompt = sys_prompt.lower()

    phase_match = re.search(r"phase\s+([1-6])\s+of\s+6", sys_prompt)
    if phase_match:
        return {
            "1": "secretary",
            "2": "recon",
            "3": "vuln",
            "4": "exploit",
            "5": "exploit",
            "6": "secretary",
        }[phase_match.group(1)]
    
    # Check for exact roles defined in the first lines of LANCE prompts
    if "topology analyst" in sys_prompt or "report writer" in sys_prompt:
        return "secretary"
    elif "reconnaissance and network scanning" in sys_prompt or "network reconnaissance agent" in sys_prompt:
        return "recon"
    elif "vulnerability analyst" in sys_prompt or "vulnerability aggregator" in sys_prompt:
        return "vuln"
    elif (
        "exploit verification agent" in sys_prompt
        or "offensive security agent" in sys_prompt
        or "iot pentester exploiting vulnerabilities" in sys_prompt
    ):
        return "exploit"
    
    # Fallback to base model if no clear match
    return "base"

# --- Qwen Tool Call Parser ---
def _extract_json_objects(text: str) -> list[tuple[dict, str]]:
    """Robustly extract all JSON objects from a string, handling nested braces."""
    results = []
    brace_level = 0
    in_string = False
    escape_next = False
    start_idx = -1
    
    for i, char in enumerate(text):
        if escape_next:
            escape_next = False
            continue
            
        if char == '\\':
            escape_next = True
            continue
            
        if char == '"':
            in_string = not in_string
            continue
            
        if not in_string:
            if char == '{':
                if brace_level == 0:
                    start_idx = i
                brace_level += 1
            elif char == '}':
                brace_level -= 1
                if brace_level == 0 and start_idx != -1:
                    json_str = text[start_idx:i+1]
                    try:
                        results.append((json.loads(json_str), json_str))
                    except Exception:
                        pass
                    start_idx = -1
                elif brace_level < 0:
                    brace_level = 0  # reset if malformed
                    
    return results


def _load_tool_call_json(text: str) -> Optional[dict[str, Any]]:
    """Load a Qwen tool call and repair conservative truncation patterns."""
    candidate = text.lstrip(" ,\n\r\t")
    if not candidate.startswith("{"):
        return None

    candidate = re.split(
        r"</(?:tool_call|tool_response|delabelyer)>",
        candidate,
        maxsplit=1,
        flags=re.IGNORECASE,
    )[0].rstrip()
    try:
        value = json.loads(candidate)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        pass

    # The adapters also sometimes close the root object with ``]``. Only
    # accept that exact one-character repair when it produces valid JSON.
    if candidate.endswith("]"):
        try:
            value = json.loads(candidate[:-1] + "}")
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            pass

    stack: list[str] = []
    in_string = False
    escape_next = False
    complete_at: Optional[int] = None
    matching = {"}": "{", "]": "["}
    for index, char in enumerate(candidate):
        if escape_next:
            escape_next = False
            continue
        if in_string and char == "\\":
            escape_next = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char in "{[":
            stack.append(char)
        elif char in "}]":
            if not stack or stack[-1] != matching[char]:
                return None
            stack.pop()
            if not stack:
                complete_at = index + 1
                break

    if complete_at is not None:
        repaired = candidate[:complete_at]
    else:
        repaired = candidate
        if escape_next:
            repaired += "\\"
        if in_string:
            repaired += '"'
        repaired = re.sub(r",\s*$", "", repaired)
        repaired += "".join("}" if opener == "{" else "]" for opener in reversed(stack))

    try:
        value = json.loads(repaired)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _to_openai_tool_call(call_data: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Validate and convert one model-emitted call to OpenAI format."""
    name = call_data.get("name") or call_data.get("tool")
    args = call_data.get("arguments")
    if args is None:
        args = call_data.get("args", {})
    if not isinstance(name, str) or not name.strip() or not isinstance(args, dict):
        return None
    return {
        "id": f"call_{uuid.uuid4().hex[:8]}",
        "type": "function",
        "function": {"name": name.strip(), "arguments": json.dumps(args)},
    }

def _parse_qwen_tool_calls(text: str) -> tuple[str, list[dict]]:
    """Parse tool calls, supporting both Qwen native <tool_call> tags and fine-tuned JSON formats."""
    tool_calls = []
    
    # 1. Strip dangling commas often hallucinated at the start
    text = text.lstrip(",").strip()
    
    # 2. Extract anything inside <tool_call> tags (even unclosed)
    pattern = re.compile(r"<tool_call>\s*(.*?)(?:</tool_call>|$)", re.DOTALL)
    
    content_parts = []
    last_idx = 0
    
    for match in pattern.finditer(text):
        if match.start() > last_idx:
            content_parts.append(text[last_idx:match.start()].strip())
            
        call_str = match.group(1).strip()
        call_data = _load_tool_call_json(call_str) if call_str else None
        tool_call = _to_openai_tool_call(call_data) if call_data else None
        if tool_call:
            tool_calls.append(tool_call)
        elif call_str:
            log.error("Failed to parse Qwen tool call JSON: %r", call_str[:500])
            
        last_idx = match.end()
        
    if last_idx < len(text):
        remainder = text[last_idx:].strip()
        if remainder:
            content_parts.append(remainder)
            
    content = "\n".join(content_parts).strip()
    
    # 3. If no <tool_call> tags were found, maybe the model outputted RAW JSON
    if not tool_calls:
        extracted = _extract_json_objects(content)
        for obj, obj_str in extracted:
            tool_call = _to_openai_tool_call(obj)

            # If it looks like a tool call, extract it
            if tool_call:
                tool_calls.append(tool_call)
                # Remove this JSON block from the textual content
                content = content.replace(obj_str, "").strip()

    return content, tool_calls

# --- Endpoints ---
@app.get("/health")
def health():
    return {
        "status": "ok",
        "loaded_adapters": _ADAPTERS,
        "adapter_context_tokens": _ADAPTER_CONTEXT_TOKENS,
        "contract_recovery": True,
    }


@app.get("/v1/models")
def list_models():
    created = int(time.time())
    return {
        "object": "list",
        "data": [
            {"id": model_id, "object": "model", "created": created, "owned_by": "lance"}
            for model_id in _MODEL_IDS
        ],
    }


def _format_hf_message(message: Message) -> dict[str, Any]:
    content = message.content
    if isinstance(content, list):
        content = json.dumps(content)

    formatted: dict[str, Any] = {"role": message.role, "content": content or ""}
    if message.tool_calls:
        tool_calls = json.loads(json.dumps(message.tool_calls))
        for tool_call in tool_calls:
            function = tool_call.get("function", {})
            arguments = function.get("arguments")
            if isinstance(arguments, str):
                try:
                    function["arguments"] = json.loads(arguments)
                except json.JSONDecodeError:
                    pass
        formatted["tool_calls"] = tool_calls
    if message.tool_call_id:
        formatted["tool_call_id"] = message.tool_call_id
    if message.name:
        formatted["name"] = message.name
    return formatted


def _message_tool_calls(message: Message) -> list[dict[str, Any]]:
    return message.tool_calls if isinstance(message.tool_calls, list) else []


def _tool_call_details(tool_call: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    function = tool_call.get("function", {}) if isinstance(tool_call, dict) else {}
    name = str(function.get("name") or tool_call.get("name") or "").strip()
    arguments = function.get("arguments", tool_call.get("arguments", {}))
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError:
            arguments = {}
    return name, arguments if isinstance(arguments, dict) else {}


def _result_payload(content: object) -> dict[str, Any]:
    if isinstance(content, list):
        content = json.dumps(content)
    if not isinstance(content, str):
        return {}
    try:
        value = json.loads(content)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _tool_result_failed(payload: dict[str, Any], raw_content: object) -> bool:
    if payload:
        return bool(
            payload.get("ok") is False
            or payload.get("error")
            or payload.get("error_kind")
            or str(payload.get("status", "")).upper() == "ERROR"
            or payload.get("return_code") not in (None, 0)
        )
    return isinstance(raw_content, str) and raw_content.startswith("Error")


def _ports_from_arguments(arguments: dict[str, Any]) -> set[int]:
    values = arguments.get("ports", arguments.get("port", ""))
    return {
        int(value) for value in re.findall(r"\d{1,5}", str(values))
        if 0 < int(value) <= 65535
    }


def _requirement_satisfied(
    requirement: dict[str, Any], tool_name: str, arguments: dict[str, Any]
) -> bool:
    expected_tool = requirement.get("tool") or requirement.get("suggested_tool")
    if expected_tool != tool_name:
        return False
    if requirement.get("filename") and arguments.get("filename") != requirement["filename"]:
        return False
    if requirement.get("target") and arguments.get("target") != requirement["target"]:
        return False
    missing_ports = {
        int(value) for value in requirement.get("missing_ports", [])
        if str(value).isdigit()
    }
    return not missing_ports or missing_ports.issubset(_ports_from_arguments(arguments))


def _build_execution_state(messages: List[Message]) -> dict[str, Any]:
    """Reconstruct tool progress from one stateless OpenAI conversation."""
    calls_by_id: dict[str, tuple[str, dict[str, Any]]] = {}
    tool_counts: dict[str, int] = {}
    successful_counts: dict[str, int] = {}
    outstanding: list[dict[str, Any]] = []
    rejected_saves = 0
    last_error_kind = ""
    recon_progress: dict[str, Any] = {}

    for message in messages:
        if message.role == "assistant":
            for tool_call in _message_tool_calls(message):
                name, arguments = _tool_call_details(tool_call)
                if not name:
                    continue
                call_id = str(tool_call.get("id", ""))
                if call_id:
                    calls_by_id[call_id] = (name, arguments)
                tool_counts[name] = tool_counts.get(name, 0) + 1
            continue
        if message.role != "tool":
            continue
        tool_name, arguments = calls_by_id.get(
            str(message.tool_call_id or ""), (str(message.name or ""), {})
        )
        payload = _result_payload(message.content)
        progress = payload.get("recon_progress")
        has_authoritative_progress = isinstance(progress, dict)
        if has_authoritative_progress:
            recon_progress = progress
            outstanding = [
                item for item in progress.get("missing_requirements", [])
                if isinstance(item, dict)
            ]
        if _tool_result_failed(payload, message.content):
            last_error_kind = str(payload.get("error_kind", ""))
            if tool_name == "save_deliverable" and isinstance(
                payload.get("missing_requirements"), list
            ):
                rejected_saves += 1
                outstanding = [
                    item for item in payload["missing_requirements"]
                    if isinstance(item, dict)
                ]
            continue
        if tool_name:
            successful_counts[tool_name] = successful_counts.get(tool_name, 0) + 1
            if not has_authoritative_progress:
                outstanding = [
                    item for item in outstanding
                    if not _requirement_satisfied(item, tool_name, arguments)
                ]
            if not outstanding:
                last_error_kind = ""

    return {
        "tool_counts": tool_counts,
        "successful_counts": successful_counts,
        "outstanding_requirements": outstanding,
        "rejected_saves": rejected_saves,
        "last_error_kind": last_error_kind,
        "recon_progress": recon_progress,
    }


def _runtime_state_text(state: dict[str, Any]) -> str:
    completed = state.get("successful_counts", {})
    completed_text = ", ".join(
        f"{name}×{count}" for name, count in sorted(completed.items())
    ) or "none"
    lines = [
        "[RUNTIME EXECUTION STATE — authoritative]",
        f"Successful tool calls: {completed_text}.",
        f"Rejected save attempts: {state.get('rejected_saves', 0)}.",
    ]
    outstanding = state.get("outstanding_requirements", [])
    progress = state.get("recon_progress", {})
    targets = progress.get("targets", []) if isinstance(progress, dict) else []
    if targets:
        lines.append("Per-target minimum coverage:")
        for target in targets:
            if not isinstance(target, dict):
                continue
            missing_ports = target.get("missing_ports", [])
            failed_ports = target.get("failed_ports", [])
            if missing_ports:
                status = f"missing ports {','.join(str(port) for port in missing_ports)}"
            elif failed_ports:
                status = (
                    "coverage attempted twice but probes failed on ports "
                    + ",".join(str(port) for port in failed_ports)
                    + "; document these failures"
                )
            else:
                status = "complete"
            lines.append(
                f"- {target.get('target', 'unknown')} "
                f"({target.get('device_id', 'unknown')}): {status}"
            )
    if outstanding:
        lines.append("Outstanding requirements must be completed before saving:")
        for item in outstanding:
            tool = item.get("tool") or item.get("suggested_tool") or "unknown"
            args = {
                key: item[key] for key in ("filename", "target", "missing_ports")
                if item.get(key) not in (None, "", [])
            }
            lines.append(
                f"- {item.get('requirement', 'requirement')}: call {tool} with "
                f"{json.dumps(args, ensure_ascii=False, sort_keys=True)}"
            )
        lines.append("Do NOT call save_deliverable again until this list is empty.")
    else:
        lines.append("No contract requirement is currently known to be outstanding.")
        if progress.get("ready_to_save") is True:
            lines.append(
                "Recon baseline is complete. Synthesize the evidence already collected "
                "and call save_deliverable exactly once; do not run another baseline scan."
            )
    return "\n".join(lines)


def _select_model_tools(
    target_expert: str,
    tools: Optional[List[Dict[str, Any]]],
    state: Optional[dict[str, Any]] = None,
) -> Optional[List[Dict[str, Any]]]:
    """Expose the training-aligned core interface to the Recon adapter.

    The caller retains its complete executable tool map. Only the verbose JSON
    schemas rendered into the 3B model prompt are reduced.
    """
    if target_expert != "recon" or not tools:
        return tools
    progress = (state or {}).get("recon_progress", {})
    if isinstance(progress, dict) and progress.get("ready_to_save") is True:
        selected = [
            tool for tool in tools
            if str(tool.get("function", {}).get("name", "")) == "save_deliverable"
        ]
        log.info("Recon baseline complete: model tool schemas reduced to save-only")
        return selected
    selected = [
        tool for tool in tools
        if str(tool.get("function", {}).get("name", "")) in _RECON_CORE_MODEL_TOOLS
    ]
    missing = _RECON_CORE_MODEL_TOOLS - {
        str(tool.get("function", {}).get("name", "")) for tool in selected
    }
    if missing:
        log.warning("Recon core tool schemas missing from request: %s", sorted(missing))
    log.info("Recon model tool schemas: %d -> %d", len(tools), len(selected))
    return selected


def _forced_recovery_tool(
    state: dict[str, Any], tools: Optional[List[Dict[str, Any]]]
) -> tuple[str, dict[str, Any]] | None:
    """Turn a structured contract rejection into the exact missing tool call."""
    available = {
        str(tool.get("function", {}).get("name", ""))
        for tool in (tools or []) if isinstance(tool, dict)
    }
    for item in state.get("outstanding_requirements", []):
        name = str(item.get("tool") or item.get("suggested_tool") or "")
        if not name or name not in available or name not in _CONTRACT_RECOVERY_TOOLS:
            continue
        arguments: dict[str, Any] = {}
        if item.get("filename"):
            arguments["filename"] = item["filename"]
        if item.get("target"):
            arguments["target"] = item["target"]
        if item.get("missing_ports"):
            arguments["ports"] = ",".join(str(value) for value in item["missing_ports"])
            arguments["skip_discovery"] = True
        return name, arguments
    return None


def _summarize_tool_content(content: str, limit: int = 1600) -> str:
    payload = _result_payload(content)
    if payload.get("error_kind") or payload.get("missing_requirements"):
        rendered = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        return rendered[:limit]
    if isinstance(payload.get("hosts"), list):
        compact = {"hosts": payload["hosts"]}
        return json.dumps(compact, ensure_ascii=False, separators=(",", ":"))[:limit]
    stdout = str(payload.get("stdout", ""))
    if stdout:
        useful = [
            line for line in stdout.splitlines()
            if re.search(
                r"Nmap scan report|Host is up|^\d+/(?:tcp|udp)\s+open|MAC Address|Service Info",
                line,
                re.IGNORECASE,
            )
        ]
        compact = {key: value for key, value in payload.items() if key != "stdout"}
        compact["stdout_summary"] = useful[:80]
        return json.dumps(compact, ensure_ascii=False, separators=(",", ":"))[:limit]
    if len(content) <= limit:
        return content
    half = max(1, (limit - 48) // 2)
    return content[:half] + "\n[... compacted by MoE runtime ...]\n" + content[-half:]


def _compact_hf_messages(
    messages: list[dict[str, Any]], *, aggressive: bool = False
) -> list[dict[str, Any]]:
    """Compact rejected drafts and old tool output without breaking call/result IDs."""
    compacted = json.loads(json.dumps(messages))
    latest_index = len(compacted) - 1
    for index, message in enumerate(compacted):
        if message.get("role") == "assistant":
            for tool_call in message.get("tool_calls", []) or []:
                function = tool_call.get("function", {})
                if function.get("name") != "save_deliverable":
                    continue
                arguments = function.get("arguments")
                if isinstance(arguments, dict) and len(str(arguments.get("content", ""))) > 400:
                    size = len(str(arguments["content"]))
                    arguments["content"] = f"[rejected draft compacted: {size} characters]"
        if message.get("role") != "tool":
            continue
        content = str(message.get("content", ""))
        payload = _result_payload(content)
        preserve_latest_contract_error = (
            index == latest_index
            and bool(payload.get("error_kind") or payload.get("missing_requirements"))
        )
        if preserve_latest_contract_error:
            continue
        if (
            (aggressive and (index != latest_index or len(content) > 4000))
            or index < len(compacted) - 6
            or len(content) > 4000
        ):
            message["content"] = _summarize_tool_content(content)
    return compacted


def _fold_old_history(
    messages: list[dict[str, Any]], *, keep_recent: int = 6
) -> list[dict[str, Any]]:
    """Fold old tool turns into a compact ledger while keeping recent pairs intact."""
    if len(messages) <= keep_recent + 2:
        return messages
    prefix_end = 0
    while prefix_end < len(messages) and messages[prefix_end].get("role") == "system":
        prefix_end += 1
    if prefix_end < len(messages) and messages[prefix_end].get("role") == "user":
        prefix_end += 1

    start = max(prefix_end, len(messages) - keep_recent)
    if start < len(messages) and messages[start].get("role") == "tool":
        tool_call_id = messages[start].get("tool_call_id")
        for index in range(start - 1, prefix_end - 1, -1):
            calls = messages[index].get("tool_calls", []) or []
            if any(call.get("id") == tool_call_id for call in calls):
                start = index
                break

    dropped = messages[prefix_end:start]
    if not dropped:
        return messages
    ledger: list[dict[str, Any]] = []
    call_names: dict[str, tuple[str, dict[str, Any]]] = {}
    for message in dropped:
        if message.get("role") == "assistant":
            for call in message.get("tool_calls", []) or []:
                name, arguments = _tool_call_details(call)
                call_id = str(call.get("id", ""))
                if call_id:
                    call_names[call_id] = (name, arguments)
        elif message.get("role") == "tool":
            call_id = str(message.get("tool_call_id", ""))
            name, arguments = call_names.get(call_id, (str(message.get("name", "")), {}))
            ledger.append({
                "tool": name,
                "arguments": arguments,
                "result": _summarize_tool_content(str(message.get("content", "")), limit=500),
            })
    summary = (
        "[COMPACTED TOOL HISTORY — deterministic runtime ledger]\n"
        + json.dumps(ledger[-20:], ensure_ascii=False, separators=(",", ":"))
    )
    return messages[:prefix_end] + [{"role": "user", "content": summary}] + messages[start:]


def _attach_runtime_state(
    messages: list[dict[str, Any]], state: dict[str, Any]
) -> list[dict[str, Any]]:
    enriched = json.loads(json.dumps(messages))
    state_text = _runtime_state_text(state)
    if enriched:
        content = str(enriched[-1].get("content", ""))
        enriched[-1]["content"] = content + "\n\n" + state_text
    else:
        enriched.append({"role": "system", "content": state_text})
    return enriched


def _render_prompt(
    tokenizer, messages: list[dict[str, Any]], tools: Optional[List[Dict[str, Any]]]
) -> str:
    try:
        return tokenizer.apply_chat_template(
            messages, tools=tools, tokenize=False, add_generation_prompt=True,
        )
    except Exception as exc:
        log.warning("Tokenizer tool formatting failed, falling back to basic template: %s", exc)
        return tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True,
        )


def _prompt_token_count(tokenizer, prompt: str) -> int:
    encoded = tokenizer(prompt, add_special_tokens=False)
    input_ids = encoded.get("input_ids", [])
    return len(input_ids)


def _prepare_prompt(
    tokenizer,
    messages: List[Message],
    tools: Optional[List[Dict[str, Any]]],
    state: dict[str, Any],
    context_budget: int,
) -> tuple[str, int, bool]:
    formatted = [_format_hf_message(message) for message in messages]
    formatted = _attach_runtime_state(formatted, state)
    prompt = _render_prompt(tokenizer, formatted, tools)
    original_tokens = _prompt_token_count(tokenizer, prompt)
    if original_tokens <= context_budget:
        return prompt, original_tokens, False

    compacted = _compact_hf_messages(formatted)
    prompt = _render_prompt(tokenizer, compacted, tools)
    compacted_tokens = _prompt_token_count(tokenizer, prompt)
    if compacted_tokens > context_budget:
        compacted = _compact_hf_messages(compacted, aggressive=True)
        prompt = _render_prompt(tokenizer, compacted, tools)
        compacted_tokens = _prompt_token_count(tokenizer, prompt)
    log.info(
        "Context compaction: %d -> %d tokens (adapter budget=%d)",
        original_tokens, compacted_tokens, context_budget,
    )
    if compacted_tokens > context_budget:
        for keep_recent in (6, 4, 2):
            compacted = _fold_old_history(compacted, keep_recent=keep_recent)
            prompt = _render_prompt(tokenizer, compacted, tools)
            compacted_tokens = _prompt_token_count(tokenizer, prompt)
            if compacted_tokens <= context_budget:
                break
    if compacted_tokens > context_budget:
        log.warning(
            "Prompt remains above adapter training budget after safe compaction: %d > %d",
            compacted_tokens, context_budget,
        )
    return prompt, compacted_tokens, True


def _forced_tool_response(
    req: ChatCompletionRequest,
    name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    response = {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "tool_calls": [{
                    "id": f"call_{uuid.uuid4().hex[:8]}",
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": json.dumps(arguments),
                    },
                }],
            },
            "finish_reason": "tool_calls",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }
    log.warning("Contract recovery forced tool call: %s(%s)", name, arguments)
    return response


def _stream_response(response: dict[str, Any]):
    response_id = response["id"]
    model = response["model"]
    created = response["created"]
    message = response["choices"][0]["message"]

    first_chunk = {
        "id": response_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": message, "finish_reason": None}],
    }
    final_chunk = {
        "id": response_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": {},
            "finish_reason": response["choices"][0]["finish_reason"],
        }],
        "usage": response["usage"],
    }
    yield f"data: {json.dumps(first_chunk)}\n\n"
    yield f"data: {json.dumps(final_chunk)}\n\n"
    yield "data: [DONE]\n\n"


@app.post("/v1/chat/completions")
def chat_completions(req: ChatCompletionRequest):
    import torch

    global _MODEL, _TOKENIZER, _ADAPTERS
    if not _MODEL:
        raise HTTPException(status_code=503, detail="Model not initialized")
        
    # Determine the expert to use
    target_expert = "base"
    if req.model == "lance-moe":
        target_expert = _route_expert(req.messages)
        log.info(f"[ROUTER] Automatically routed to expert: {target_expert}")
    elif req.model.startswith("expert-"):
        target_expert = req.model.replace("expert-", "")
        log.info(f"[ROUTER] Manual standalone expert requested: {target_expert}")
        
    execution_state = _build_execution_state(req.messages)
    forced_recovery = _forced_recovery_tool(execution_state, req.tools)
    if forced_recovery is not None:
        response = _forced_tool_response(req, *forced_recovery)
        if req.stream:
            return StreamingResponse(_stream_response(response), media_type="text/event-stream")
        return response

    model_tools = _select_model_tools(target_expert, req.tools, execution_state)
    prompt, prepared_prompt_tokens, _compacted = _prepare_prompt(
        _TOKENIZER,
        req.messages,
        model_tools,
        execution_state,
        _ADAPTER_CONTEXT_TOKENS,
    )

    with _GENERATION_LOCK:
        _cancel_scheduled_cuda_cleanup()
        inputs = None
        outputs = None
        generated_ids = None
        try:
            adapter_context = nullcontext()
            if target_expert in _ADAPTERS:
                _MODEL.set_adapter(target_expert)
                log.info(f"Active Adapter: {target_expert}")
            else:
                if target_expert != "base":
                    log.warning(f"Expert {target_expert} not found. Falling back to the base model.")
                adapter_context = _MODEL.disable_adapter()
                log.info("Active Adapter: BASE")

            inputs = _TOKENIZER(prompt, return_tensors="pt").to(_MODEL.device)
            input_tokens = inputs.input_ids.shape[-1]
            if abs(input_tokens - prepared_prompt_tokens) > 2:
                log.debug(
                    "Rendered/tokenized prompt count differs: prepared=%d actual=%d",
                    prepared_prompt_tokens, input_tokens,
                )
            t0 = time.time()
            with adapter_context, torch.inference_mode():
                requested_tokens = int(req.max_tokens or 4096)
                if target_expert == "recon":
                    remaining_training_window = max(256, _ADAPTER_CONTEXT_TOKENS - input_tokens)
                    requested_tokens = min(requested_tokens, 1536, remaining_training_window)
                outputs = _MODEL.generate(
                    **inputs,
                    max_new_tokens=requested_tokens,
                    temperature=req.temperature if req.temperature > 0 else 0.01,
                    do_sample=req.temperature > 0,
                    pad_token_id=_TOKENIZER.eos_token_id
                )
            t1 = time.time()

            # Decode before releasing all request-scoped CUDA tensors.
            generated_ids = outputs[0][input_tokens:]
            output_tokens = len(generated_ids)
            response_text = _TOKENIZER.decode(generated_ids, skip_special_tokens=True)
        finally:
            generated_ids = None
            outputs = None
            inputs = None
            _schedule_cuda_cleanup(torch)
    
    # Parse potential tool calls
    content, tool_calls = _parse_qwen_tool_calls(response_text)
    
    # Format response for OpenAI compatibility
    res_msg = {"role": "assistant"}
    if content:
        res_msg["content"] = content
    if tool_calls:
        res_msg["tool_calls"] = tool_calls
        
    log.info(f"Generated {output_tokens} tokens in {t1-t0:.2f}s ({output_tokens/(t1-t0):.1f} t/s)")
    
    response = {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [{
            "index": 0,
            "message": res_msg,
            "finish_reason": "tool_calls" if tool_calls else "stop"
        }],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens
        }
    }
    if req.stream:
        return StreamingResponse(_stream_response(response), media_type="text/event-stream")
    return response


def load_models(base_model_path: str, adapters_dir: str):
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    global _MODEL, _TOKENIZER, _ADAPTERS
    log.info(f"Loading base model in 4-bit: {base_model_path}")
    
    quantization_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=torch.bfloat16
    )
    
    _TOKENIZER = AutoTokenizer.from_pretrained(base_model_path)
    base_model = AutoModelForCausalLM.from_pretrained(
        base_model_path,
        quantization_config=quantization_config,
        device_map="auto",
        torch_dtype=torch.bfloat16,
    )
    
    _MODEL = base_model
    
    if os.path.isdir(adapters_dir):
        # Find checkpoint directories inside each expert folder
        for expert_name in ["recon", "vuln", "exploit", "secretary"]:
            expert_dir = os.path.join(adapters_dir, expert_name)
            if not os.path.exists(expert_dir):
                log.warning(f"Expert dir not found: {expert_dir}")
                continue
                
            adapter_path = expert_dir
            if not os.path.isfile(os.path.join(adapter_path, "adapter_model.safetensors")):
                checkpoints = [d for d in os.listdir(expert_dir) if d.startswith("checkpoint-")]
                if not checkpoints:
                    log.warning(f"No adapter weights or checkpoints found in {expert_dir}")
                    continue

                best_ckpt = sorted(checkpoints, key=lambda x: int(x.split("-")[1]))[-1]
                adapter_path = os.path.join(expert_dir, best_ckpt)
            
            log.info(f"Loading adapter [{expert_name}] from {adapter_path}")
            # If it's the first adapter, PeftModel wraps the base model
            if not isinstance(_MODEL, PeftModel):
                _MODEL = PeftModel.from_pretrained(base_model, adapter_path, adapter_name=expert_name)
            else:
                _MODEL.load_adapter(adapter_path, adapter_name=expert_name)
            _ADAPTERS.append(expert_name)
            
    log.info(f"HMoE initialization complete. Loaded adapters: {_ADAPTERS}")
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-model", default="Qwen/Qwen2.5-3B-Instruct", help="Path or HF hub ID for the base model")
    parser.add_argument("--adapters-dir", default="output/adapters/lance-qlora_moe_3b", help="Directory containing the expert adapters")
    parser.add_argument("--adapter-context-tokens", type=int, default=_ADAPTER_CONTEXT_TOKENS, help="Training-aligned prompt budget before safe compaction")
    parser.add_argument("--port", type=int, default=8001, help="Port to run the API server on")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    args = parser.parse_args()
    
    # Load model synchronously before starting server
    _ADAPTER_CONTEXT_TOKENS = args.adapter_context_tokens
    load_models(args.base_model, args.adapters_dir)
    
    uvicorn.run(app, host=args.host, port=args.port)
