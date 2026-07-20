#!/usr/bin/env python3
"""Create bounded-context LANCE datasets for Qwen2.5-3B QLoRA training."""
from __future__ import annotations

import argparse
import copy
import json
from collections import Counter
from pathlib import Path
from typing import Any

from transformers import AutoTokenizer

EXPERTS = ("secretary", "recon", "vuln", "exploit")
DEFAULT_LENGTHS = {"secretary": 6144, "recon": 6144, "vuln": 4096, "exploit": 6144}
TRUNCATION_MARKER = "\n[truncated for Qwen2.5-3B training context]"


def parse_tools(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, str):
        raw = json.loads(raw)
    return raw if isinstance(raw, list) else []


def tool_name(tool: dict[str, Any]) -> str | None:
    return tool.get("function", {}).get("name")


def used_tool_names(messages: list[dict[str, Any]]) -> set[str]:
    names: set[str] = set()
    for message in messages:
        if message.get("role") != "assistant":
            continue
        for call in message.get("tool_calls") or []:
            name = call.get("function", {}).get("name")
            if name:
                names.add(name)
    return names


def select_tools(
    tools: list[dict[str, Any]], messages: list[dict[str, Any]], distractors: int
) -> list[dict[str, Any]]:
    used = used_tool_names(messages)
    selected = [tool for tool in tools if tool_name(tool) in used]
    if distractors:
        selected_names = {tool_name(tool) for tool in selected}
        for tool in tools:
            name = tool_name(tool)
            if name not in selected_names:
                selected.append(tool)
                selected_names.add(name)
                if len(selected_names - used) >= distractors:
                    break
    return selected


def split_messages(messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[list[dict[str, Any]]]]:
    first_assistant = next(
        (index for index, message in enumerate(messages) if message.get("role") == "assistant"),
        len(messages),
    )
    prefix = copy.deepcopy(messages[:first_assistant])
    units: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for message in messages[first_assistant:]:
        if message.get("role") == "assistant" and current:
            units.append(current)
            current = []
        current.append(copy.deepcopy(message))
    if current:
        units.append(current)
    return prefix, units


def truncate_text(value: str, new_size: int) -> str:
    marker_size = len(TRUNCATION_MARKER)
    if new_size <= marker_size:
        return value[:new_size]
    return value[: new_size - marker_size].rstrip() + TRUNCATION_MARKER


def truncate_middle(value: str, new_size: int) -> str:
    """Keep both the role/rules prefix and completion criteria suffix."""
    marker = "\n[... middle truncated for Qwen2.5-3B training context ...]\n"
    if new_size <= len(marker):
        return value[:new_size]
    remaining = new_size - len(marker)
    head = (remaining * 2) // 3
    tail = remaining - head
    return value[:head].rstrip() + marker + value[-tail:].lstrip()


def shrink_once(messages: list[dict[str, Any]]) -> bool:
    candidates: list[tuple[int, int]] = []
    for index, message in enumerate(messages):
        content = message.get("content")
        if message.get("role") == "tool" and isinstance(content, str) and len(content) > 512:
            candidates.append((len(content), index))
    if candidates:
        _, index = max(candidates)
        content = messages[index]["content"]
        messages[index]["content"] = truncate_text(content, max(512, int(len(content) * 0.65)))
        return True

    argument_candidates: list[tuple[int, int, int, str]] = []
    for message_index, message in enumerate(messages):
        for call_index, call in enumerate(message.get("tool_calls") or []):
            arguments = call.get("function", {}).get("arguments")
            if not isinstance(arguments, dict):
                continue
            for key, value in arguments.items():
                if isinstance(value, str) and len(value) > 1024:
                    argument_candidates.append((len(value), message_index, call_index, key))
    if argument_candidates:
        _, message_index, call_index, key = max(argument_candidates)
        arguments = messages[message_index]["tool_calls"][call_index]["function"]["arguments"]
        arguments[key] = truncate_text(arguments[key], max(1024, int(len(arguments[key]) * 0.7)))
        return True

    system_candidates = [
        (len(message.get("content", "")), index)
        for index, message in enumerate(messages)
        if message.get("role") == "system"
        and isinstance(message.get("content"), str)
        and len(message["content"]) > 4096
    ]
    if system_candidates:
        _, index = max(system_candidates)
        content = messages[index]["content"]
        messages[index]["content"] = truncate_middle(content, max(4096, int(len(content) * 0.8)))
        return True
    return False


def rendered_tokens(tokenizer, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> int:
    rendered = tokenizer.apply_chat_template(
        messages,
        tools=tools or None,
        tokenize=False,
        add_generation_prompt=False,
    )
    return len(tokenizer.encode(rendered, add_special_tokens=False))


def fit_chunk(
    tokenizer,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    max_length: int,
) -> tuple[list[dict[str, Any]], int, bool]:
    fitted = copy.deepcopy(messages)
    length = rendered_tokens(tokenizer, fitted, tools)
    truncated = False
    while length > max_length and shrink_once(fitted):
        truncated = True
        length = rendered_tokens(tokenizer, fitted, tools)
    return fitted, length, truncated


def build_chunks(
    tokenizer,
    row: dict[str, Any],
    max_length: int,
    distractors: int,
) -> tuple[list[dict[str, Any]], Counter]:
    stats: Counter = Counter()
    original_tools = parse_tools(row.get("tools"))
    prefix, units = split_messages(row.get("messages") or [])
    if not prefix or not units:
        stats["invalid"] += 1
        return [], stats

    chunks: list[dict[str, Any]] = []
    active: list[list[dict[str, Any]]] = []

    def materialize(grouped_units: list[list[dict[str, Any]]], chunk_index: int) -> bool:
        messages = copy.deepcopy(prefix)
        if chunk_index:
            messages.append({
                "role": "user",
                "content": f"[System Note: continuation window {chunk_index + 1} of the same autonomous run.]",
            })
        for unit in grouped_units:
            messages.extend(copy.deepcopy(unit))
        tools = select_tools(original_tools, messages, distractors)
        fitted, length, truncated = fit_chunk(tokenizer, messages, tools, max_length)
        if length > max_length:
            stats["oversized_skipped"] += 1
            return False
        metadata = copy.deepcopy(row.get("metadata") or {})
        metadata.update({
            "prepared_for": "Qwen/Qwen2.5-3B-Instruct",
            "source_max_length": max_length,
            "source_trace_window": chunk_index,
            "content_truncated": truncated,
        })
        chunks.append({"messages": fitted, "tools": tools, "metadata": metadata})
        stats["truncated"] += int(truncated)
        stats["max_tokens"] = max(stats["max_tokens"], length)
        return True

    for unit in units:
        candidate = active + [unit]
        probe_messages = copy.deepcopy(prefix)
        if chunks:
            probe_messages.append({"role": "user", "content": "[System Note: continuation window.]"})
        for item in candidate:
            probe_messages.extend(item)
        probe_tools = select_tools(original_tools, probe_messages, distractors)
        if rendered_tokens(tokenizer, probe_messages, probe_tools) <= max_length:
            active = candidate
            continue
        if active:
            materialize(active, len(chunks))
            active = [unit]
        else:
            materialize([unit], len(chunks))
            active = []
    if active:
        materialize(active, len(chunks))
    stats["chunks"] += len(chunks)
    return chunks, stats


def prepare_expert(tokenizer, input_path: Path, output_path: Path, max_length: int, distractors: int) -> Counter:
    totals: Counter = Counter()
    temp_path = output_path.with_suffix(output_path.suffix + ".tmp")
    with input_path.open(encoding="utf-8") as source, temp_path.open("w", encoding="utf-8") as target:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            totals["traces"] += 1
            try:
                row = json.loads(line)
                chunks, stats = build_chunks(tokenizer, row, max_length, distractors)
            except Exception as exc:
                totals["errors"] += 1
                if totals["errors"] <= 10:
                    print(f"{input_path}:{line_number}: {exc}")
                continue
            row_max_tokens = stats.pop("max_tokens", 0)
            totals.update(stats)
            totals["max_tokens"] = max(totals["max_tokens"], row_max_tokens)
            for chunk in chunks:
                target.write(json.dumps(chunk, ensure_ascii=False, separators=(",", ":")) + "\n")
            if line_number % 500 == 0:
                print(f"{input_path.name}: {line_number} traces -> {totals['chunks']} chunks")
    temp_path.replace(output_path)
    return totals


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="Qwen/Qwen2.5-3B-Instruct")
    parser.add_argument("--input-dir", type=Path, default=Path("data/finetuning"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/finetuning"))
    parser.add_argument("--experts", nargs="+", choices=EXPERTS, default=list(EXPERTS))
    parser.add_argument("--distractor-tools", type=int, default=2)
    parser.add_argument("--max-length", type=int, help="Override all expert context limits")
    args = parser.parse_args()

    tokenizer = AutoTokenizer.from_pretrained(args.model)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    failed = False
    for expert in args.experts:
        input_path = args.input_dir / expert / f"{expert}_moe_dataset_v2.jsonl"
        output_path = args.output_dir / expert / f"{expert}_moe_dataset_3b.jsonl"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        max_length = args.max_length or DEFAULT_LENGTHS[expert]
        if not input_path.is_file():
            print(f"Missing {input_path}")
            failed = True
            continue
        totals = prepare_expert(tokenizer, input_path, output_path, max_length, args.distractor_tools)
        print(
            f"{expert}: {totals['traces']} traces -> {totals['chunks']} chunks; "
            f"truncated={totals['truncated']}, skipped={totals['oversized_skipped']}, "
            f"errors={totals['errors']}, max_tokens={totals['max_tokens']}"
        )
        failed |= bool(totals["errors"] or totals["oversized_skipped"])
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
