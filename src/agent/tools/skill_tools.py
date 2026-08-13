"""Skill and knowledge tools exposed to LLM agents.

Provides:
  - list_skills(): discover available IoT security skills
  - load_skill(): load a full skill document
  - search_knowledge(): semantic search across ChromaDB collections
  - cve_search(): cache-then-query CVE lookup
"""

from __future__ import annotations

import json
import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).parent.parent / "skills"


# Official benchmark runs must be reproducible: a cache miss must not silently
# change the CVE knowledge source by querying NVD and ingesting fresh results.
# This is configured by Pipeline for benchmark-scoped runs and deliberately
# remains opt-in for ordinary development/tool use.
_CVE_CACHE_ONLY = False


def set_cve_cache_only(enabled: bool) -> None:
    """Use only the persistent CVE cache until the next pipeline is started."""
    global _CVE_CACHE_ONLY
    _CVE_CACHE_ONLY = bool(enabled)


def cve_cache_only_enabled() -> bool:
    """Return whether live CVE fetches are disabled for the current process."""
    return _CVE_CACHE_ONLY


# ── Frontmatter parsing ─────────────────────────────────────────

def _parse_skill_file(path: Path) -> dict[str, Any]:
    """Parse a skill Markdown file with YAML frontmatter.

    Returns {"meta": {frontmatter dict}, "content": "markdown body"}.
    """
    text = path.read_text(encoding="utf-8")
    meta: dict[str, Any] = {}
    content = text

    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            try:
                meta = yaml.safe_load(parts[1]) or {}
            except yaml.YAMLError:
                pass
            content = parts[2].strip()

    return {"meta": meta, "content": content}


# ── Active skill filter (set by pipeline per phase) ─────────────

_active_filter_tags: set[str] | None = None


def set_skill_filter(tags: list[str] | None) -> None:
    """Set the active skill filter (called by pipeline before each phase).

    When set, list_skills() and load_skill() only expose skills
    whose tags intersect with the filter. Pass None to clear.
    """
    global _active_filter_tags
    _active_filter_tags = set(tags) if tags else None


def _skill_matches_filter(skill_tags: list[str]) -> bool:
    """Check if a skill's tags pass the active filter."""
    if _active_filter_tags is None:
        return True
    return bool(set(skill_tags) & _active_filter_tags)


# ── Skill functions ──────────────────────────────────────────────

def get_skills_metadata() -> list[dict]:
    """Return skill metadata as Python objects (internal API).

    Not affected by the active filter — returns all skills.
    """
    if not SKILLS_DIR.exists():
        return []

    skills = []
    for md_file in sorted(SKILLS_DIR.glob("*.md")):
        parsed = _parse_skill_file(md_file)
        meta = parsed["meta"]

        skills.append({
            "name": meta.get("name", md_file.stem),
            "description": meta.get("description", ""),
            "tags": meta.get("tags", []),
            "tools": meta.get("tools", []),
            "device_types": meta.get("device_types", []),
            "file": md_file.name,
        })

    return skills


def list_skills() -> str:
    """List available IoT security skills with metadata.

    Respects the active skill filter set by the pipeline.
    """
    skills = [s for s in get_skills_metadata() if _skill_matches_filter(s["tags"])]
    if not skills and not SKILLS_DIR.exists():
        return json.dumps({"error": "Skills directory not found"})
    return json.dumps(skills, ensure_ascii=False)


def load_skill(skill_name: str) -> str:
    """Load a full skill document by name, including metadata.

    Respects the active skill filter — blocks loading skills outside the filter.
    """
    md_path = SKILLS_DIR / f"{skill_name}.md"
    if not md_path.exists():
        available = [s["name"] for s in get_skills_metadata() if _skill_matches_filter(s["tags"])]
        return json.dumps({
            "error": f"Skill '{skill_name}' not found",
            "available": available,
        })

    parsed = _parse_skill_file(md_path)
    meta = parsed["meta"]

    # Hard filter: block loading skills outside the active filter
    if not _skill_matches_filter(meta.get("tags", [])):
        available = [s["name"] for s in get_skills_metadata() if _skill_matches_filter(s["tags"])]
        return json.dumps({
            "error": f"Skill '{skill_name}' is not available for this phase",
            "available": available,
        })

    return json.dumps({
        "skill": skill_name,
        "meta": meta,
        "content": parsed["content"],
    }, ensure_ascii=False)


# ── Knowledge search functions ───────────────────────────────────

def search_knowledge(
    query: str,
    collection: str = "cve_knowledge",
    top_k: int = 5,
    where: dict | None = None,
) -> str:
    """Semantic search across knowledge store collections.

    Collections: cve_knowledge, skills, run_history
    When searching 'skills', results are filtered by the active skill filter.
    """
    try:
        from src.agent.knowledge.store import search
        results = search(collection, query, top_k=top_k, where=where)

        # Hard filter: when searching skills, only return chunks from allowed skills
        if collection == "skills" and _active_filter_tags is not None:
            allowed_names = {
                s["name"] for s in get_skills_metadata()
                if _skill_matches_filter(s["tags"])
            }
            results = [
                r for r in results
                if r.get("metadata", {}).get("skill_name") in allowed_names
            ]

        return json.dumps(results, ensure_ascii=False)
    except Exception as e:
        log.error("Knowledge search failed: %s", e)
        return json.dumps({"error": str(e)})


_CVE_BENCHMARK_SNAPSHOT = (
    Path(__file__).resolve().parents[2] / "benchmark" / "cve_snapshot.json"
)


def _normalise_cve_query(query: str) -> str:
    return " ".join(str(query or "").casefold().split())


@lru_cache(maxsize=1)
def _load_cve_benchmark_snapshot() -> tuple[dict, ...]:
    """Load the immutable CVE reference once per worker process."""
    try:
        payload = json.loads(_CVE_BENCHMARK_SNAPSHOT.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        log.error("Benchmark CVE snapshot unavailable: %s", exc)
        return ()
    if payload.get("schema_version") != 1:
        log.error("Unsupported benchmark CVE snapshot schema: %s", payload.get("schema_version"))
        return ()
    return tuple(
        entry for entry in payload.get("entries", [])
        if isinstance(entry, dict) and isinstance(entry.get("results"), list)
    )


def _benchmark_cve_results(query: str, limit: int) -> list[dict]:
    """Resolve a benchmark CVE query without touching persistent knowledge storage."""
    entries = _load_cve_benchmark_snapshot()
    if not entries:
        return []
    normalised = _normalise_cve_query(query)
    exact = [
        entry for entry in entries
        if _normalise_cve_query(entry.get("query", "")) == normalised
    ]
    if exact:
        return [dict(item) for item in exact[0]["results"][:limit]]

    # Models often add a product suffix or a version qualifier. Use a small,
    # deterministic lexical fallback over the frozen query catalogue; never
    # fall back to ChromaDB or NVD for an unknown benchmark query.
    query_tokens = set(re.findall(r"[a-z0-9][a-z0-9_.:-]*", normalised))
    scored: list[tuple[int, str, dict]] = []
    for entry in entries:
        entry_query = _normalise_cve_query(entry.get("query", ""))
        overlap = len(query_tokens & set(re.findall(r"[a-z0-9][a-z0-9_.:-]*", entry_query)))
        if overlap:
            scored.append((overlap, entry_query, entry))
    if not scored:
        return []
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [dict(item) for item in scored[0][2]["results"][:limit]]


def cve_search(query: str, top_k: int = 5) -> str:
    """Look up CVEs from the live source or the immutable benchmark snapshot.

    Development runs retain cache-then-query behavior. Benchmark-scoped runs
    read only the versioned snapshot and never consult ChromaDB or NVD.
    """
    try:
        from src.agent.knowledge.store import get_or_fetch
        from src.cve_lookup import (
            classify_cve_compatibility,
            query_nvd,
        )

        def fetch_from_nvd(q: str) -> list[dict]:
            api_key = os.environ.get("NVD_API_KEY")
            results = query_nvd(q, api_key)
            return [
                {
                    "id": r.cve_id,
                    "document": (
                        f"{r.cve_id}: {r.description} "
                        f"(CVSS {r.cvss_score}, {r.severity})"
                    ),
                    "cve_id": r.cve_id,
                    "cvss_score": float(r.cvss_score) if r.cvss_score else 0.0,
                    "severity": r.severity or "UNKNOWN",
                    "attack_vector": r.attack_vector or "UNKNOWN",
                    "description": r.description,
                    "affected_cpes_json": json.dumps(r.cpe_matches, separators=(",", ":")),
                    "compatibility_status": r.compatibility_status,
                    "compatibility_reason": r.compatibility_reason,
                    "matched_cpes_json": json.dumps(r.matched_cpes, separators=(",", ":")),
                }
                for r in results
            ]

        def annotate_result(item: dict) -> dict:
            metadata = item.get("metadata") or item
            raw_matches = metadata.get("affected_cpes_json", "[]")
            try:
                matches = json.loads(raw_matches)
            except (TypeError, ValueError, json.JSONDecodeError):
                matches = []
            assessment = classify_cve_compatibility(query, matches)
            annotated = dict(item)
            annotated["compatibility"] = {
                "status": assessment.status,
                "reason": assessment.reason,
                "matched_cpes": assessment.matched_cpes,
            }
            return annotated

        # Retrieve a wider cache window before ranking: semantic similarity
        # alone can otherwise let an incompatible candidate crowd a more
        # useful compatible candidate out of a small top_k response.
        cache_k = max(top_k * 4, 20)
        try:
            if _CVE_CACHE_ONLY:
                # Benchmark runs must be independent of the mutable ChromaDB
                # cache on nato-master. The frozen snapshot is the only source.
                results = _benchmark_cve_results(query, cache_k)
                if not results:
                    log.warning(
                        "CVE snapshot miss for '%s' in benchmark cache-only mode; "
                        "persistent cache and live NVD lookup disabled",
                        query,
                    )
            else:
                results = get_or_fetch(
                    "cve_knowledge", query, fetch_fn=fetch_from_nvd, top_k=cache_k,
                    threshold=0.62,
                )
        except Exception as store_err:
            if _CVE_CACHE_ONLY:
                log.warning(
                    "CVE cache unavailable (%s); live NVD lookup disabled",
                    store_err,
                )
                results = []
            else:
                log.warning(
                    "ChromaDB/Voyage unavailable (%s), falling back to NVD direct",
                    store_err,
                )
                results = fetch_from_nvd(query)[:top_k]
        annotated = [annotate_result(item) for item in results]
        priority = {"compatible": 0, "conditional": 1, "indeterminate": 2, "incompatible": 3}
        annotated.sort(key=lambda item: priority[item["compatibility"]["status"]])
        return json.dumps(annotated[:top_k], ensure_ascii=False)
    except Exception as e:
        log.error("CVE search failed: %s", e)
        return json.dumps({"error": str(e)})


# ── Run history search ──────────────────────────────────────────

def search_history(query: str, device_id: str | None = None, top_k: int = 5) -> str:
    """Search previous run findings for a device or vulnerability type.

    Delegates to search_knowledge with run_history collection and optional device filter.
    """
    where = {"device_id": device_id} if device_id else None
    return search_knowledge(query, collection="run_history", top_k=top_k, where=where)


# ── Tool definitions (for the provider) ──────────────────────────

SKILL_TOOLS = [
    {
        "name": "list_skills",
        "description": "List available IoT security skills (MQTT, SSH, LoRaWAN, firmware, etc.) with their descriptions.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "function": list_skills,
    },
    {
        "name": "load_skill",
        "description": "Load a full IoT security skill document by name. Use list_skills() first to see available skills.",
        "input_schema": {
            "type": "object",
            "properties": {
                "skill_name": {
                    "type": "string",
                    "description": "Skill name (e.g. 'mqtt_security', 'ssh_hardening', 'lorawan_analysis')",
                },
            },
            "required": ["skill_name"],
        },
        "function": load_skill,
    },
    {
        "name": "search_knowledge",
        "description": "Semantic search across the knowledge store. Search for CVEs, attack patterns, or IoT security topics by natural language query.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural language search query (e.g. 'MQTT broker without authentication', 'SSH Terrapin vulnerability')",
                },
                "collection": {
                    "type": "string",
                    "description": "Collection to search: 'cve_knowledge' or 'skills' (default: cve_knowledge)",
                    "default": "cve_knowledge",
                },
                "top_k": {
                    "type": "integer",
                    "description": "Number of results to return (default: 5)",
                    "default": 5,
                },
            },
            "required": ["query"],
        },
        "function": search_knowledge,
    },
    {
        "name": "cve_search",
        "description": "Search for CVEs by CPE string or software+version. Every candidate is returned with a compatibility classification (compatible, conditional, indeterminate, or incompatible) derived from NVD CPE ranges; classification ranks evidence but never deletes candidates. Product-only queries remain indeterminate until a version is confirmed.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "CPE 2.3 string or keyword (e.g. 'cpe:2.3:a:eclipse:mosquitto:2.0.21:*:*:*:*:*:*:*' or 'MikroTik RouterOS')",
                },
                "top_k": {
                    "type": "integer",
                    "description": "Number of results to return (default: 5)",
                    "default": 5,
                },
            },
            "required": ["query"],
        },
        "function": cve_search,
    },
    {
        "name": "search_history",
        "description": "Search previous pipeline run findings. Returns past vulnerability test results for a device or vulnerability type. Useful to avoid re-testing known issues or to compare results across runs.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural language query (e.g. 'MQTT anonymous access on rpi5', 'SSH weak ciphers')",
                },
                "device_id": {
                    "type": "string",
                    "description": "Optional device ID to filter results (e.g. 'rpi5', 'mikrotik')",
                },
                "top_k": {
                    "type": "integer",
                    "description": "Number of results to return (default: 5)",
                    "default": 5,
                },
            },
            "required": ["query"],
        },
        "function": search_history,
    },
]
