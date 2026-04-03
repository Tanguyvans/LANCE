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
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).parent.parent / "skills"


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


def cve_search(query: str, top_k: int = 5) -> str:
    """Cache-then-query CVE lookup.

    Searches ChromaDB first. On cache miss, queries NVD live,
    stores results, and returns them.
    """
    try:
        from src.agent.knowledge.store import get_or_fetch
        from src.cve_lookup import query_nvd

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
                }
                for r in results
            ]

        try:
            results = get_or_fetch(
                "cve_knowledge", query, fetch_fn=fetch_from_nvd, top_k=top_k,
                threshold=0.65,
            )
        except Exception as store_err:
            log.warning("ChromaDB/Voyage unavailable (%s), falling back to NVD direct", store_err)
            results = fetch_from_nvd(query)[:top_k]
        return json.dumps(results, ensure_ascii=False)
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
        "description": "Search for CVEs by CPE string or keyword. Checks local knowledge store first (fast), falls back to live NVD API on cache miss (slower). Results are cached for future searches.",
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
