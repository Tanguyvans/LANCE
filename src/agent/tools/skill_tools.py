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


# ── Skill functions ──────────────────────────────────────────────

def list_skills() -> str:
    """List available IoT security skills with metadata."""
    if not SKILLS_DIR.exists():
        return json.dumps({"error": "Skills directory not found"})

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

    return json.dumps(skills, ensure_ascii=False)


def load_skill(skill_name: str) -> str:
    """Load a full skill document by name, including metadata."""
    md_path = SKILLS_DIR / f"{skill_name}.md"
    if not md_path.exists():
        available = [f.stem for f in SKILLS_DIR.glob("*.md")]
        return json.dumps({
            "error": f"Skill '{skill_name}' not found",
            "available": available,
        })

    parsed = _parse_skill_file(md_path)
    return json.dumps({
        "skill": skill_name,
        "meta": parsed["meta"],
        "content": parsed["content"],
    }, ensure_ascii=False)


# ── Knowledge search functions ───────────────────────────────────

def search_knowledge(query: str, collection: str = "cve_knowledge", top_k: int = 5) -> str:
    """Semantic search across knowledge store collections.

    Collections: cve_knowledge, skills
    """
    try:
        from src.agent.knowledge.store import search
        results = search(collection, query, top_k=top_k)
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

        results = get_or_fetch(
            "cve_knowledge", query, fetch_fn=fetch_from_nvd, top_k=top_k
        )
        return json.dumps(results, ensure_ascii=False)
    except Exception as e:
        log.error("CVE search failed: %s", e)
        return json.dumps({"error": str(e)})


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
]
