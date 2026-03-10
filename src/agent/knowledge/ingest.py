"""Bulk ingestion utilities for populating the knowledge store.

Supports:
  - CVE ingestion from NVD (via existing cve_lookup module)
  - Skill ingestion from Markdown files
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from src.agent.knowledge.store import ingest, collection_stats

log = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).parent.parent / "skills"


def _parse_frontmatter(content: str) -> tuple[dict, str]:
    """Extract YAML frontmatter from Markdown content.

    Returns (metadata_dict, body_without_frontmatter).
    """
    if not content.startswith("---"):
        return {}, content

    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, content

    try:
        meta = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        meta = {}

    return meta, parts[2].strip()


def ingest_cve_reports(cve_reports: list) -> int:
    """Ingest CVE reports (from cve_lookup.scan_all_devices) into ChromaDB.

    Each CVE becomes a document with its description, metadata includes
    cve_id, cvss_score, severity, attack_vector.
    """
    documents = []
    metadatas = []
    ids = []

    for report in cve_reports:
        for cve in report.cves:
            doc = (
                f"{cve.cve_id}: {cve.description} "
                f"(CVSS {cve.cvss_score}, {cve.severity}, "
                f"vector: {cve.attack_vector})"
            )
            documents.append(doc)
            metadatas.append({
                "cve_id": cve.cve_id,
                "cvss_score": float(cve.cvss_score) if cve.cvss_score else 0.0,
                "severity": cve.severity or "UNKNOWN",
                "attack_vector": cve.attack_vector or "UNKNOWN",
                "device_id": report.device_id,
            })
            ids.append(cve.cve_id)

    if not documents:
        log.info("No CVEs to ingest")
        return 0

    count = ingest("cve_knowledge", documents=documents, metadatas=metadatas, ids=ids)
    log.info("Ingested %d CVEs into cve_knowledge", count)
    return count


def ingest_skills(skills_dir: Path | None = None) -> int:
    """Ingest skill Markdown files into ChromaDB.

    Each skill file is chunked by section (## headings) and each chunk
    becomes a separate document for better retrieval granularity.
    """
    skills_dir = skills_dir or SKILLS_DIR
    if not skills_dir.exists():
        log.warning("Skills directory not found: %s", skills_dir)
        return 0

    documents = []
    metadatas = []
    ids = []

    for md_file in sorted(skills_dir.glob("*.md")):
        raw = md_file.read_text(encoding="utf-8")
        meta, body = _parse_frontmatter(raw)

        skill_name = meta.get("name", md_file.stem)
        description = meta.get("description", "")
        tags = meta.get("tags", [])

        # Prefix each chunk with skill context so ChromaDB retrieval
        # knows which skill the chunk belongs to
        context_prefix = f"[Skill: {skill_name}] {description}\n\n"

        chunks = _chunk_by_sections(body)

        for i, chunk in enumerate(chunks):
            if len(chunk.strip()) < 20:
                continue
            documents.append(context_prefix + chunk)
            metadatas.append({
                "skill_name": skill_name,
                "description": description,
                "tags": ",".join(tags) if tags else "",
                "chunk_index": i,
                "source_file": str(md_file.name),
            })
            ids.append(f"skill_{skill_name}_{i}")

    if not documents:
        log.info("No skills to ingest")
        return 0

    count = ingest("skills", documents=documents, metadatas=metadatas, ids=ids)
    log.info("Ingested %d skill chunks into skills", count)
    return count


def _chunk_by_sections(content: str, max_chunk_size: int = 512) -> list[str]:
    """Split Markdown content by ## headings into chunks.

    If a section exceeds max_chunk_size tokens (rough approximation: words),
    it's split further by paragraphs.
    """
    lines = content.split("\n")
    chunks = []
    current_chunk: list[str] = []

    for line in lines:
        if line.startswith("## ") and current_chunk:
            chunks.append("\n".join(current_chunk))
            current_chunk = [line]
        else:
            current_chunk.append(line)

    if current_chunk:
        chunks.append("\n".join(current_chunk))

    final_chunks = []
    for chunk in chunks:
        words = chunk.split()
        if len(words) > max_chunk_size:
            paragraphs = chunk.split("\n\n")
            sub_chunk: list[str] = []
            sub_words = 0
            for para in paragraphs:
                para_words = len(para.split())
                if sub_words + para_words > max_chunk_size and sub_chunk:
                    final_chunks.append("\n\n".join(sub_chunk))
                    sub_chunk = [para]
                    sub_words = para_words
                else:
                    sub_chunk.append(para)
                    sub_words += para_words
            if sub_chunk:
                final_chunks.append("\n\n".join(sub_chunk))
        else:
            final_chunks.append(chunk)

    return final_chunks


def ingest_all() -> dict[str, int]:
    """Run all ingestion pipelines. Returns {collection: count} dict."""
    results = {}
    results["skills"] = ingest_skills()
    stats = {
        name: collection_stats(name)
        for name in ["cve_knowledge", "skills"]
    }
    log.info("Knowledge store stats: %s", stats)
    return results
