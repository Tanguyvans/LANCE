"""Agent registry — declarative configuration for each pipeline phase."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AgentConfig:
    name: str
    phase: int
    prompt_template: str
    deliverable_file: str
    tools: list[str]
    prerequisites: list[str] = field(default_factory=list)
    validator: str = "default"
    max_turns: int = 30
    user_message: str = ""
    conditional: str | None = None
    description: str = ""


AGENTS: dict[str, AgentConfig] = {
    "graph_analysis": AgentConfig(
        name="graph_analysis",
        phase=1,
        prompt_template="graph_analysis",
        deliverable_file="01_graph_analysis.md",
        tools=["graph", "deliverable"],
        prerequisites=[],
        validator="markdown_with_sections",
        max_turns=20,
        user_message="Analyse la topologie du lab NATO Smart City IoT et identifie la surface d'attaque.",
        description="Topology analysis, attack surface, critical paths",
    ),
    "recon": AgentConfig(
        name="recon",
        phase=2,
        prompt_template="recon",
        deliverable_file="02_recon.md",
        tools=["graph", "recon", "deliverable"],
        prerequisites=["graph_analysis"],
        validator="markdown_with_sections",
        max_turns=30,
        user_message="Lance la reconnaissance réseau du lab en te basant sur l'analyse de la Phase 1.",
        description="nmap scan, service discovery, compare with YAML model",
    ),
    "vuln_analysis": AgentConfig(
        name="vuln_analysis",
        phase=3,
        prompt_template="vuln_analysis",
        deliverable_file="03_vuln_analysis.json",
        tools=["graph", "recon", "deliverable"],
        prerequisites=["recon"],
        validator="json_vuln_queue",
        max_turns=25,
        user_message="Analyse les vulnérabilités des services découverts en Phase 2.",
        description="SSH audit, HTTP headers, MQTT auth checks",
    ),
    "exploitation": AgentConfig(
        name="exploitation",
        phase=4,
        prompt_template="exploitation",
        deliverable_file="04_exploitation.md",
        tools=["recon", "deliverable"],
        prerequisites=["vuln_analysis"],
        validator="markdown_with_sections",
        max_turns=20,
        user_message="Exécute les tests d'exploitation safe sur la queue de vulnérabilités.",
        conditional="03_vuln_analysis.json",
        description="Safe exploitation: MQTT no-auth, default creds check",
    ),
    "report": AgentConfig(
        name="report",
        phase=5,
        prompt_template="report",
        deliverable_file="05_report.md",
        tools=["graph", "deliverable"],
        prerequisites=[],
        validator="markdown_with_sections",
        max_turns=15,
        user_message="Compile le rapport final de pentest à partir de tous les livrables précédents.",
        description="Compile all findings into structured report",
    ),
}
