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
    max_tokens: int = 4096
    user_message: str = ""
    conditional: str | None = None
    description: str = ""
    has_device_agents: bool = False
    has_exploit_agents: bool = False
    deterministic_aggregation: bool = False
    skill_filter: dict[str, list[str]] | None = None


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
        user_message="Analyze the NATO Smart City IoT lab topology and identify the attack surface.",
        description="Topology analysis, attack surface, critical paths",
    ),
    "recon": AgentConfig(
        name="recon",
        phase=2,
        prompt_template="recon",
        deliverable_file="02_recon.md",
        tools=["graph", "recon", "deliverable", "skill"],
        prerequisites=["graph_analysis"],
        validator="markdown_with_sections",
        max_turns=20,
        user_message="Run network reconnaissance on the lab based on the Phase 1 analysis.",
        description="nmap scan, service discovery, compare with YAML model",
        skill_filter={"tags": ["mqtt", "ssh", "http", "lorawan", "zigbee", "router"]},
    ),
    "vuln_analysis": AgentConfig(
        name="vuln_analysis",
        phase=3,
        prompt_template="vuln_analysis",
        deliverable_file="03_vuln_analysis.json",
        tools=["graph", "recon", "deliverable", "skill"],
        prerequisites=["recon"],
        validator="json_vuln_queue",
        max_turns=25,
        user_message="Aggregate vulnerability results from device sub-agents into a unified deliverable.",
        description="Deterministic aggregation of per-device vuln results",
        has_device_agents=True,
        deterministic_aggregation=True,
        skill_filter={"tags": ["mqtt", "ssh", "http", "firmware", "lorawan", "zigbee", "router"]},
    ),
    "exploitation": AgentConfig(
        name="exploitation",
        phase=4,
        prompt_template="exploitation",
        deliverable_file="04_exploitation.json",
        tools=["graph", "recon", "deliverable", "skill"],
        prerequisites=["vuln_analysis"],
        validator="json_exploitation",
        max_turns=10,
        max_tokens=2048,
        user_message="Exploit each vulnerability to prove impact.",
        conditional="03_vuln_analysis.json",
        description="Per-vuln exploit agents + deterministic aggregation",
        has_exploit_agents=True,
        skill_filter={"tags": ["mqtt", "ssh", "http", "firmware"]},
    ),
    "report": AgentConfig(
        name="report",
        phase=5,
        prompt_template="report",
        deliverable_file="05_report.md",
        tools=["graph", "deliverable", "skill"],
        prerequisites=["exploitation"],
        validator="markdown_with_sections",
        max_turns=20,
        max_tokens=16384,
        user_message="Compile the final pentest report from all previous deliverables.",
        description="Compile all findings into structured report",
        skill_filter={"tags": ["report", "methodology"]},
    ),
}
