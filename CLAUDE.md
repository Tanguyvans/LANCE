# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NATO Smart City IoT security analysis platform. Models a physical IoT lab network (192.168.88.0/24) as a directed graph to detect multi-hop attack paths. A multi-phase LLM agent pipeline (inspired by Shannon/LLMDFA) analyzes the enriched graph to find vulnerabilities and generate pentest reports.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run all tests (need plugin workaround for this environment)
python3 -m pytest tests/ -v -p no:pytest_ethereum -p no:web3

# Run a single test
python3 -m pytest tests/test_loader.py::TestGraphBackend::test_path_em310_to_rpi5 -v -p no:pytest_ethereum -p no:web3

# Generate interactive HTML visualization
python3 -m src.visualize
# Output: output/nato_lab.html

# CVE lookup by CPE
python3 -m src.cve_cli --cpe "cpe:2.3:a:mosquitto:mosquitto:2.0.21:*:*:*:*:*:*:*"

# Risk scoring analysis
python3 -m src.risk_cli

# Run the LLM agent pipeline
python3 -m src.agent --provider anthropic --model claude-sonnet-4-20250514
python3 -m src.agent --provider openrouter --model google/gemini-2.5-flash-preview
python3 -m src.agent --dry-run          # validate without calling LLM
python3 -m src.agent --phases 1 3 5     # run specific phases only
python3 -m src.agent --verbose           # detailed output
```

## Architecture

**Data flow:** YAML infrastructure → dataclasses → graph backend → analysis modules → LLM agent pipeline → reports

### Core Modules (Phase 1–3)

- `infrastructure/nato_lab.yaml` — Single source of truth for the lab topology (15 devices, 16 links, networks, external entities). All device IDs referenced in links must exist as device or external entries.
- `infrastructure/cpe_mapping.yaml` — Exact CPE strings mapping devices/services to NVD identifiers for CVE lookup.
- `src/models.py` — Pure dataclasses (`Device`, `Service`, `Link`, `Network`, `ExternalEntity`, `Infrastructure`). No ORM, no logic.
- `src/graph_backend.py` — Abstract `GraphBackend` ABC defining the query interface (`get_neighbors`, `find_all_paths`, `get_attack_surface`, `to_dict`). `NetworkXBackend` implements it with a `nx.DiGraph`. The ABC exists so other backends (Memgraph, Neo4j) can be swapped in.
- `src/loader.py` — `load_yaml()` parses YAML into dataclasses; `build_graph()` populates a backend. Main entry point used by tests, visualization, and agent tools.
- `src/visualize.py` — Generates pyvis HTML. Color-codes nodes by device type, styles edges by protocol.
- `src/cve_lookup.py` — NIST NVD API client. Queries CVEs by CPE, parses CVSS 3.1/2.0, rate-limited (5 sec/request).
- `src/cve_cli.py` — CLI wrapper for CVE lookup by CPE or keyword.
- `src/risk_scorer.py` — Risk scoring: CVSS max + network exposure (hop distance) + betweenness centrality.
- `src/risk_cli.py` — CLI wrapper for risk scoring analysis.
- `src/attack_path.py` — Dijkstra-based attack path analysis. Weights edges by CVSS exploitability and protocol factors. Identifies pivots (high betweenness), choke points, multi-hop chains.

### LLM Agent Pipeline (Phase 4–5)

- `src/agent/__main__.py` — CLI entry point. Accepts `--provider`, `--model`, `--dry-run`, `--phases`, `--verbose`.
- `src/agent/provider.py` — LLM provider abstraction. Translates tool schemas between Anthropic (native `tool_use`) and OpenAI-compatible APIs (function calling). Supports multi-turn agentic loops. Providers: Anthropic, OpenRouter, MiniMax, GLM, Qwen.
- `src/agent/registry.py` — Declarative agent config. 5 agents across 5 phases, each with name, prompt, tool groups, prerequisites, and validators.
- `src/agent/pipeline.py` — Pipeline orchestrator. Executes agents in phase sequence, resolves tool groups (graph/recon/deliverable/skill), passes deliverables between phases, tracks cost.
- `src/agent/prompt_manager.py` — Loads prompt templates from `prompts/*.txt` with variable substitution (`{lab_context}`, `{previous_findings}`).
- `src/agent/cost_tracker.py` — Token/cost tracking per phase. Pricing tables for Anthropic, MiniMax, GLM, Qwen, Gemini, DeepSeek.

### Agent Tools

- `src/agent/tools/graph_tools.py` — Exposes Phase 1–3 analysis to agents: `load_lab_context()`, `get_attack_surface()`, `get_risk_scores()`, `get_device_info()`.
- `src/agent/tools/recon_tools.py` — YAML-based network recon tools (`_run()` subprocess runner, `nvd_lookup()` Python handler). `RECON_TOOLS` is auto-generated from YAML definitions at import time.
- `src/agent/tools/tool_loader.py` — YAML-to-tool engine. Loads declarative tool definitions from `definitions/*.yaml`, builds JSON Schema and subprocess functions. Supports positional, flag, and port_suffix parameter formats.
- `src/agent/tools/definitions/` — Declarative YAML tool definitions: `nmap.yaml`, `ssh_audit.yaml`, `curl_headers.yaml`, `mqtt_listen.yaml`, `nvd_lookup.yaml`. Add new recon tools here (no Python needed for subprocess tools).
- `src/agent/tools/skill_tools.py` — IoT security skill tools: `list_skills()`, `load_skill()`, `search_knowledge()` (ChromaDB semantic search), `cve_search()` (cache-then-query NVD).
- `src/agent/tools/deliverable.py` — File I/O: `save_deliverable()` (JSON/Markdown), `read_deliverable()`, `list_deliverables()`.
- `src/agent/validators/__init__.py` — Output validators: `markdown_with_sections()`, `json_valid()`, `file_exists()`.

### Agent Prompt Templates

- `src/agent/prompts/graph_analysis.txt` — Phase 1: Topology analysis
- `src/agent/prompts/recon.txt` — Phase 2: Network reconnaissance
- `src/agent/prompts/vuln_analysis.txt` — Phase 3: Vulnerability analysis
- `src/agent/prompts/vuln_device.txt` — Per-device vulnerability analysis
- `src/agent/prompts/exploitation.txt` — Phase 4: Exploitation strategies
- `src/agent/prompts/report.txt` — Phase 5: Final report generation
- `src/agent/prompts/shared/_tools.txt`, `_target.txt`, `_rules.txt` — Shared context

### Knowledge Store & Skills

- `src/agent/knowledge/store.py` — ChromaDB wrapper with Voyage AI embeddings (`voyage-3.5-lite`, 512 dims). Persistent storage at `data/knowledge.db`. Key functions: `search()`, `ingest()`, `get_or_fetch()` (cache-then-query).
- `src/agent/knowledge/embedder.py` — Voyage AI embedding client. Requires `VOYAGE_API_KEY` env var.
- `src/agent/knowledge/ingest.py` — Bulk ingestion for CVE reports and skill Markdown files. Chunks skills by `##` headings with context prefix for RAG.
- `src/agent/skills/` — IoT security skill Markdown files with YAML frontmatter (name, tags, tools, device_types, cpe_patterns): `mqtt_security.md`, `ssh_hardening.md`, `lorawan_analysis.md`, `mikrotik_routeros.md`, `web_service_analysis.md`, `firmware_analysis.md`.

## Key Conventions

- The graph is **directed** (`DiGraph`), but `find_all_paths` uses an undirected view to find reachable paths in both directions.
- "Attack surface" = devices that expose services (have open ports). Sensors with only wireless protocols (lorawan/zigbee) and no services are excluded.
- Device types: `router`, `switch`, `gateway`, `sensor`, `compute`, `camera`, `ap`, `external`.
- Link types: `ethernet`, `lorawan`, `zigbee`, `mqtt`, `wan`.
- When modifying the YAML topology, update test assertions (device/link counts, neighbor sets) accordingly.
- Language: code and comments in English, infrastructure descriptions in French.
- Agent pipeline outputs go to `output/agent/<timestamp>/` with numbered deliverables (01_graph_analysis.md, 02_recon.md, etc.).
- Environment variables (API keys) loaded from `.env` via python-dotenv.

## Tests

14 test files, ~191 test functions covering all modules:

| File | Coverage |
|------|----------|
| `test_loader.py` | YAML loading, device/link counts, neighbors, paths, attack surface |
| `test_cve_lookup.py` | CVE parsing, CVSS 3.1/2.0, NVD queries, rate limiting |
| `test_risk_scorer.py` | CVSS scoring, betweenness centrality, hop distance, exposure |
| `test_attack_path.py` | Edge weighting, path scoring, pivot detection, exploit probability |
| `test_pipeline.py` | Tool resolution, dry-run, prerequisites, phase execution |
| `test_registry.py` | Agent config validation, unique phases, deliverables |
| `test_prompt_manager.py` | Variable substitution, prompt loading |
| `test_cost_tracker.py` | Token counting, pricing, per-phase costs |
| `test_agent_tools.py` | YAML-generated recon tools (nmap, ssh_audit, curl, mqtt), nvd_lookup, provider |
| `test_tool_loader.py` | YAML parsing, schema generation, subprocess function generation |
| `test_skill_tools.py` | Skill listing, loading, frontmatter parsing, tool definitions |
| `test_deliverable_tools.py` | File save/read, directory listing |
| `test_validators.py` | Markdown validation, required sections |

## Dependencies

```
networkx>=3.0          # Graph backend, path analysis
pyyaml>=6.0            # YAML infrastructure loading
pyvis>=0.3.2           # Interactive HTML visualization
pytest>=8.0            # Test framework
requests>=2.31         # HTTP for NVD API
anthropic>=0.40.0      # Anthropic API (primary LLM)
openai>=1.50.0         # OpenAI-compatible API (OpenRouter, MiniMax, GLM, Qwen)
python-dotenv>=1.0.0   # Environment variable loading
chromadb>=0.5.0        # Vector database for knowledge store
voyageai>=0.3.0        # Voyage AI embeddings (voyage-3.5-lite)
```

## Current Status & Next Steps

### Phase 1 — Graph modeling + visualization (DONE)
- Directed graph (NetworkX DiGraph) modeling of 15 devices, 16 links
- pyvis HTML visualization with color-coded nodes/edges

### Phase 2 — CVE enrichment & risk scoring (DONE)
- NIST NVD module with CPE mapping (24 CVEs across 5 devices)
- Risk scoring: MikroTik (6.6) and WisGate (5.6) highest risk

### Phase 3 — Attack path analysis (DONE)
- Dijkstra-weighted edges by CVSS exploitability + protocol factors
- Critical paths detected (e.g., Internet → MikroTik → Netgear → WisGate → MQTT)
- Pivot points identified (Netgear betweenness 0.72, WisGate 0.48)

### Phase 4 — LLM agent pentester (DONE)
- Multi-phase pipeline: graph analysis → recon → vuln analysis → exploitation → report
- Multi-provider support: Anthropic, OpenRouter, MiniMax, GLM, Qwen
- Tool-calling architecture with graph, recon, and deliverable tool groups
- Cost tracking per phase with per-model pricing
- Dry-run mode for validation without API calls

### Phase 5 — Pentest progressif (IN PROGRESS)
- Tests safe sur le lab réel : MQTT sans auth, SSH default creds, Terrapin scan
- Tests destructifs sur containers Docker (nginx:1.19.6, Dropbear, MikroTik CHR)
- Difficulté croissante : device unique → chaînage 2 hops → scénario multi-hop complet
