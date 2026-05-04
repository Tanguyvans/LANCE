# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

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
python3 -m src.agent --provider anthropic --model Codex-sonnet-4-20250514
python3 -m src.agent --provider openrouter --model google/gemini-2.5-flash-preview
python3 -m src.agent --dry-run          # validate without calling LLM
python3 -m src.agent --phases 1 3 5     # run specific phases only
python3 -m src.agent --verbose           # detailed output
python3 -m src.agent --batch "1,2,3"    # run multiple scenarios sequentially, aggregate metrics
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

### LLM Agent Pipeline (Phase 4–6)

- `src/agent/__main__.py` — CLI entry point. Accepts `--provider`, `--model`, `--dry-run`, `--phases`, `--verbose`.
- `src/agent/provider.py` — LLM provider abstraction. Translates tool schemas between Anthropic (native `tool_use`) and OpenAI-compatible APIs (function calling). Supports multi-turn agentic loops. Providers: Anthropic, OpenRouter, MiniMax, GLM, Qwen.
- `src/agent/registry.py` — Declarative agent config. 6 agents across phases 1–6, each with name, prompt, tool groups, prerequisites, and validators.
- `src/agent/pipeline.py` — Pipeline orchestrator. Executes agents in phase sequence, resolves tool groups (graph/recon/deliverable/skill/intrusion), passes deliverables between phases, tracks cost. When a scenario is active, loads scenario topology instead of physical lab. Fallback: if the LLM never calls `save_deliverable`, the last text output is saved automatically. Saves `cost_summary.json` at end of run. Phase 3 aggregation (`_aggregate_device_vulns`) applies deterministic filters in this order: (1) canonicalize types via `vuln_taxonomy.canonicalize`, (2) drop `NOISE_TYPES` and `severity=INFO` findings, (3) severity-aware dedup (keeps the LOWER severity on `(ip, type, port)` collisions to avoid inflating match penalties). Phase 4 aggregation (`_aggregate_exploit_results`) merges per-vuln exploit JSON with Phase 3 via `_make_test_entry` and `_exploit_relpath` helpers. Phase 4 uses `EXPLOIT_INSTRUCTIONS` (credentials / data_access / injection categories) routed via `exploit_category()` from vuln_taxonomy. Phase 5 (`intrusion`) and Phase 6 (`report`) pre-generate context files before their agents run: `_generate_intrusion_context()` → `05_intrusion_context.json`, `_generate_phase6_context()` → `06_phase6_context.json` + `_pregenerate_report_sections()` → `06_report_prefill.md`.
- `src/agent/vuln_taxonomy.py` — Single source of truth for vuln-type taxonomy, shared by pipeline and evaluator. Exports `CANONICAL_TYPES`, `CONFIG_ONLY_TYPES`, `NOISE_TYPES`, `EXPLOIT_CATEGORY_MAP`, `VULN_TYPE_ALIASES`, and the helpers `canonicalize()`, `is_config_only()`, `is_noise()`, `exploit_category()`. Any new vuln type or synonym goes here, not scattered across modules.
- `src/agent/prompt_manager.py` — Loads prompt templates from `prompts/*.txt` with variable substitution (`{lab_context}`, `{previous_deliverables}`, etc.).
- `src/agent/cost_tracker.py` — Token/cost tracking per phase. Pricing tables for Anthropic, MiniMax, GLM, Qwen, Gemini, DeepSeek. `summary()` computes all metrics under a single lock (avoid deadlock on nested lock acquisition).

### FastAPI Backend & Dashboard

- `src/api/main.py` — FastAPI app entry point. Mounts routers, serves static files.
- `src/api/routes/pipeline.py` — Pipeline lifecycle: `POST /api/pipeline/start`, `GET /api/pipeline/stream` (SSE), `POST /api/pipeline/stop`. Runs pipeline in a background thread, streams events to the frontend. `StartRequest` accepts `target_network: str | None` (CIDR) to enable discovery mode.
- `src/api/routes/runs.py` — Run history: `GET /api/runs` (list), `GET /api/runs/{id}` (metadata), `GET /api/runs/{id}/{filename}` (file content), `GET /api/runs/{id}/score` (benchmark evaluation), `GET /api/runs/{id}/download/zip`. **Route order matters**: `score` and `download/zip` must be declared before `/{id}/{filename}`.
- `src/api/routes/topology.py` — `GET /api/topology` — returns lab or scenario graph for Cytoscape. Pass `?empty=true` to get an empty graph (used by Docker discovery mode where nodes are added dynamically as nmap discovers hosts).
- `src/static/app.js` — Single-page dashboard (vanilla JS + Cytoscape.js). Tabs: Dashboard (run config + topology), Benchmark (Recall/Precision/F1/Score table). Dynamically adds Cytoscape nodes when `tool_result` events for `nmap_scan` arrive with previously unseen IPs.
- `src/static/style.css` — Dashboard styles.
- `src/static_docker/index.html` — Simplified end-user dashboard (no Benchmark tab, no scenario selector, no Teardown). Has a "Réseau cible (CIDR)" input field.
- `src/static_docker/app.js` — Simplified JS for end-user Docker image. Starts with an empty graph (`?empty=true`), reads `target_network` from the CIDR input and passes it to the pipeline start request. Nodes are added live as nmap discovers hosts.
- `src/static_v2/index.html` — Internal real-time monitoring dashboard (dark cyberpunk aesthetic, Cytoscape graph with layered rendering, intrusion hop tracking, batch runs, scenario selector). Served at `/v2`. No benchmark evaluation tab.
- `src/static_v2/app.js` — Monitor JS: SSE pipeline stream, phase progress bar, layer toggles, device detail right panel, event log.
- `src/static_v2/style.css` — Glassmorphism dark theme with glowing severity nodes.

### Benchmark Evaluation

- `src/benchmark/evaluator.py` — Compares LLM findings against a ground truth YAML. Computes TP/FP/FN, Recall, Precision, F1, and weighted Score (CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1). Matching strategy: CVE ID → IP+type → IP+category (fallback). Severity mismatches apply a 0.75× multiplier on the matched weight; loose category matches apply 0.5×. Findings are loaded via `_load_llm_findings()`, which prefers `04_exploitation.json` when present (falls back to `03_vuln_analysis.json`) and drops Phase 4 statuses in `_SKIPPED_PHASE4_STATUSES = {"FAILED", "ERROR"}` — this constant is the shared contract with `_aggregate_exploit_results` in pipeline.py.
- `benchmarks/ground_truth/scenario_N.yaml` — Ground truth for each scenario. Each file lists expected vulnerabilities with device IP, severity, category, optional CVE ID, and a `bonus_types` list for finding types that should be tolerated (not counted as FP) when not in the injected set.
- `benchmarks/ansible/` — Ansible playbooks to deploy and inject vulnerabilities into benchmark VMs (`192.168.100.0/24`).

### Agent Tools

- `src/agent/tools/graph_tools.py` — Exposes Phase 1–3 analysis to agents: `load_lab_context()`, `load_scenario_topology()`, `load_discovery_context()`, `get_attack_surface()`, `get_risk_scores()`, `get_device_info()`. Three modes: (1) physical lab (`192.168.88.x`), (2) benchmark scenario (`192.168.100.x`), (3) discovery mode (empty — agent uses nmap to discover the target network, all graph tool functions return "run nmap first" guidance).
- `src/agent/tools/recon_tools.py` — YAML-based network recon tools (`_run()` subprocess runner, `nvd_lookup()` Python handler). `RECON_TOOLS` is auto-generated from YAML definitions at import time.
- `src/agent/tools/tool_loader.py` — YAML-to-tool engine. Loads declarative tool definitions from `definitions/*.yaml`, builds JSON Schema and subprocess functions. Supports three tool types: subprocess (auto-generated CLI), handler: python, and type: hardware (physical attack tools with protocol-specific commands).
- `src/agent/tools/definitions/` — 21 declarative YAML tool definitions. Key tools: `nmap.yaml`, `nmap_discovery.yaml` (ping scan), `ssh_audit.yaml`, `curl_headers.yaml`, `http_get.yaml`, `mqtt_listen.yaml`, `ssh_login.yaml`, `ssh_exec.yaml`, `try_credential.yaml`, `ftp_list.yaml`, `mysql_query.yaml`, `redis_cmd.yaml`, `telnet_connect.yaml`, `nvd_lookup.yaml`, `arp_scan.yaml`, `traceroute.yaml`. Hardware tools: `hackrf.yaml` (SDR 1 MHz–6 GHz), `flipper_zero.yaml` (sub-GHz/RFID/NFC/IR/GPIO), `proxmark3.yaml` (RFID/NFC badge cracking), `exploit_iot_kit.yaml` (UART/JTAG/SPI/I2C/glitching). Hardware tools return protocol-specific command suggestions for the operator.
- `src/agent/scanner.py` — Phase 3a deterministic scanner. Runs all recon tools on every device in parallel, saves raw results to `03_scans/{device_id}.json`, auto-extracts ~22 types of trivial findings, writes per-device fallback JSON (LLM overwrites on success). Feeds `{{scan_results}}` and `{{trivial_findings}}` into `analyze_device.txt` prompts.
- `src/agent/tools/skill_tools.py` — IoT security skill tools: `list_skills()`, `load_skill()`, `search_knowledge()` (ChromaDB semantic search), `cve_search()` (cache-then-query NVD).
- `src/agent/tools/deliverable.py` — File I/O: `save_deliverable()` (JSON/Markdown), `read_deliverable()`, `list_deliverables()`, and `aggregate_device_results()` for parallel merging.
- `src/agent/validators/__init__.py` — Output validators: `markdown_with_sections()`, `json_valid()`, `file_exists()`.

### Agent Prompt Templates

- `src/agent/prompts/graph_analysis.txt` — Phase 1: Topology analysis
- `src/agent/prompts/recon.txt` — Phase 2: Network reconnaissance
- `src/agent/prompts/vuln_analysis.txt` — Phase 3: Aggregation (reads per-device results)
- `src/agent/prompts/analyze_device.txt` — Phase 3b: Per-device vulnerability analysis (scanner results as input)
- `src/agent/prompts/exploit_device_vuln.txt` — Phase 4: Per-vuln exploit micro-agent template
- `src/agent/prompts/exploitation.txt` — Phase 4: Exploitation strategies
- `src/agent/prompts/intrusion.txt` — Phase 5: Full infiltration campaign (credential spraying, lateral movement)
- `src/agent/prompts/report.txt` — Phase 6: Final report generation (reads `06_phase6_context.json` as primary input)
- `src/agent/prompts/vuln_device.txt` — [DEPRECATED] Retired; replaced by `analyze_device.txt`
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
- Environment variables (API keys) loaded from `.env` via python-dotenv. Required keys: `OPENROUTER_API_KEY`. Optional: `MINIMAX_API_KEY` (MiniMax Coding Plan subscription — provider auto-selected when a MiniMax model is chosen in the dashboard), `VOYAGE_API_KEY` (knowledge store ChromaDB). On the master VM, secrets are injected via Ansible Vault (`vault_openrouter_api_key`, `vault_minimax_api_key`, `vault_voyage_api_key` in `group_vars/all/vault_master.yml`).

### Vulnerability taxonomy discipline

- All vuln type constants and alias resolution live in `src/agent/vuln_taxonomy.py`. Do NOT re-declare `CONFIG_ONLY_TYPES`, `EXPLOIT_CATEGORY_MAP`, or similar sets in another module — import them from there. The evaluator and the pipeline must agree on the same taxonomy.
- New LLM synonym → add one line to `VULN_TYPE_ALIASES` mapping it to a canonical type already in `CANONICAL_TYPES`. Never introduce a new canonical type without also updating `CONFIG_ONLY_TYPES` and `EXPLOIT_CATEGORY_MAP` if the semantics require it.
- Categorically non-vuln outputs (the LLM reporting meta-observations or negative results as findings) → add the exact type string to `NOISE_TYPES`. These are dropped by `_aggregate_device_vulns` regardless of severity.
- Phase 3 is hypothesis generation; Phase 4 is verification. A Phase 3 finding with `exploitation_status="confirmed"` is trusted over a Phase 4 FAILED/ERROR (to avoid losing directly-observed findings when the exploit agent crashes). Any Phase 4 refactor should preserve this asymmetry.
- Phase 3 dedup keeps the LOWER severity on `(ip, type, port)` collisions. This is intentional — LLMs inflate severity, so the lower finding is statistically closer to the GT.

## Tests

15 test files, 280 test functions covering all modules:

| File | Coverage |
|------|----------|
| `test_loader.py` | YAML loading, device/link counts, neighbors, paths, attack surface |
| `test_cve_lookup.py` | CVE parsing, CVSS 3.1/2.0, NVD queries, rate limiting |
| `test_risk_scorer.py` | CVSS scoring, betweenness centrality, hop distance, exposure |
| `test_attack_path.py` | Edge weighting, path scoring, pivot detection, exploit probability |
| `test_pipeline.py` | Tool resolution, dry-run, prerequisites, phase execution, aggregation helpers |
| `test_registry.py` | Agent config validation, unique phases, deliverables |
| `test_prompt_manager.py` | Variable substitution, prompt loading |
| `test_cost_tracker.py` | Token counting, pricing, per-phase costs |
| `test_agent_tools.py` | YAML-generated recon tools (nmap, ssh_audit, curl, mqtt), nvd_lookup, provider |
| `test_tool_loader.py` | YAML parsing, schema generation, subprocess function generation |
| `test_skill_tools.py` | Skill listing, loading, frontmatter parsing, tool definitions |
| `test_deliverable_tools.py` | File save/read, directory listing |
| `test_validators.py` | Markdown validation, required sections |
| `test_evaluator.py` | Benchmark matching, weighted score, severity mismatch penalties, bonus findings |
| `test_runs_route.py` | `GET /api/runs` endpoints, score route ordering, ZIP download |

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
- Multi-phase pipeline: graph analysis → recon → vuln analysis → exploitation → intrusion → report
- Per-vuln micro-agents in Phase 4 via `EXPLOIT_INSTRUCTIONS` (credentials / data_access / injection categories)
- Multi-provider support: Anthropic, OpenRouter, MiniMax, GLM, Qwen
- Phase 3a deterministic scanner (`src/agent/scanner.py`) runs all recon tools before LLM device agents
- Phase 5 intrusion: credential spraying, lateral movement, crown jewel access (`05_intrusion.json`)
- Phase 6 report: reads `06_phase6_context.json` as primary input, auto-fills Sections 5/6 tables from `06_report_prefill.md`
- Cost tracking per phase with per-model pricing
- Dry-run mode for validation without API calls
- `--batch "1,2,3"` / `--batch all` — run multiple scenarios sequentially, aggregate metrics into `batch_summary.json`

### Phase 5 — Benchmark LLM sur scénarios Proxmox ✅
- VM maître (LXC 200) sur Proxmox (`10.0.0.110`) — orchestre le pipeline
- Scénarios déployés via Ansible sur `192.168.100.0/24` (vmbr1), vulnérabilités injectées via playbooks
- Dashboard FastAPI accessible via Tailscale; CI/CD self-hosted runner sur la VM maître
- Secrets injectés via Ansible Vault (`group_vars/all/vault_master.yml`)

### Infrastructure & Deployment

- `benchmarks/ansible/` — Playbooks pour déployer et injecter des vulnérabilités dans les VMs Proxmox (`192.168.100.0/24`)
- `benchmarks/packs/definitions/f*.yaml` — Paquets de vulnérabilités organisés par catégorie (weak_auth, misconfig, data_exposure, injection, crypto, etc.)
- `benchmarks/topologies/*.yaml` — topologies scénarios (flat, mesh, gateway, ics_scada, smart_city_*, etc.)
- `Dockerfile` — image multi-stage Python 3.12-slim avec nmap, mosquitto-clients, openssh-client
- `docker-compose.yml` — volumes `./data` (ChromaDB knowledge store) et `./output` (résultats pipeline)
- `docker/entrypoint.sh` — auto-ingestion des skills ChromaDB au premier démarrage (flag `.initialized`)
- `.env.example` — template de configuration (OPENROUTER_API_KEY, VOYAGE_API_KEY)
- `src/static_v2/` — tableau de bord interne (monitoring temps-réel, `/v2`), distinct de `src/static/` (benchmark) et `src/static_docker/` (end-user)
