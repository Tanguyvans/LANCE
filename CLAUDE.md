# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NATO Smart City IoT security analysis platform. Models a physical IoT lab network (192.168.88.0/24) as a directed graph to detect multi-hop attack paths. Inspired by Shannon/LLMDFA: LLM agents analyze the network graph to find vulnerabilities.

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
```

## Architecture

**Data flow:** YAML infrastructure file → dataclasses → graph backend → queries / visualization

- `infrastructure/nato_lab.yaml` — Single source of truth for the lab topology (devices, links, networks, external entities). All device IDs referenced in links must exist as device or external entries.
- `src/models.py` — Pure dataclasses (`Device`, `Service`, `Link`, `Network`, `ExternalEntity`, `Infrastructure`). No ORM, no logic.
- `src/graph_backend.py` — Abstract `GraphBackend` ABC defining the query interface (`get_neighbors`, `find_all_paths`, `get_attack_surface`, `to_dict`). `NetworkXBackend` implements it with a `nx.DiGraph`. The ABC exists so other backends (Memgraph, Neo4j) can be swapped in if needed.
- `src/loader.py` — `load_yaml()` parses YAML into dataclasses; `build_graph()` populates a backend. `build_graph()` is the main entry point used by tests and visualization.
- `src/visualize.py` — Generates pyvis HTML. Color-codes nodes by device type, styles edges by protocol (ethernet/lorawan/zigbee/mqtt/wan).

## Key Conventions

- The graph is **directed** (`DiGraph`), but `find_all_paths` uses an undirected view to find reachable paths in both directions.
- "Attack surface" = devices that expose services (have open ports). Sensors with only wireless protocols (lorawan/zigbee) and no services are excluded.
- Device types: `router`, `switch`, `gateway`, `sensor`, `compute`, `camera`, `ap`, `external`.
- Link types: `ethernet`, `lorawan`, `zigbee`, `mqtt`, `wan`.
- When modifying the YAML topology, update test assertions (device/link counts, neighbor sets) accordingly.
- Language: code and comments in English, infrastructure descriptions in French.

## Current Status & Next Steps

### Phase 1 — Graph modeling + visualization (DONE)
- Directed graph (NetworkX DiGraph) modeling of 15 devices, 16 links
- pyvis HTML visualization with color-coded nodes/edges
- 20 tests passing

### Phase 2 — CVE enrichment & risk scoring (IN PROGRESS)
Steps 1-3 done (nmap scan, SSH version collection, YAML schema extended). Remaining:

1. ~~Scan the lab with `nmap -sV`~~ — done 2026-02-17
2. ~~Collect firmware/OS versions via SSH~~ — done (RouterOS 7.18.2, JetPack R36.4.7, Mosquitto, Debian 13, etc.)
3. ~~Extend YAML schema with `os_version`, `firmware`, service `version`~~ — done
4. **Collect missing versions** — NVR (.253), cam_turret, Netgear GS348PP, LoRaWAN/Zigbee sensor firmware
5. **Build NIST NVD module** (`src/cve_lookup.py`) — auto-fetch CVEs by CPE (product/version) from NIST NVD API
6. **Add `cves` field to YAML** — store CVE IDs per device/service
7. **Score nodes by risk** — CVSS score + network exposure (open ports, graph centrality, reachability from internet)

### Phase 3 — LLM agent attack path analysis
- Agent Claude analyzes the enriched graph to find multi-hop attack paths
- Generate risk reports with exploitation scenarios and recommendations

### Phase 4 — Pentest & exploitation
- Start with isolated targets (e.g., MikroTik Telnet/FTP)
- Progressive difficulty: chain exploits across multiple hops
