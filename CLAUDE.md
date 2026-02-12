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
python3 -m pytest tests/test_loader.py::TestGraphBackend::test_path_em310_to_rpi4 -v -p no:pytest_ethereum -p no:web3

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

Phase 1 (graph modeling + visualization) is complete. Phase 2 is next:

1. **Scan the lab** with `nmap -sV` to detect service versions (requires physical access to the 192.168.88.0/24 network)
2. **Collect firmware/OS versions** manually from each device (RouterOS version, Mosquitto version, JetPack version, etc.)
3. **Extend the YAML schema** to include `os_version`, `firmware`, service `version`, and `cves` fields
4. **Build a NIST NVD module** to auto-fetch CVEs by product/version
5. **Score nodes** by risk (CVSS + network exposure)

The lab devices do not have known versions yet — they need to be collected on-site.
