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

### Phase 2 — CVE enrichment & risk scoring (DONE)

1. ~~Scan the lab with `nmap -sV`~~ — done
2. ~~Collect firmware/OS versions via SSH~~ — done (RouterOS 7.18.2, Mosquitto 2.0.21, OpenSSH 10.0p1, Dropbear 2020.81, nginx 1.19.6, etc.)
3. ~~Extend YAML schema with `os_version`, `firmware`, service `version`~~ — done
4. ~~Build NIST NVD module~~ — `src/cve_lookup.py` + `infrastructure/cpe_mapping.yaml` (exact CPE strings)
5. ~~Risk scoring module~~ — `src/risk_scorer.py` (CVSS + network exposure + betweenness centrality)
6. Results: 24 CVEs across 5 devices, MikroTik (6.6) and WisGate (5.6) highest risk

### Phase 3 — Attack path analysis
- Pondérer les arêtes du graphe par difficulté d'exploitation
- Détecter les chemins d'attaque critiques (ex: Internet → MikroTik → Netgear → WisGate → MQTT)
- Identifier les points de pivot (noeuds à haute centralité : Netgear 0.72, WisGate 0.48)
- Générer un rapport de risque avec scénarios d'exploitation

### Phase 4 — LLM agent pentester (style Shannon/PentAGI)
- Agent semi-autonome : Claude analyse le graphe enrichi + CVEs, propose des commandes
- Outils de l'agent : nmap, ssh, curl, mosquitto_sub/pub, ssh-audit
- Mode opérateur : l'agent raisonne, l'humain valide et exécute
- Framework : Claude Agent SDK (comme Shannon)

### Phase 5 — Pentest progressif
- Tests safe sur le lab réel : MQTT sans auth, SSH default creds, Terrapin scan
- Tests destructifs sur containers Docker (nginx:1.19.6, Dropbear, MikroTik CHR)
- Difficulté croissante : device unique → chaînage 2 hops → scénario multi-hop complet
