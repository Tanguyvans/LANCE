# NATO Smart City IoT - Plateforme d'Analyse des Chemins d'Attaque

## 🎯 Objectif

Plateforme de cybersécurité pour infrastructures IoT Smart City. Modélisation du réseau sous forme de graphe dirigé pour analyser les vulnérabilités et détecter les chemins d'attaque multi-hop. Inspirée de l'approche Shannon/LLMDFA : des agents IA interrogent le graphe pour identifier les surfaces d'attaque.

## 🌐 Accès Réseau

| Service | URL | Notes |
|---------|-----|-------|
| WisGate (LoRaWAN) | <http://192.168.88.238> | Gateway LoRaWAN EU868 |
| Zigbee2MQTT | <http://192.168.88.247:8080> | Interface Zigbee |
| MikroTik | 192.168.88.1 | Routeur/Firewall (WinBox) |
| TP-Link EAP613 | <http://192.168.88.251> | AP WiFi "NATO-Lab" |
| Homebox | <http://ilia-corsair-5000x.umons.ac.be:7745> | Inventaire matériel |

### SSH

```bash
ssh nato@192.168.88.248  # Jetson Orin Nano
ssh nato@192.168.88.247  # Raspberry Pi 5
ssh tanguy@ilia-corsair-5000x.umons.ac.be  # Tour UMONS
```

## 🏗️ Architecture Réseau

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INTERNET                                       │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MikroTik RB5009 (.1)                                │
│                           Routeur/Firewall                                  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Netgear GS348PP (PoE)                                │
│                           Switch 48 ports                                   │
└─────────────────────────────────────────────────────────────────────────────┘
        │          │          │          │          │          │          │
        ▼          ▼          ▼          ▼          ▼          ▼          ▼
  ┌─────────┐┌─────────┐┌─────────┐┌─────────┐┌─────────┐┌─────────┐┌─────────┐
  │TP-Link  ││WisGate  ││iot-hub  ││rpi-nato ││Jetson   ││Ubiquiti ││Ubiquiti │
  │EAP613   ││RAK7268  ││RPi5     ││RPi5     ││Orin Nano││AI Turret││NVR      │
  │.251     ││.238     ││.231     ││.247     ││.248     ││.230     ││.253     │
  │WiFi AP  ││LoRaWAN  ││MQTT     ││Zigbee   ││Vision IA││Caméra   ││Vidéo    │
  └─────────┘└─────────┘└─────────┘└─────────┘└─────────┘└─────────┘└─────────┘
       │          │          ▲          │                    │          │
       │          │          │          │                    └────┬─────┘
       ▼          │          │          │                         │
  ┌─────────┐     │          │          │                   ┌─────▼─────┐
  │WiFi     │     │          │          │                   │Flux vidéo │
  │Clients  │     │          │          │                   └───────────┘
  └─────────┘     │          │          │
                  │          │          │
            ┌─────┴─────┐    │    ┌─────┴─────┐
            │  LoRaWAN  │    │    │  Zigbee   │
            └───────────┘    │    └───────────┘
                  │          │          │
            ┌─────┴─────┐    │    ┌─────┴─────┐
            │Milesight  │    │    │Aqara      │
            │EM310-UDL  │    │    │Vibration  │
            │(ultrason) │    │    │Sensor     │
            └───────────┘    │    └───────────┘
                  │          │          │
                  │    ┌─────┴─────┐    │
                  └───►│   MQTT    │◄───┘
                       │   .231    │
                       └───────────┘
```

## 📡 Protocoles IoT

| Protocole | Gateway | Capteurs |
|-----------|---------|----------|
| **LoRaWAN** | WisGate Edge Lite 2 | Milesight EM310-UDL, SenseCAP S2120, Elsys EMS, Dragino PS-LB |
| **Zigbee** | Sonoff ZBDongle-P (RPi5) | Aqara Vibration, Aqara Door/Window |
| **WiFi/BLE** | TP-Link EAP613 | Industrial Shields Ardbox |

## 📦 Inventaire

Inventaire complet sur [Homebox](http://ilia-corsair-5000x.umons.ac.be:7745)

### Matériel principal

| Device | Rôle | IP |
|--------|------|-----|
| MikroTik RB5009 | Routeur/Firewall | 192.168.88.1 |
| Netgear GS348PP | Switch PoE 48 ports | - |
| Jetson Orin Nano | Edge AI, Vision | 192.168.88.248 |
| Raspberry Pi 5 | Gateway Zigbee | 192.168.88.247 |
| Raspberry Pi 4 | MQTT Broker | - |
| WisGate Edge Lite 2 | Gateway LoRaWAN | 192.168.88.238 |
| TP-Link EAP613 | AP WiFi NATO-Lab | 192.168.88.251 |

## 🛠️ Stack Logicielle

- **NetworkX** : Backend graphe pour la modélisation de topologie et l'analyse de chemins
- **PyYAML** : Chargement du modèle d'infrastructure déclaratif
- **pyvis** : Visualisation interactive du réseau (export HTML)
- **pytest** : Tests unitaires
- **Zigbee2MQTT** : Bridge Zigbee → MQTT (sur RPi5)

## 🚀 Getting Started

### 1. Installation

```bash
pip install -r requirements.txt
```

### 2. Lancer les tests

```bash
python3 -m pytest tests/ -v
```

### 3. Générer la visualisation

```bash
python3 -m src.visualize
open output/nato_lab.html
```

### 4. Lancer l'analyse des chemins d'attaque

```bash
python3 -c "
from src.loader import build_graph
from src.cve_lookup import load_cpe_mapping, scan_all_devices
from src.attack_path import analyze_attack_paths, print_attack_report

backend = build_graph()
infra = __import__('src.loader', fromlist=['load_yaml']).load_yaml()
cpe = load_cpe_mapping('infrastructure/cpe_mapping.yaml')
cve_reports = scan_all_devices(infra, cpe)
report = analyze_attack_paths(backend, cve_reports)
print_attack_report(report)
"
```

### 5. Accéder au réseau physique

Connecte-toi au WiFi `NATO-Lab` ou branche-toi sur le switch.

```bash
# Vérifier les services
curl http://192.168.88.247:8080   # Zigbee2MQTT
curl http://192.168.88.238        # WisGate
```

## 📁 Structure du repo

```
NATO-SmartCity-IoT/
├── infrastructure/
│   └── nato_lab.yaml          # Source de vérité : topologie du lab
├── src/
│   ├── models.py              # Dataclasses (Device, Service, Link, Network)
│   ├── graph_backend.py       # ABC GraphBackend + implémentation NetworkX
│   ├── loader.py              # YAML → dataclasses → graphe
│   ├── cve_lookup.py          # Module NIST NVD (requêtes CVE par CPE)
│   ├── risk_scorer.py         # Scoring de risque par device (CVSS + exposition + centralité)
│   ├── attack_path.py         # Chemins d'attaque pondérés + pivots (Dijkstra)
│   └── visualize.py           # Génération HTML interactive (pyvis)
├── tests/
│   ├── test_loader.py         # Tests : chargement, chemins, surface d'attaque
│   ├── test_cve_lookup.py     # Tests : parsing NVD, rate limiting
│   ├── test_risk_scorer.py    # Tests : scoring, centralité, hops
│   └── test_attack_path.py    # Tests : poids arêtes, chemins, pivots
├── output/
│   └── nato_lab.html          # Visualisation générée
└── requirements.txt
```

## 🗺️ Roadmap

### Phase 1 — Modélisation du réseau ✅

- Modèle YAML déclaratif de l'infrastructure
- Backend graphe NetworkX avec interface abstraite (interchangeable)
- Visualisation interactive pyvis (HTML)
- Tests unitaires (chargement, chemins, surface d'attaque)

### Phase 2 — Enrichissement CVE ✅

1. Scanner le lab avec `nmap -sV` pour détecter les versions de services
2. Relever les versions firmware/OS via SSH (RouterOS 7.18.2, Mosquitto 2.0.21, OpenSSH 10.0p1, etc.)
3. Enrichir le YAML avec `os_version`, `firmware`, service `version`
4. Module NIST NVD (`src/cve_lookup.py`) + mapping CPE (`infrastructure/cpe_mapping.yaml`)
5. Scoring de risque (`src/risk_scorer.py`) : CVSS + exposition réseau + centralité betweenness
6. Résultats : 24 CVEs sur 5 devices, MikroTik (6.6) et WisGate (5.6) risque le plus élevé

### Phase 3 — Analyse des chemins d'attaque ✅

- Pondération des arêtes par difficulté d'exploitation (protocole × exploitabilité CVSS)
- Distinction relais réseau (switch/router/ap) vs cibles d'exploitation
- Détection des chemins d'attaque critiques via Dijkstra dirigé
- Identification des points de pivot (Netgear betweenness 0.72, MikroTik 5 chemins)
- Scoring des chaînes : `∏ P(hop) × impact(cible) × amplification^(n-1)`

#### Méthodologie de scoring

Le scoring des chemins d'attaque repose sur trois composantes issues de la littérature :

**1. Poids des arêtes — Exploitabilité CVSS v3.1**

Chaque arête est pondérée par l'exploitabilité du device cible, calculée via la formule CVSS v3.1 :
`Exploitability = 8.22 × AV × AC × PR × UI` (normalisé en probabilité [0,1]).
Les constantes numériques (AV, AC, PR, UI) proviennent de la spécification officielle [1].

**2. Facteur protocolaire**

Pour les liens sans CVE associée, un facteur de difficulté basé sur le type de protocole est appliqué (ethernet, MQTT, Zigbee, LoRaWAN), reflétant le chiffrement, la portée et l'accès requis.

**3. Score de chemin — Probabilité cumulative + amplification**

Le score d'un chemin d'attaque combine :
- **Probabilité cumulative** : produit des probabilités d'exploitation par hop `P(chemin) = ∏ P(hop_i)`, selon l'approche d'agrégation du NIST [2].
- **Impact de la cible** : criticité de l'asset final (score CVSS Impact).
- **Facteur d'amplification** : les vulnérabilités chaînées présentent un risque supérieur à la somme des risques individuels (effet "domino", 1+1 > 2) [4]. Les chemins courts avec gain de privilèges à chaque hop sont pénalisés davantage.
- **Choke points** : les noeuds où convergent plusieurs chemins d'attaque sont identifiés via la centralité de betweenness [3].

#### Références

1. FIRST — *CVSS v3.1 Specification Document* : formule d'exploitabilité et constantes numériques.
   https://www.first.org/cvss/v3-1/specification-document
2. NIST — *Aggregating Vulnerability Metrics in Enterprise Networks using Attack Graphs* : agrégation probabiliste des scores CVSS le long des chemins d'attaque.
   https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=926022
3. Picus Security — *Attack Path Analysis Explained* : scoring context-aware (exploitabilité, complexité du chemin, criticité de l'asset) et concept de choke points.
   https://www.picussecurity.com/resource/blog/what-is-attack-path-analysis
4. Software Secured — *The Domino Effect: Chaining Medium and Low Vulnerabilities is The Path to Critical Breaches* : effet de propagation des vulnérabilités chaînées.
   https://www.softwaresecured.com/post/the-domino-effect-chaining-medium-and-low-vulnerabilities-is-the-path-to-critical-breaches
5. Park et al. — *Network Security Node-Edge Scoring System Using Attack Graph Based on Vulnerability Correlation*, Applied Sciences, 2022 : scoring combiné node+edge avec corrélation de vulnérabilités.
   https://www.mdpi.com/2076-3417/12/14/6852
6. Frigault & Wang — *Using CVSS in Attack Graphs* : conversion des scores CVSS en poids d'arêtes pour graphes d'attaque.
   https://www.researchgate.net/publication/221326700_Using_CVSS_in_attack_graphs

### Phase 4 — Agents LLM (approche LLMDFA)

Agents spécialisés qui interrogent le graphe enrichi :
- **Agent reconnaissance** : cartographie la surface d'attaque
- **Agent lateral movement** : trouve les chemins de propagation
- **Agent impact assessment** : évalue les conséquences
- **Orchestrateur** : coordonne les agents et produit un rapport

Mode semi-autonome : l'agent raisonne et génère les commandes, l'opérateur valide et exécute.

### Phase 5 — Pentest progressif

Tester les scénarios d'attaque sur le lab physique, par difficulté croissante :

| Niveau | Scénario | Exemple |
|--------|----------|---------|
| 1 | Device unique, service exposé | Exploit HTTP sur WisGate |
| 2 | Device unique, MQTT sans auth | Interception données capteurs |
| 3 | Chaînage 2 hops | Capteur LoRaWAN → WisGate → MQTT broker |
| 4 | Scénario complet multi-hop | Internet → MikroTik → pivot LAN → cible interne |

#### Stratégie de test

| Attaque | Environnement | Raison |
|---------|---------------|--------|
| MQTT sans auth (`mosquitto_sub -t '#'`) | Lab réel | Non destructif, écoute passive |
| SSH default creds | Lab réel | Non destructif, simple test de login |
| Terrapin SSH scan (`ssh-audit`) | Lab réel | Non destructif, scan passif |
| DoS MikroTik (CVE-2018-5951) | Docker/GNS3 | Risque de couper le réseau |
| RCE nginx (CVE-2021-23017) | Container `nginx:1.19.6` | Risque de crasher le WisGate |
| Exploit Dropbear (CVE-2021-36369) | Container | Risque de perdre l'accès SSH |

Les attaques destructives (DoS, RCE, exploit SSH) sont testées sur des **containers Docker** qui reproduisent les services vulnérables avec les mêmes versions que le lab réel. Cela permet de valider les exploits sans impacter l'infrastructure.

### Phase 6 — Dashboard + Backend graphe avancé (optionnel)

- Dashboard web temps réel (état du réseau, alertes, chemins d'attaque visualisés)
- Si besoin de performances ou de requêtes plus complexes : implémenter un backend Memgraph ou Neo4j (l'ABC `GraphBackend` est prête pour ça)

## 👥 Équipe

- Tanguy Vansnick

## 📄 Licence

Projet NATO - Usage interne uniquement
