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

### 4. Accéder au réseau physique

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
│   └── visualize.py           # Génération HTML interactive (pyvis)
├── tests/
│   └── test_loader.py         # Tests : chargement, chemins, surface d'attaque
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

### Phase 2 — Enrichissement CVE (prochaine étape)

1. **Scanner le lab** avec `nmap -sV` pour détecter les versions de services
2. **Relever les versions firmware/OS** sur chaque device (RouterOS, JetPack, Mosquitto, etc.)
3. **Enrichir le YAML** avec les versions exactes et les CVE connues
4. **Module NIST NVD** : interrogation automatique de l'API pour récupérer les CVE par produit/version
5. **Scoring de risque** par noeud (basé sur CVSS et exposition réseau)

### Phase 3 — Analyse des chemins d'attaque

- Pondération des arêtes par difficulté d'exploitation
- Détection des chemins d'attaque critiques (ex: Internet → MikroTik → MQTT broker)
- Identification des points de pivot (noeuds à haute centralité)

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
| 2 | Device unique, MQTT sans auth | Interception données capteurs sur RPi4 |
| 3 | Chaînage 2 hops | Capteur LoRaWAN → WisGate → RPi4 |
| 4 | Scénario complet multi-hop | Internet → MikroTik → pivot LAN → cible interne |

### Phase 6 — Dashboard + Backend graphe avancé (optionnel)

- Dashboard web temps réel (état du réseau, alertes, chemins d'attaque visualisés)
- Si besoin de performances ou de requêtes plus complexes : implémenter un backend Memgraph ou Neo4j (l'ABC `GraphBackend` est prête pour ça)

## 👥 Équipe

- Tanguy Vansnick

## 📄 Licence

Projet NATO - Usage interne uniquement
