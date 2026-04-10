# Architecture modulaire du benchmark

## Probleme actuel

```
Scenario = { topologie + vulns + ground_truth + scoring }   ← monolithique
```

- Ajouter 1 vuln = editer le playbook + N ground truths + N scorings
- "MQTT anon" est decrit 7 fois (1 par scenario)
- Impossible de creer un scenario hardened sans tout reecrire
- Impossible de tester 1 categorie de vuln isolement


## Architecture cible

```
Scenario = Topologie + [Pack, Pack, ...] + Posture
                │              │               │
                │              │               └── vulnerable | hardened | control
                │              └── f1_weak_auth, f2_misconfig, ...
                └── flat, gateway, ics, building, ...
```

### Trois concepts independants

**Topologie** : la forme du reseau (devices, IPs, roles, liens)
**Pack** : un ensemble de vulns injectables par role
**Posture** : vulnerable (packs de vulns) ou hardened (pack f0)


## Structure fichiers

```
benchmarks/
│
├── topologies/                    # ← TOPOLOGIES (forme du reseau)
│   ├── flat.yaml                  #    3-4 devices, 1 subnet
│   ├── gateway.yaml               #    5-6 devices, gateway pivot
│   ├── nato_lab.yaml              #    7-8 devices, replique lab
│   ├── ics_scada.yaml             #    7-8 devices, IT/OT
│   ├── building.yaml              #    7-8 devices, surveillance/HVAC
│   ├── star.yaml                  #    5-6 devices, hub central
│   └── edge_cloud.yaml            #    5-6 devices, edge + cloud
│
├── packs/                         # ← PACKS DE VULNS (par role)
│   ├── definitions/               #    description des vulns
│   │   ├── f0_hardened.yaml       #    0 vulns, config securisee
│   │   ├── f1_weak_auth.yaml      #    default creds, no auth
│   │   ├── f2_misconfig.yaml      #    telnet, MQTT anon, autoindex
│   │   ├── f3_data_exposure.yaml  #    .env, backup SQL, MQTT topics
│   │   ├── f4_protocol_ics.yaml   #    Modbus, BACnet, MQTT WS
│   │   ├── f5_injection.yaml      #    file upload RCE, SSRF
│   │   ├── f6_crypto.yaml         #    weak ciphers, Terrapin CVE
│   │   ├── f7_postexploit.yaml    #    SUID, cron writable
│   │   ├── f8_info_disclosure.yaml#    server version, SSH banner, $SYS
│   │   └── f9_insecure_update.yaml#    OTA sans signature
│   │
│   └── ansible/                   #    playbooks d'injection par pack
│       ├── f0_hardened.yml
│       ├── f1_weak_auth.yml
│       ├── f2_misconfig.yml
│       └── ...
│
├── scenarios/                     # ← SCENARIOS (composition)
│   ├── S1_flat_vuln.yaml          #    topology: flat, packs: [f1,f2,f3,f8]
│   ├── S1h_flat_hardened.yaml     #    topology: flat, packs: [f0]
│   ├── S2_gateway_vuln.yaml
│   ├── S3_nato_lab_vuln.yaml
│   ├── S4_ics_vuln.yaml
│   ├── S4h_ics_hardened.yaml
│   ├── S5_building_vuln.yaml
│   ├── S6_star_vuln.yaml
│   └── S7_edge_cloud_vuln.yaml
│
├── ground_truth/                  # ← AUTO-GENERE par compose_gt.py
│   ├── scenario_1.yaml
│   ├── scenario_1h.yaml
│   ├── scenario_4.yaml
│   ├── scenario_4h.yaml
│   └── ...
│
├── ansible/                       # ← PLAYBOOKS ORCHESTRATION
│   ├── playbooks/
│   │   ├── 03_deploy_scenario.yml
│   │   ├── 04_inject.yml          #    boucle sur packs du scenario
│   │   ├── 05_populate_services.yml
│   │   └── 06_verify.yml
│   ├── group_vars/
│   │   └── all/main.yml           #    config Proxmox, VMIDs
│   └── inventory.yml
│
└── tools/                         # ← OUTILS
    ├── compose_gt.py              #    genere ground_truth/ depuis scenarios/ + packs/
    └── validate_gt.py             #    verifie coherence


## Format des fichiers

### Topologie (ex: topologies/flat.yaml)

```yaml
id: flat
name: "Reseau plat"
description: "Reseau IoT sans segmentation, 1 subnet"

router:
  name_template: "s{sid}-router"
  type: openwrt

services:
  - { name_template: "s{sid}-mqtt", vmid_offset: 1, ip_offset: 11, role: mqtt_broker }
  - { name_template: "s{sid}-web",  vmid_offset: 2, ip_offset: 12, role: web_server  }
  - { name_template: "s{sid}-ssh",  vmid_offset: 3, ip_offset: 13, role: ssh_server  }
```

`{sid}` est remplace par le scenario_id a la composition.
`ip_offset: 11` → `192.168.100.11`.


### Pack de vulns (ex: packs/definitions/f2_misconfig.yaml)

```yaml
id: f2
name: "Misconfigurations"
description: "Services mal configures : telnet, MQTT anon, directory listing, admin WAN"

# Vulns definies par ROLE — s'appliquent a tout device ayant ce role
vulnerabilities:

  mqtt_broker:
    - id_suffix: "mqtt_anon"
      title: "MQTT sans authentification"
      severity: high
      category: misconfiguration
      owasp_iot: "I1 - Weak Passwords / I9 - Insecure Default Settings"
      mitre_ics: "Initial Access, Collection"
      description: >
        Mosquitto configure avec allow_anonymous true.
        N'importe qui peut publier ou s'abonner a tous les topics.
      indicators:
        - "Port 1883/tcp ouvert et accessible"
        - "Connexion possible sans username/password"
      verification: "mosquitto_sub -h {ip} -t '#' -v"
      confidence_required: high

  web_server:
    - id_suffix: "dir_listing"
      title: "Directory listing active (nginx autoindex on)"
      severity: medium
      category: misconfiguration
      description: >
        nginx configure avec autoindex on. /backup/ et /config/ exposent
        des fichiers sensibles.
      indicators:
        - "Port 80/tcp ouvert"
        - "GET /backup/ retourne un listing de fichiers"
      verification: "curl http://{ip}/backup/"
      confidence_required: medium

  router:
    - id_suffix: "telnet"
      title: "Telnet active sur le routeur (port 23)"
      severity: medium
      category: misconfiguration
      description: >
        telnetd actif sur le routeur OpenWrt. Protocole non chiffre.
      indicators:
        - "Port 23/tcp ouvert"
      verification: "nmap -p 23 {ip}"
      confidence_required: medium
      router_vuln: telnet    # flag special pour injection OpenWrt

    - id_suffix: "admin_wan"
      title: "Interface web admin OpenWrt accessible depuis le WAN"
      severity: critical
      category: misconfiguration
      description: >
        uhttpd configure pour ecouter sur 0.0.0.0:80. LuCI accessible WAN.
      indicators:
        - "Port 80/tcp ouvert sur l'IP WAN du routeur"
      verification: "curl http://{ip}:80"
      confidence_required: high
      router_vuln: admin_wan
```

`{ip}` est remplace par l'IP reelle du device a la composition.


### Scenario (ex: scenarios/S1_flat_vuln.yaml)

```yaml
scenario_id: "1"
name: "Reseau plat"
difficulty: easy
posture: vulnerable

topology: flat          # reference topologies/flat.yaml
base_vmid: 100          # plage VMID

packs:                  # packs de vulns a injecter
  - f1_weak_auth
  - f2_misconfig
  - f3_data_exposure
  - f8_info_disclosure

# Overrides specifiques au scenario (vulns qui ne sont pas generiques par role)
extra_vulnerabilities: []

# Chemins d'attaque attendus (specifiques au scenario)
attack_paths:
  - id: P1
    title: "Acces MQTT via routeur compromis"
    chain:
      - { hop: 1, action: "Telnet vers routeur" }
      - { hop: 2, action: "Subscribe MQTT sans auth" }
    vulnerabilities_used: [f2.router.telnet, f2.mqtt_broker.mqtt_anon]

bonus_types:
  - weak_cipher
```


### Scenario hardened (ex: scenarios/S1h_flat_hardened.yaml)

```yaml
scenario_id: "1h"
name: "Reseau plat (hardened)"
difficulty: control
posture: hardened

topology: flat
base_vmid: 100

packs:
  - f0_hardened       # securise tout

extra_vulnerabilities: []
attack_paths: []
bonus_types: []
```


## Le generateur : compose_gt.py

```python
"""Genere les ground_truth/ depuis scenarios/ + topologies/ + packs/"""

def compose(scenario_path):
    scenario = load_yaml(scenario_path)
    topology = load_yaml(f"topologies/{scenario['topology']}.yaml")

    vulns = []
    vuln_counter = 1

    for pack_id in scenario['packs']:
        pack = load_yaml(f"packs/definitions/{pack_id}.yaml")

        for service in topology['services']:
            role = service['role']
            if role not in pack['vulnerabilities']:
                continue

            for vuln_template in pack['vulnerabilities'][role]:
                vuln = {
                    'id': f'V{vuln_counter}',
                    'device': service['name_template'].format(sid=scenario['scenario_id']),
                    'ip': f"192.168.100.{service['ip_offset']}",
                    'role': role,
                    'pack': pack_id,
                    **vuln_template,
                }
                # Remplacer {ip} dans verification/indicators
                vuln['verification'] = vuln['verification'].format(ip=vuln['ip'])
                vulns.append(vuln)
                vuln_counter += 1

        # Router vulns
        if 'router' in pack['vulnerabilities']:
            for vuln_template in pack['vulnerabilities']['router']:
                vuln = {
                    'id': f'V{vuln_counter}',
                    'device': topology['router']['name_template'].format(sid=scenario['scenario_id']),
                    'ip': '192.168.100.1',
                    'role': 'router',
                    'pack': pack_id,
                    **vuln_template,
                }
                vulns.append(vuln)
                vuln_counter += 1

    # Extra vulns specifiques au scenario
    for v in scenario.get('extra_vulnerabilities', []):
        v['id'] = f'V{vuln_counter}'
        vulns.append(v)
        vuln_counter += 1

    # Scoring automatique
    weights = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    max_score = sum(weights.get(v.get('severity', 'low'), 1) for v in vulns)

    return {
        'scenario_id': scenario['scenario_id'],
        'scenario_name': scenario['name'],
        'difficulty': scenario['difficulty'],
        'topology': build_topology_section(topology, scenario),
        'vulnerabilities': vulns,
        'attack_paths': scenario.get('attack_paths', []),
        'scoring': {
            'total_vulnerabilities': len(vulns),
            'weights': weights,
            'max_weighted_score': max_score,
        },
        'bonus_types': scenario.get('bonus_types', []),
    }
```


## Workflow

### Ajouter une nouvelle vulnerabilite

```
1. Editer packs/definitions/fX_xxx.yaml     → ajouter la vuln pour le role
2. Editer packs/ansible/fX_xxx.yml          → ajouter l'injection Ansible
3. python3 benchmarks/tools/compose_gt.py   → regenere TOUS les ground truths
4. Done. Tous les scenarios qui utilisent ce pack heritent de la vuln.
```

### Creer un nouveau scenario

```
1. Choisir une topologie existante (ou en creer une)
2. Creer scenarios/S8_xxx.yaml avec topology + packs
3. python3 benchmarks/tools/compose_gt.py   → genere le ground truth
4. Done.
```

### Creer un scenario hardened

```
1. Copier un scenario existant
2. Changer packs: [f0_hardened]
3. python3 benchmarks/tools/compose_gt.py   → genere un GT avec 0 vulns
4. Done.
```

### Deployer et tester

```bash
# Deployer le scenario 4
ansible-playbook 03_deploy_scenario.yml -e scenario_id=4

# Injecter les vulns (boucle sur les packs)
ansible-playbook 04_inject.yml -e scenario_id=4

# Ou deployer le scenario 4 hardened
ansible-playbook 04_inject.yml -e scenario_id=4h
# → le playbook voit packs=[f0], applique le hardening

# Lancer le LLM agent
python3 -m src.agent --scenario 4

# Evaluer
python3 -m src.benchmark.evaluator --run-dir output/agent/latest \
  --ground-truth benchmarks/ground_truth/scenario_4.yaml
```


## Migration depuis la structure actuelle

### Ce qui ne change pas
- Le pipeline LLM (src/agent/) reste identique
- L'evaluateur (src/benchmark/evaluator.py) reste identique
- Le format final des ground_truth/*.yaml reste le meme

### Ce qui change
- Les 7 ground truths manuels → auto-generes par compose_gt.py
- Le gros 04_inject_vulns.yml (600 lignes) → eclate en 10 fichiers de pack
- group_vars/all/main.yml → les topologies migrent vers topologies/
- Les scenarios deviennent des fichiers de composition (5-10 lignes chacun)

### Etapes de migration
1. Creer topologies/ depuis les definitions actuelles dans main.yml
2. Extraire les vulns du 04_inject_vulns.yml vers packs/ansible/
3. Extraire les descriptions de vulns des ground truths vers packs/definitions/
4. Ecrire compose_gt.py
5. Creer les scenarios/ (fichiers de composition)
6. Valider que compose_gt.py genere les memes ground truths qu'avant
7. Supprimer les anciens fichiers


## Matrice de couverture

Avec cette structure, on peut generer automatiquement une matrice de couverture :

```
                    f0   f1   f2   f3   f4   f5   f6   f7   f8   f9
                   hard auth misc data prot inj  cryp post info upd
S1  flat            -    x    x    x    -    -    -    -    x    -
S1h flat           [x]   -    -    -    -    -    -    -    -    -
S2  gateway         -    x    x    x    -    -    x    -    x    x
S3  nato_lab        -    x    x    x    -    -    x    x    x    -
S4  ics             -    x    x    x    x    x    x    x    x    x
S4h ics            [x]   -    -    -    -    -    -    -    -    -
S5  building        -    x    x    x    x    -    -    -    x    -
S6  star            -    x    x    x    x    -    -    -    x    x
S7  edge_cloud      -    x    x    x    -    x    x    x    x    x
```

Chaque `x` = le pack est actif pour ce scenario.
`[x]` = pack hardened (f0).

On voit immediatement les trous et on peut decider quels packs ajouter ou.
```
