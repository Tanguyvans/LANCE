# Architectures & Failles — Diagrammes

## Couverture des référentiels

| Référentiel | Couverture | Détails |
|---|---|---|
| OWASP IoT Top 10 | **9/10** | Manque uniquement #10 Physical Hardening (non simulable en VM) |
| MITRE ATT&CK ICS | **9/12** | Manque Evasion, Persistence avancée, Inhibit Response Function |
| Couches IoT | **3/4** | Manque couche Perception (capteurs physiques réels) |

### Mapping détaillé OWASP IoT Top 10

| # | OWASP IoT | Pack(s) |
|---|---|---|
| 1 | Weak/Hardcoded Passwords | F1 |
| 2 | Insecure Network Services | F2 |
| 3 | Insecure Ecosystem Interfaces | F4, F8 |
| 4 | Lack of Secure Update Mechanism | F10 |
| 5 | Insecure/Outdated Components | F3 |
| 6 | Insufficient Privacy Protection | F8 |
| 7 | Insecure Data Transfer & Storage | F6, F8 |
| 8 | Lack of Device Management | F10 |
| 9 | Insecure Default Settings | F1, F2 |
| 10 | Lack of Physical Hardening | Non simulable en VM |

### Mapping détaillé MITRE ATT&CK ICS

| Tactique | Pack(s) |
|---|---|
| Initial Access | F1, F2, F3 |
| Execution | F3 (RCE), F9 (injection) |
| Persistence | F7 (backdoor post-pivot) |
| Discovery | F2 (services exposés), F5 (ICMP non filtré) |
| Lateral Movement | F5, F7 |
| Collection | F8 (data exposure) |
| Command & Control | F9 (DNS spoofing, tunneling) |
| Impair Process Control | F4 (Modbus), F9 (MITM) |
| Impact | F9 (DoS, destruction) |

---

## Architectures

### A1 — Flat (réseau plat)

Tous les devices sur le même réseau, pas de segmentation.

```mermaid
graph LR
    Internet((Internet))
    Router[Router<br/>MikroTik CHR]
    MQTT[MQTT Broker<br/>Mosquitto]
    WebServer[Web Server<br/>nginx]
    SSH[SSH Server<br/>Debian]
    IoTDevice[IoT Device<br/>Capteur simulé]

    Internet -->|WAN| Router
    Router -->|192.168.88.0/24| MQTT
    Router --> WebServer
    Router --> SSH
    Router --> IoTDevice
    MQTT -.->|subscribe| IoTDevice
```

**VMs :** 5
**Réseau :** 1 (192.168.88.0/24)
**Cas d'usage :** Petit déploiement IoT sans budget sécu

---

### A2 — Star (hub central)

Un hub central (gateway IoT) connecte tous les devices.

```mermaid
graph TD
    Internet((Internet))
    Router[Router<br/>MikroTik CHR]
    Hub[IoT Hub<br/>Debian + Node-RED]
    Sensor1[Capteur Temp<br/>MQTT client]
    Sensor2[Capteur Humidity<br/>MQTT client]
    Camera[Caméra IP<br/>RTSP stream]
    Actuator[Actionneur<br/>Relais MQTT]
    DB[(Base de données<br/>InfluxDB)]

    Internet -->|WAN| Router
    Router --> Hub
    Hub --> Sensor1
    Hub --> Sensor2
    Hub --> Camera
    Hub --> Actuator
    Hub --> DB
```

**VMs :** 6-7
**Réseau :** 1
**Cas d'usage :** Smart home, domotique centralisée

---

### A3 — Gateway (DMZ + LAN)

Zone démilitarisée exposée + réseau interne protégé.

```mermaid
graph LR
    Internet((Internet))
    Firewall[Firewall/Router<br/>MikroTik CHR]

    subgraph DMZ ["DMZ (172.16.0.0/24)"]
        WebServer[Web Server<br/>nginx]
        API[API Gateway<br/>REST]
    end

    subgraph LAN ["LAN (192.168.88.0/24)"]
        MQTT[MQTT Broker<br/>Mosquitto]
        IoTGW[IoT Gateway<br/>OpenWrt]
        DB[(Database<br/>PostgreSQL)]
    end

    Internet -->|WAN| Firewall
    Firewall --> WebServer
    Firewall --> API
    Firewall --> MQTT
    Firewall --> IoTGW
    Firewall --> DB
    API -->|autorisé| MQTT
    IoTGW -->|publish| MQTT
    MQTT -->|store| DB
```

**VMs :** 6-7
**Réseaux :** 2 (DMZ + LAN)
**Cas d'usage :** Plateforme IoT avec portail web public

---

### A4 — Segmenté (2 VLANs + firewall)

Séparation IT / IoT avec firewall inter-zones.

```mermaid
graph TB
    Internet((Internet))
    Firewall[Firewall<br/>MikroTik CHR]

    subgraph VLAN10 ["VLAN 10 — IT"]
        Admin[Poste Admin<br/>Debian]
        WebApp[Application Web<br/>nginx + app]
        Monitor[Monitoring<br/>Grafana]
    end

    subgraph VLAN20 ["VLAN 20 — IoT"]
        MQTT[MQTT Broker<br/>Mosquitto]
        GW_LoRa[Gateway LoRa<br/>OpenWrt]
        GW_Zigbee[Gateway Zigbee<br/>Debian]
        Sensor1[Capteur 1]
        Sensor2[Capteur 2]
    end

    Internet -->|WAN| Firewall
    Firewall --> Admin
    Firewall --> WebApp
    Firewall --> Monitor
    Firewall --> MQTT
    Firewall --> GW_LoRa
    Firewall --> GW_Zigbee
    GW_LoRa -->|publish| MQTT
    GW_Zigbee -->|publish| MQTT
    Sensor1 -.->|LoRaWAN| GW_LoRa
    Sensor2 -.->|Zigbee| GW_Zigbee
    Monitor -->|query| MQTT
    WebApp -->|API| MQTT
```

**VMs :** 8-10
**Réseaux :** 2 VLANs + WAN
**Cas d'usage :** Entreprise avec réseau IoT séparé

---

### A5 — Multi-zone (3+ VLANs)

Architecture industrielle avec zones IT / IoT / OT.

```mermaid
graph TB
    Internet((Internet))
    FW_Edge[Firewall Edge<br/>MikroTik CHR]

    subgraph IT ["VLAN 10 — IT"]
        Admin[Admin PC]
        WebPortal[Portail Web<br/>nginx]
        SIEM[SIEM / Logs<br/>Debian]
    end

    subgraph IOT ["VLAN 20 — IoT"]
        MQTT[MQTT Broker<br/>Mosquitto]
        GW1[Gateway 1<br/>OpenWrt]
        GW2[Gateway 2<br/>Debian]
        Sensors[Capteurs x3]
    end

    subgraph OT ["VLAN 30 — OT"]
        PLC[PLC Simulé<br/>Modbus TCP]
        HMI[HMI / SCADA<br/>Web interface]
        Historian[(Historian<br/>Base SQL)]
    end

    Internet -->|WAN| FW_Edge
    FW_Edge --> Admin
    FW_Edge --> WebPortal
    FW_Edge --> SIEM
    FW_Edge --> MQTT
    FW_Edge --> GW1
    FW_Edge --> GW2
    FW_Edge --> PLC
    FW_Edge --> HMI
    FW_Edge --> Historian
    Sensors -.-> GW1
    Sensors -.-> GW2
    GW1 -->|publish| MQTT
    GW2 -->|publish| MQTT
    MQTT -->|bridge| PLC
    HMI -->|Modbus| PLC
    HMI -->|store| Historian
    SIEM -->|collect| MQTT
```

**VMs :** 10-12
**Réseaux :** 3 VLANs + WAN
**Cas d'usage :** Usine connectée, smart building industriel

---

### A6 — Mesh (interconnexion multiple)

Devices qui communiquent entre eux sans point central unique.

```mermaid
graph LR
    Internet((Internet))
    Router[Router<br/>MikroTik CHR]

    subgraph Mesh ["Réseau Mesh (192.168.88.0/24)"]
        Node1[Node 1<br/>MQTT + SSH]
        Node2[Node 2<br/>MQTT + HTTP]
        Node3[Node 3<br/>MQTT + CoAP]
        Node4[Node 4<br/>MQTT + Modbus]
        Node5[Node 5<br/>MQTT Bridge]
        GW[Gateway<br/>OpenWrt]
    end

    Internet -->|WAN| Router
    Router --> GW
    GW --> Node1
    GW --> Node2
    Node1 <-->|MQTT| Node2
    Node2 <-->|MQTT| Node3
    Node3 <-->|MQTT| Node4
    Node4 <-->|MQTT| Node5
    Node5 <-->|MQTT| Node1
    Node1 <-->|MQTT| Node3
```

**VMs :** 6-8
**Réseau :** 1 (mais communication pair-à-pair)
**Cas d'usage :** Réseau de capteurs distribué, smart city outdoor

---

### A7 — Edge-Cloud (edge local + cloud)

Architecture avec traitement local (edge) et remontée vers un cloud simulé.

```mermaid
graph TB
    PublicCloud((Cloud Simulé))

    subgraph Cloud ["Cloud Zone (10.0.0.0/24)"]
        CloudMQTT[Cloud MQTT<br/>Broker central]
        Dashboard[Dashboard<br/>Grafana]
        CloudDB[(Cloud DB<br/>PostgreSQL)]
        API[Cloud API<br/>REST]
    end

    subgraph Edge ["Edge Zone (192.168.88.0/24)"]
        EdgeGW[Edge Gateway<br/>OpenWrt]
        EdgeMQTT[Edge MQTT<br/>Mosquitto local]
        Compute[Edge Compute<br/>Debian]
        Sensor1[Capteur 1]
        Sensor2[Capteur 2]
        Actuator[Actionneur]
    end

    PublicCloud -->|WAN| API
    EdgeGW -->|VPN / WAN| CloudMQTT
    EdgeMQTT -->|bridge| CloudMQTT
    CloudMQTT --> Dashboard
    CloudMQTT --> CloudDB
    Sensor1 --> EdgeMQTT
    Sensor2 --> EdgeMQTT
    EdgeMQTT --> Compute
    Compute --> Actuator
    EdgeGW --> EdgeMQTT
    EdgeGW --> Compute
```

**VMs :** 8-10
**Réseaux :** 2 (Edge + Cloud) reliés par VPN/WAN simulé
**Cas d'usage :** Déploiement IoT avec cloud analytics

---

### A8 — Multi-site VPN (deux sites distants)

Deux sites reliés par un tunnel VPN, chacun avec sa propre infrastructure IoT.

```mermaid
graph TB
    Internet((Internet))

    subgraph SiteA ["Site A — Bureau principal"]
        FW_A[Firewall A<br/>MikroTik CHR]
        Admin_A[Admin PC]
        Dashboard_A[Dashboard<br/>Grafana]
        MQTT_A[MQTT Broker A<br/>Mosquitto]
        DB_A[(Database<br/>PostgreSQL)]
    end

    subgraph SiteB ["Site B — Site distant"]
        FW_B[Firewall B<br/>MikroTik CHR]
        GW_B[IoT Gateway<br/>OpenWrt]
        MQTT_B[MQTT Broker B<br/>Mosquitto]
        Sensor_B1[Capteur 1]
        Sensor_B2[Capteur 2]
        Actuator_B[Actionneur]
    end

    Internet --> FW_A
    Internet --> FW_B
    FW_A <-->|VPN IPsec/WireGuard| FW_B
    FW_A --> Admin_A
    FW_A --> Dashboard_A
    FW_A --> MQTT_A
    FW_A --> DB_A
    MQTT_A <-->|bridge| MQTT_B
    FW_B --> GW_B
    FW_B --> MQTT_B
    GW_B --> Sensor_B1
    GW_B --> Sensor_B2
    GW_B --> Actuator_B
    Sensor_B1 -->|publish| MQTT_B
    Sensor_B2 -->|publish| MQTT_B
    Dashboard_A -->|query| DB_A
    MQTT_A -->|store| DB_A
```

**VMs :** 10-12
**Réseaux :** 3 (Site A LAN + Site B LAN + VPN tunnel)
**Cas d'usage :** Entreprise multi-sites, gestion centralisée IoT

---

---

## Packs de failles

### F1 — Auth faible

```mermaid
graph TD
    F1[Pack F1<br/>Auth Faible]
    F1a[SSH default creds<br/>admin/admin]
    F1b[MQTT anonymous<br/>allow_anonymous true]
    F1c[Web admin<br/>admin/password]
    F1d[Base de données<br/>root sans mot de passe]
    F1e[SNMP community<br/>public/private]

    F1 --> F1a
    F1 --> F1b
    F1 --> F1c
    F1 --> F1d
    F1 --> F1e

    style F1 fill:#e74c3c,color:#fff
    style F1a fill:#ffcccc
    style F1b fill:#ffcccc
    style F1c fill:#ffcccc
    style F1d fill:#ffcccc
    style F1e fill:#ffcccc
```

**Injection Ansible :**
- Configurer Mosquitto avec `allow_anonymous true`
- Créer user SSH `admin` / mot de passe `admin`
- Installer MySQL/PostgreSQL sans mot de passe root
- Configurer SNMP avec community string `public`

**OWASP :** #1, #9 | **MITRE :** Initial Access

---

### F2 — Services exposés

```mermaid
graph TD
    F2[Pack F2<br/>Services Exposés]
    F2a[Telnet ouvert<br/>port 23]
    F2b[Admin panel<br/>sur 0.0.0.0]
    F2c[FTP ouvert<br/>port 21]
    F2d[Debug port<br/>Node.js inspect 9229]
    F2e[MQTT sur WAN<br/>pas de bind local]

    F2 --> F2a
    F2 --> F2b
    F2 --> F2c
    F2 --> F2d
    F2 --> F2e

    style F2 fill:#e67e22,color:#fff
    style F2a fill:#ffecd2
    style F2b fill:#ffecd2
    style F2c fill:#ffecd2
    style F2d fill:#ffecd2
    style F2e fill:#ffecd2
```

**Injection Ansible :**
- Installer et activer telnetd
- Configurer nginx/app pour écouter sur `0.0.0.0`
- Installer vsftpd avec accès anonymous
- Lancer Node.js avec `--inspect=0.0.0.0:9229`

**OWASP :** #2, #9 | **MITRE :** Initial Access, Discovery

---

### F3 — Software outdated (CVEs connues)

```mermaid
graph TD
    F3[Pack F3<br/>Software Outdated]
    F3a[nginx 1.19.6<br/>CVE-2021-23017]
    F3b[Dropbear 2020.81<br/>CVE-2023-48795 Terrapin]
    F3c[OpenSSH 8.2<br/>CVE-2023-38408]
    F3d[Log4j simulé<br/>CVE-2021-44228]
    F3e[curl outdated<br/>CVE-2023-38545]

    F3 --> F3a
    F3 --> F3b
    F3 --> F3c
    F3 --> F3d
    F3 --> F3e

    style F3 fill:#8e44ad,color:#fff
    style F3a fill:#e8d5f5
    style F3b fill:#e8d5f5
    style F3c fill:#e8d5f5
    style F3d fill:#e8d5f5
    style F3e fill:#e8d5f5
```

**Injection Ansible :**
- Installer nginx 1.19.6 depuis les archives
- Compiler Dropbear 2020.81 depuis les sources
- Installer OpenSSH 8.2 depuis les archives
- Déployer une app Java avec Log4j 2.14.1

**OWASP :** #5 | **MITRE :** Initial Access, Execution

---

### F4 — Protocoles IoT non sécurisés

```mermaid
graph TD
    F4[Pack F4<br/>Protocoles IoT]
    F4a[MQTT sans auth<br/>+ sans TLS]
    F4b[Modbus TCP<br/>sans authentification]
    F4c[CoAP ouvert<br/>sans DTLS]
    F4d[MQTT topics<br/>pas de ACL]
    F4e[HTTP API REST<br/>sans token/auth]

    F4 --> F4a
    F4 --> F4b
    F4 --> F4c
    F4 --> F4d
    F4 --> F4e

    style F4 fill:#2ecc71,color:#fff
    style F4a fill:#d5f5e3
    style F4b fill:#d5f5e3
    style F4c fill:#d5f5e3
    style F4d fill:#d5f5e3
    style F4e fill:#d5f5e3
```

**Injection Ansible :**
- Mosquitto : `allow_anonymous true`, pas de `certfile`
- Installer `pymodbus` simulateur sans auth
- Installer `aiocoap` serveur sans DTLS
- MQTT : pas de fichier ACL, tous les topics accessibles

**OWASP :** #3 | **MITRE :** Impair Process Control

---

### F5 — Firewall / segmentation faible

```mermaid
graph TD
    F5[Pack F5<br/>Firewall Faible]
    F5a[Règle ANY→ANY<br/>entre VLANs]
    F5b[Pas de egress filter<br/>tout le trafic sort]
    F5c[DMZ→LAN autorisé<br/>pas d'isolation]
    F5d[ICMP non filtré<br/>scan possible]
    F5e[Port forwarding<br/>excessif depuis WAN]

    F5 --> F5a
    F5 --> F5b
    F5 --> F5c
    F5 --> F5d
    F5 --> F5e

    style F5 fill:#3498db,color:#fff
    style F5a fill:#d6eaf8
    style F5b fill:#d6eaf8
    style F5c fill:#d6eaf8
    style F5d fill:#d6eaf8
    style F5e fill:#d6eaf8
```

**Injection Ansible :**
- MikroTik : ajouter règle `accept` inter-VLAN
- Pas de règle `drop` en egress
- Port forwarding WAN → services internes

**OWASP :** #2 | **MITRE :** Lateral Movement, Discovery

---

### F6 — Crypto faible

```mermaid
graph TD
    F6[Pack F6<br/>Crypto Faible]
    F6a[SSH weak ciphers<br/>arcfour, 3des-cbc]
    F6b[HTTP sans TLS<br/>admin en clair]
    F6c[MQTT sans TLS<br/>credentials en clair]
    F6d[Certificats self-signed<br/>expirés]
    F6e[Clés SSH par défaut<br/>non regénérées]

    F6 --> F6a
    F6 --> F6b
    F6 --> F6c
    F6 --> F6d
    F6 --> F6e

    style F6 fill:#1abc9c,color:#fff
    style F6a fill:#d1f2eb
    style F6b fill:#d1f2eb
    style F6c fill:#d1f2eb
    style F6d fill:#d1f2eb
    style F6e fill:#d1f2eb
```

**Injection Ansible :**
- sshd_config : `Ciphers 3des-cbc,arcfour`
- nginx sans bloc `ssl`
- Mosquitto sans `certfile`/`keyfile`
- Générer un certificat expiré avec `openssl`

**OWASP :** #7 | **MITRE :** Collection

---

### F7 — Chaînes de pivot (multi-hop)

```mermaid
graph LR
    F7[Pack F7<br/>Pivot Chains]

    subgraph Chain1 ["Chaîne 1 — Web → DB"]
        Web1[Web vulnérable<br/>SQLi] -->|exploit| DB1[DB sans auth<br/>data leak]
    end

    subgraph Chain2 ["Chaîne 2 — SSH → MQTT → IoT"]
        SSH1[SSH weak creds] -->|pivot| MQTT1[MQTT open] -->|publish| IoT1[Actionneur<br/>commande malveillante]
    end

    subgraph Chain3 ["Chaîne 3 — Web → Réseau interne → OT"]
        Web2[SSRF] -->|accès interne| FW1[Firewall bypass] -->|Modbus| PLC1[PLC<br/>arrêt process]
    end

    F7 --> Chain1
    F7 --> Chain2
    F7 --> Chain3

    style F7 fill:#c0392b,color:#fff
```

**Injection Ansible :**
- Combiner les failles des autres packs
- S'assurer que le chemin de pivot est exploitable de bout en bout
- Configurer les routes/firewall pour que le chaînage fonctionne

**OWASP :** #3 | **MITRE :** Lateral Movement

---

### F8 — Data exposure (fuite de données)

```mermaid
graph TD
    F8[Pack F8<br/>Data Exposure]
    F8a[MQTT topics sensibles<br/>credentials, PII dans payloads]
    F8b[Logs avec secrets<br/>API keys, passwords en clair]
    F8c[.env exposé<br/>fichier accessible via HTTP]
    F8d[Base de données<br/>données non chiffrées]
    F8e[API sans pagination<br/>dump complet possible]
    F8f[Backup exposé<br/>fichier .sql/.tar accessible]

    F8 --> F8a
    F8 --> F8b
    F8 --> F8c
    F8 --> F8d
    F8 --> F8e
    F8 --> F8f

    style F8 fill:#f39c12,color:#fff
    style F8a fill:#fef3cd
    style F8b fill:#fef3cd
    style F8c fill:#fef3cd
    style F8d fill:#fef3cd
    style F8e fill:#fef3cd
    style F8f fill:#fef3cd
```

**Injection Ansible :**
- Publier des données sensibles simulées sur MQTT topics (`home/alarm/code`, `system/credentials`)
- Écrire des API keys/passwords dans `/var/log/app.log`
- Placer un `.env` avec des secrets dans le webroot nginx
- Créer une base avec des données PII non chiffrées (noms, emails, tokens)
- API REST qui retourne tout sans pagination ni auth
- Laisser un `backup.sql` dans `/var/www/html/`

**OWASP :** #6, #7 | **MITRE :** Collection

---

### F9 — Attaques réseau actives (DoS, MITM)

```mermaid
graph TD
    F9[Pack F9<br/>Attaques Réseau]
    F9a[ARP spoofing possible<br/>pas de protection ARP]
    F9b[DoS MQTT<br/>broker sans rate limiting]
    F9c[DNS spoofing<br/>pas de DNSSEC]
    F9d[SYN flood<br/>pas de SYN cookies]
    F9e[Replay attack<br/>tokens sans expiration]
    F9f[VLAN hopping<br/>trunk port mal configuré]

    F9 --> F9a
    F9 --> F9b
    F9 --> F9c
    F9 --> F9d
    F9 --> F9e
    F9 --> F9f

    style F9 fill:#e74c3c,color:#fff
    style F9a fill:#f5b7b1
    style F9b fill:#f5b7b1
    style F9c fill:#f5b7b1
    style F9d fill:#f5b7b1
    style F9e fill:#f5b7b1
    style F9f fill:#f5b7b1
```

**Injection Ansible :**
- Désactiver ARP inspection sur le switch/routeur
- Mosquitto sans `max_connections` ni `max_inflight_messages`
- DNS local sans validation DNSSEC
- Désactiver SYN cookies : `sysctl net.ipv4.tcp_syncookies=0`
- API avec tokens JWT sans expiration (`exp` très loin)
- Configurer un port trunk sans restriction de VLANs

**OWASP :** #2 | **MITRE :** Impact, Command & Control, Impair Process Control

---

### F10 — Insecure update & management

```mermaid
graph TD
    F10[Pack F10<br/>Insecure Update]
    F10a[OTA sans signature<br/>firmware download HTTP]
    F10b[Pas de vérification intégrité<br/>pas de checksum]
    F10c[Management interface<br/>accessible sans auth]
    F10d[API de config<br/>write sans authentification]
    F10e[Auto-update désactivé<br/>versions figées vulnérables]
    F10f[TFTP ouvert<br/>config accessible]

    F10 --> F10a
    F10 --> F10b
    F10 --> F10c
    F10 --> F10d
    F10 --> F10e
    F10 --> F10f

    style F10 fill:#6c3483,color:#fff
    style F10a fill:#d7bde2
    style F10b fill:#d7bde2
    style F10c fill:#d7bde2
    style F10d fill:#d7bde2
    style F10e fill:#d7bde2
    style F10f fill:#d7bde2
```

**Injection Ansible :**
- Serveur HTTP avec faux firmware (pas de signature, téléchargeable)
- Pas de fichier `.sha256` ou `.sig` à côté du firmware
- Interface web de management sans login (ex: Node-RED sans auth)
- API REST `PUT /config` sans token
- Figer les versions de tous les packages (pas d'`unattended-upgrades`)
- Installer un serveur TFTP avec les configs accessibles

**OWASP :** #4, #8 | **MITRE :** Initial Access, Execution

---

## Matrice de combinaison

```mermaid
graph TB
    subgraph Architectures
        A1[A1 Flat]
        A2[A2 Star]
        A3[A3 Gateway]
        A4[A4 Segmenté]
        A5[A5 Multi-zone]
        A6[A6 Mesh]
        A7[A7 Edge-Cloud]
        A8[A8 Multi-site VPN]
    end

    subgraph Packs
        F1[F1 Auth faible]
        F2[F2 Services exposés]
        F3[F3 Software outdated]
        F4[F4 Protocoles IoT]
        F5[F5 Firewall faible]
        F6[F6 Crypto faible]
        F7[F7 Pivot chains]
        F8[F8 Data exposure]
        F9[F9 Attaques réseau]
        F10[F10 Insecure update]
    end

    A1 --- F1
    A1 --- F2
    A1 --- F9
    A2 --- F1
    A2 --- F4
    A2 --- F8
    A2 --- F10
    A3 --- F3
    A3 --- F5
    A3 --- F8
    A4 --- F4
    A4 --- F5
    A4 --- F9
    A5 --- F5
    A5 --- F7
    A5 --- F9
    A6 --- F4
    A6 --- F6
    A6 --- F9
    A7 --- F1
    A7 --- F3
    A7 --- F7
    A7 --- F8
    A8 --- F5
    A8 --- F6
    A8 --- F7
    A8 --- F10

    style A1 fill:#3498db,color:#fff
    style A2 fill:#3498db,color:#fff
    style A3 fill:#3498db,color:#fff
    style A4 fill:#3498db,color:#fff
    style A5 fill:#3498db,color:#fff
    style A6 fill:#3498db,color:#fff
    style A7 fill:#3498db,color:#fff
    style A8 fill:#3498db,color:#fff
    style F1 fill:#e74c3c,color:#fff
    style F2 fill:#e67e22,color:#fff
    style F3 fill:#8e44ad,color:#fff
    style F4 fill:#2ecc71,color:#fff
    style F5 fill:#3498db,color:#fff
    style F6 fill:#1abc9c,color:#fff
    style F7 fill:#c0392b,color:#fff
    style F8 fill:#f39c12,color:#fff
    style F9 fill:#e74c3c,color:#fff
    style F10 fill:#6c3483,color:#fff
```

### Scénarios proposés (8 × 10 = 80 combinaisons possibles, 20 sélectionnées)

| # | Architecture | Packs | Difficulté | Vulns | Focus |
|---|---|---|---|---|---|
| S01 | A1 Flat | F1 | Easy | 3-4 | Auth basique |
| S02 | A1 Flat | F2+F9 | Easy | 5-6 | Services + DoS |
| S03 | A1 Flat | F1+F3+F8 | Easy-Med | 8-10 | Auth + CVE + data |
| S04 | A2 Star | F1+F4 | Easy | 5-6 | Auth + protocoles IoT |
| S05 | A2 Star | F4+F8+F10 | Medium | 8-10 | IoT complet |
| S06 | A2 Star | F2+F6+F9 | Medium | 8-10 | Exposition + réseau |
| S07 | A3 Gateway | F1+F5 | Medium | 5-7 | Auth + firewall |
| S08 | A3 Gateway | F3+F5+F8 | Medium | 8-10 | CVE + pivot + data |
| S09 | A3 Gateway | F1+F4+F5+F9 | Med-Hard | 10-12 | Multi-vecteur |
| S10 | A4 Segmenté | F4+F5 | Medium | 6-8 | Segmentation IoT |
| S11 | A4 Segmenté | F1+F3+F5+F9 | Hard | 10-12 | Multi-vecteur |
| S12 | A4 Segmenté | F5+F6+F8+F10 | Hard | 10-14 | Défense en profondeur |
| S13 | A5 Multi-zone | F5+F7 | Hard | 8-10 | Pivot cross-zone |
| S14 | A5 Multi-zone | F4+F5+F7+F9 | Very Hard | 12-16 | Attaque complète IT→OT |
| S15 | A6 Mesh | F4+F6 | Medium | 6-8 | Protocoles + crypto |
| S16 | A6 Mesh | F4+F6+F9 | Hard | 9-12 | Mesh hostile |
| S17 | A7 Edge-Cloud | F1+F8 | Medium | 6-8 | Fuite edge→cloud |
| S18 | A7 Edge-Cloud | F3+F7+F8 | Hard | 10-12 | Pivot edge→cloud |
| S19 | A8 Multi-site | F5+F6+F7 | Hard | 9-12 | VPN + pivot inter-site |
| S20 | A8 Multi-site | F5+F7+F9+F10 | Very Hard | 12-16 | Compromission totale |
