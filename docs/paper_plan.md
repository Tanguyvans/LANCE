# Plan de publication - IEEE CNS 2026

## 1. Conferences cibles

### Cible principale : IEEE CNS 2026

| | Detail |
|---|---|
| Nom complet | IEEE Conference on Communications and Network Security |
| Edition | 14th |
| Deadline soumission | **18 juillet 2026** |
| Notification | 14 aout 2026 |
| Camera-ready | 14 septembre 2026 |
| Conference | 14-17 septembre 2026 |
| Lieu | Newark, Delaware, USA |
| Format | ~9 pages IEEE double-colonne |
| Indexation | IEEE Xplore |
| Site | https://cns2026.ieee-cns.org/ |
| Taux d'acceptation | ~25-35% (estimation historique) |
| Pourquoi | Conference IEEE de reference en securite reseau. Les reviewers sont exactement le public cible pour un benchmark IoT pentest. Deadline confortable (3 mois). |

### Cible secondaire (fallback) : IEEE ISI 2026

| | Detail |
|---|---|
| Nom complet | IEEE International Conference on Intelligence and Security Informatics |
| Deadline soumission | **16 juin 2026** |
| Notification | ~mi-juillet 2026 |
| Conference | 12-14 aout 2026 |
| Lieu | Cambridge, UK |
| Format | 6 pages IEEE double-colonne |
| Indexation | IEEE Xplore |
| Site | https://ieee-isi.org/2026/ |
| Pourquoi | Topics "AI-based intrusion detection, cybersecurity". Format court (6p) plus facile a ecrire. Fallback si CNS ne convient pas. |

### Strategie de soumission

Option A (recommandee) : cibler CNS directement, utiliser les 3 mois complets.
Option B : soumettre une version 6 pages a ISI (deadline 16 juin), puis version etendue a CNS si ISI rejete.

> Note : verifier les politiques de soumission simultanee de chaque conference.


## 2. Question de recherche

**"Les agents LLM peuvent-ils detecter automatiquement les vulnerabilites IoT
au niveau des scanners traditionnels, et quelles categories de failles
les differencient ?"**

Sous-questions :
- Q1 : Quel est le recall/precision des LLM agents vs OpenVAS/Nmap sur des scenarios IoT realistes ?
- Q2 : Quelles categories de vulnerabilites les LLMs detectent-ils mieux/moins bien que les scanners ?
- Q3 : Les LLMs hallucinent-ils des vulnerabilites, et selon quels patterns ?
- Q4 : La complexite architecturale (flat vs segmente vs edge-cloud) degrade-t-elle la performance ?


## 3. Contributions du papier

1. **IoTBench** : un benchmark open-source de 7-8 scenarios smart city IoT deployables
   sur Proxmox, avec 87+ vulnerabilites injectees couvrant 11 categories, et un evaluateur
   automatique (Recall, Precision, F1, Score pondere par severite).

2. **Evaluation multi-modele** : comparaison de 4+ LLMs (Claude Sonnet, Gemini Flash,
   GPT-4o, DeepSeek) sur le meme benchmark avec repetitions statistiques.

3. **Baseline traditionnelle** : comparaison avec OpenVAS et Nmap NSE sur les memes scenarios,
   montrant les forces complementaires LLM vs scanner.

4. **Analyse qualitative** : identification des patterns de detection et d'echec des LLMs
   par categorie de vulnerabilite, protocole, et complexite architecturale.


## 4. Etat du benchmark

### Scenarios existants (7)

| # | Nom | Diff. | Devices | Vulns | Protocoles | Architecture |
|---|-----|-------|---------|-------|------------|-------------|
| S1 | Reseau plat | Easy | 4 | 12 | MQTT, SSH, HTTP, Telnet | Flat |
| S2 | Gateway exposee | Medium | 6 | 12 | + MariaDB | Gateway-centric |
| S3 | Replique NATO Lab | Hard | 8 | 13 | + FTP | Multi-device complexe |
| S4 | Reseau segmente ICS | Hard | 8 | 14 | + Modbus TCP | IT/OT convergence |
| S5 | Smart Building | Medium | 8 | 10 | + BACnet/IP | Domain-specific |
| S6 | Domotique centralisee | Medium | 6 | 13 | MQTT WS | Hub-centric (star) |
| S7 | Edge-Cloud pivot | Hard | 6 | 13 | Bridge MQTT | Edge-cloud distribue |
| **Total** | | | | **87** | **8 protocoles** | **5 patterns** |

### Categories de vulnerabilites (11)

| Categorie | Count | % | Severites |
|-----------|-------|---|-----------|
| misconfiguration | 17 | 20% | CRIT/HIGH/MED |
| data_exposure | 12 | 14% | HIGH/MED |
| default_credentials | 11 | 13% | CRIT/HIGH |
| info_disclosure | 10 | 11% | LOW |
| no_authentication | 9 | 10% | CRIT/HIGH/MED |
| insecure_update | 4 | 5% | MED |
| weak_crypto | 3 | 3% | LOW |
| missing_header | 3 | 3% | LOW |
| cve (CVE-2023-48795) | 3 | 3% | HIGH |
| code_injection | 3 | 3% | CRIT/HIGH |
| privilege_escalation | 2 | 2% | HIGH |

### Distribution par severite

| Severite | Count | % | Poids |
|----------|-------|---|-------|
| CRITICAL | 10 | 11% | 4 |
| HIGH | 38 | 44% | 3 |
| MEDIUM | 21 | 24% | 2 |
| LOW | 18 | 21% | 1 |

### Couverture OWASP IoT Top 10

| # | OWASP IoT | Couvert ? | Vulns |
|---|-----------|-----------|-------|
| I1 | Weak/Hardcoded Passwords | Oui | default_credentials, MQTT anon |
| I2 | Insecure Network Services | Oui | Telnet, FTP, Modbus, BACnet |
| I3 | Insecure Ecosystem Interfaces | Oui | HTTP no auth, SSRF, API |
| I4 | Lack of Secure Update | Oui | OTA sans signature |
| I5 | Insecure/Outdated Components | Oui | CVE-2023-48795 Terrapin |
| I6 | Insufficient Privacy | Oui | MQTT $SYS, data exposure |
| I7 | Insecure Data Transfer | Oui | weak_crypto, missing_header, .env |
| I8 | Lack of Device Management | Partiel | via insecure_update |
| I9 | Insecure Default Settings | Oui | allow_anonymous, default creds |
| I10 | Lack of Physical Hardening | Non | hors scope (virtualise) |


## 5. Travail restant

### 5.1 Benchmark (avril - mi-mai)

- [ ] Commiter les 21 nouvelles vulnerabilites (evaluator + ground truths + playbook)
- [ ] Optionnel : implementer S8 (Smart Transportation) si on veut CoAP + command injection
- [ ] Deployer les 7 scenarios sur Proxmox et verifier les injections
- [ ] Valider que le pipeline LLM tourne sur chaque scenario

### 5.2 Runs experimentaux (mi-mai - mi-juin)

Matrice experimentale :

| Modele | Provider | Cout/run | Runs/scenario | Total runs |
|--------|----------|----------|---------------|------------|
| Claude Sonnet 4 | Anthropic | ~$1.50 | 3 | 21 |
| Gemini 2.5 Flash | OpenRouter | ~$0.30 | 3 | 21 |
| GPT-4o | OpenRouter | ~$1.00 | 3 | 21 |
| DeepSeek V3 | OpenRouter | ~$0.20 | 3 | 21 |
| **Baseline: Nmap NSE** | local | $0 | 1 | 7 |
| **Baseline: OpenVAS** | local | $0 | 1 | 7 |
| | | | **Total** | **~98 runs** |

Cout estime : ~$150-200 en API calls
Temps estime : ~35h de pipeline (parallelisable)

### 5.3 Baseline non-LLM (mai)

Implementer un script d'evaluation pour les scanners traditionnels :

```bash
# Nmap NSE baseline
nmap -sV -sC --script=vuln,default,discovery -oX nmap_results.xml $TARGET_RANGE

# OpenVAS baseline
# Scanner les memes IPs, exporter en JSON, convertir au format 03_vuln_analysis.json
```

Convertir les resultats au format attendu par l'evaluateur pour une comparaison directe.

### 5.4 Analyse des resultats (juin)

- [ ] Tableaux : Recall/Precision/F1 par modele par scenario
- [ ] Tableaux : Detection rate par categorie de vulnerabilite par modele
- [ ] Heatmap : modele x scenario (score pondere)
- [ ] Radar chart : couverture OWASP IoT Top 10 par modele
- [ ] Analyse des faux positifs : types d'hallucinations les plus frequents
- [ ] Analyse par difficulte : easy vs medium vs hard
- [ ] Analyse par protocole : HTTP/MQTT vs Modbus/BACnet
- [ ] Comparaison LLM vs baseline (OpenVAS/Nmap)
- [ ] Tests statistiques : variance entre runs, significativite des differences

### 5.5 Redaction (juin - juillet)

Timeline de redaction pour la deadline du 18 juillet :

| Semaine | Tache |
|---------|-------|
| 15-21 juin | Structure du papier, related work |
| 22-28 juin | Sections methodology + benchmark description |
| 29 juin - 5 juil | Section results + analysis |
| 6-12 juil | Introduction + conclusion + abstract |
| 13-17 juil | Relecture, polish, figures finales |
| 18 juillet | **Soumission** |


## 6. Structure du papier (9 pages IEEE CNS)

### Titre provisoire
"IoTBench: Benchmarking LLM Agents for Automated Penetration Testing
of Smart City IoT Infrastructure"

### Plan

**I. Introduction** (~1 page)
- Contexte : smart city IoT + surface d'attaque croissante
- Probleme : pentest manuel ne passe pas a l'echelle, scanners automatises limites
- Contribution : IoTBench + evaluation multi-modele + comparaison baseline

**II. Related Work** (~1 page)
- LLMs pour la cybersecurite (PentestGPT, AutoPT, CyberBench)
- Benchmarks IoT existants (IoTBenchmark, SWaT, BATADAL)
- Comparaison : pourquoi notre approche est differente (real VMs, multi-protocol, tool-calling)

**III. IoTBench: Benchmark Design** (~2 pages)
- Architecture des scenarios (topologies, devices, protocoles)
- Injection de vulnerabilites (Ansible, categories OWASP IoT)
- Ground truth et evaluateur automatique (matching strategy, scoring)
- Distribution des vulnerabilites par categorie/severite/protocole

**IV. LLM Agent Pipeline** (~1 page)
- Architecture multi-phase (graph → recon → vuln → exploit → report)
- Tool-calling : graph tools, recon tools, skill tools
- Providers : Anthropic, OpenRouter (Gemini, GPT, DeepSeek)

**V. Experimental Evaluation** (~2.5 pages)
- Setup : Proxmox, 7 scenarios, 4 modeles, 3 runs chacun
- Resultats globaux : Recall, Precision, F1, Score par modele
- Resultats par categorie : heatmap detection rate
- Comparaison LLM vs OpenVAS/Nmap
- Analyse des faux positifs (hallucinations)
- Impact de la complexite architecturale
- Analyse par protocole (IT vs OT/ICS)

**VI. Discussion** (~1 page)
- Pourquoi les LLMs excellent sur certaines categories (misconfiguration, default_creds)
- Pourquoi ils echouent sur d'autres (protocoles industriels, info disclosure)
- Complementarite LLM + scanner traditionnel
- Limitations : scenarios simules, pas de vrais devices, cout API

**VII. Conclusion** (~0.5 page)
- Resume des contributions
- IoTBench disponible en open-source
- Travaux futurs : firmware analysis, physical attacks, real-time defense


## 7. Risques et mitigations

| Risque | Impact | Probabilite | Mitigation |
|--------|--------|-------------|-----------|
| Reviewers jugent "trop engineering" | Rejet | Moyen | Ajouter baseline + analyse qualitative |
| Resultats LLM trop faibles (<30% recall) | Papier peu interessant | Faible | Enrichir les prompts, ajuster le pipeline |
| Resultats LLM trop bons (>90% recall) | "Les vulns sont triviales" | Faible | Montrer la variance par categorie |
| Proxmox tombe pendant les runs | Retard | Faible | Planifier les runs tot (mai) |
| Cout API depasse le budget | Reduction des runs | Faible | Prioriser les modeles les moins chers |
| Scenarios trop similaires entre eux | Reviewers critiquent la diversite | Moyen | Bien documenter les differences architecturales |
| Pas assez de related work LLM+pentest | Gap dans la litterature | Faible | Bon signe : ca rend notre contribution plus nouvelle |


## 8. Ressources

### Infrastructure
- Proxmox sur `10.0.0.110` (VM maitre LXC 200)
- 7 scenarios deployables (VMID 100-179)
- GitHub Actions CI/CD sur la VM maitre
- Accessible via Tailscale `nato-master.tail6b8e31.ts.net:8501`

### API keys necessaires
- Anthropic (Claude Sonnet) — existant
- OpenRouter (Gemini, GPT-4o, DeepSeek) — existant
- Voyage AI (embeddings knowledge store) — existant

### Outils
- OpenVAS : a installer sur la VM maitre ou un CT dedie
- Nmap + NSE scripts : deja disponible
- LaTeX IEEE template : `IEEEtran.cls`
