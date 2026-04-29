# Sélection des baselines pour la comparaison expérimentale

> Document de travail pour la section §7.2 *"Network-scale vs baselines"* du papier ACSAC.
> Objectif : choisir un ensemble défendable de baselines qui couvre **toutes les catégories** auxquelles un reviewer s'attend.

---

## 1. Cadrage : pourquoi 4 catégories de baselines ?

Le reviewer ACSAC sceptique se posera 4 questions, dans cet ordre :

1. *"Un scanner classique ne ferait-il pas l'affaire ?"* → besoin de **baseline scanner non-LLM**
2. *"Un framework offensif traditionnel n'est-il pas déjà multi-host ?"* → besoin de **baseline framework réseau**
3. *"Y a-t-il un agent LLM à l'état de l'art qui fait déjà ça ?"* → besoin de **baseline LLM agent**
4. *"Quelle est la valeur de votre architecture en propre ?"* → besoin d'**ablations internes**

Si on saute une de ces 4 catégories, on offre le flanc. **Un reviewer ACSAC a un bingo card mental, il faut le cocher entièrement.**

---

## 2. Catégorie A — Scanners non-LLM (lower bound de détection)

Ces outils sont **autonomes mais sans exploitation** ni multi-hop. Ils répondent à la question : *"qu'est-ce qu'un scan automatique trouve déjà sans IA ?"*

| Outil | Type | Force | Faiblesse | Effort intégration |
|---|---|---|---|---|
| **Nmap + NSE** | Scripts (mqtt-info, ssh-auth, modbus-discover, default-creds…) | Déjà dans le repo, déterministe, gratuit | Pas d'agrégation cross-device, pas d'exploit | 1 j (mode "tout NSE") |
| **OpenVAS / Greenbone** | Scanner CVE-driven complet | Référence industrielle | Lourd à installer, focus CVE pas misconfig | 2-3 j |
| **Nuclei** (ProjectDiscovery) | Templates YAML rapides, dont IoT | Léger, large catalogue, FOSS actif | Surtout web/HTTP, peu OT | 1-2 j |

**Hypothèse à tester :** ces scanners attrapent les CVE connues mais **manquent les misconfigurations** (MQTT anonyme, root sans mot de passe, credentials par défaut).

Or **>60% de notre GT n'est PAS du `known_cve`** (cf. `04_iotbench.tex` Tab. categories : 11 default_credentials + 17 misconfiguration + 12 data_exposure + 9 no_authentication = 49/87). Donc ces scanners plafonnent mécaniquement. **C'est notre argument fort sur l'IA.**

→ **Recommandation A : Nmap NSE (P1) + Nuclei (P2).** OpenVAS optionnel.

---

## 3. Catégorie B — Frameworks offensifs traditionnels (référence multi-host)

C'est la catégorie que j'avais sous-traitée. **Ces outils existent depuis 15-20 ans et savent faire du réseau.** Le reviewer expert demandera "pourquoi pas Metasploit ?". Il faut une réponse écrite.

### B.1 Frameworks manuels (citation, pas test)

| Outil | Capacité multi-hop | Autonome ? | Adapté à notre éval ? |
|---|---|---|---|
| **Metasploit** | Oui (post-exploit, pivots, autoroute) | Non — pilote humain ou script | Pas comparable directement (n'est pas un agent autonome) |
| **Cobalt Strike** | Oui (Beacon, lateral movement) | Non — opérateur humain | Commercial + opérateur — hors scope |
| **Sliver** | Oui (C2 moderne) | Non — opérateur humain | Hors scope |
| **Empire / Starkiller** | Oui (post-exploit AD) | Non — opérateur humain | AD-only, hors scope |

**Position dans le papier :** ces outils sont **mentionnés en background §2** mais **pas testés comme baseline**. Justification claire :

> *"Frameworks like Metasploit and Cobalt Strike are the traditional baseline for multi-device pentest, but they require a human operator driving the workflow. As such they are not directly comparable to autonomous LLM agents; rather, the agents in this paper aim to automate decisions that those frameworks delegate to the operator."*

C'est **la phrase-bouclier** anti-reviewer.

### B.2 Outils auto-pilotables (testables comme baseline scriptée)

| Outil | Capacité | Force | Faiblesse |
|---|---|---|---|
| **Metasploit `db_autopwn`** | Exploit auto basé sur scan importé | Multi-host, autoroute possible | Quasi-déprécié (≥2010), faible sur IoT moderne |
| **CrackMapExec / NetExec** | Spraying credentials + lateral SMB/SSH/MSSQL | Multi-host, automatisable, FOSS | Focus AD/Windows, peu d'IoT |
| **Routersploit** | Framework exploit routeurs/IoT | IoT-spécifique, FOSS | Catalogue exploits limité, plus maintenu activement |
| **BloodHound + Neo4j** | **Attack-path graph-based** sur AD | Conceptuellement le plus proche de notre approche | AD-only, donc inutilisable sur ton bench IoT |

→ **Recommandation B : NetExec sur les scénarios qui ont SSH/MySQL/SMB** comme baseline scriptée. C'est gratuit, multi-host, et fait du credential reuse cross-device — le test parfait du multi-hop sans LLM.

**BloodHound n'est PAS testable** (AD-only) **mais doit être cité** dans §2 related work comme l'inspiration méthodologique du graph-based attack path. C'est l'analogue conceptuel exact, mais sur un autre domaine.

---

## 4. Catégorie C — Agents LLM-pentest (concurrents directs)

Vérifié dans la conversation précédente. Synthèse rapide :

| Outil | Venue | Code | Test prioritaire ? |
|---|---|---|---|
| **CAI** | arXiv 2504.06017 + 2 suites 2025, Dragos OT top-10 | ✅ | **OUI — P1** (concurrent canonique 2025) |
| **PentestGPT** | USENIX Security 2024 ⭐ | ✅ | **OUI — P1** (référence historique) |
| **VulnBot** | arXiv 2501.13411 (multi-agent + PTG) | ✅ | OUI — P2 (le plus proche structurellement) |
| **PentestAgent** | AsiaCCS 2025 ⭐ | ✅ | NON (web-only, peu transférable) |
| **AutoPentester** | arXiv 2510.05605 (IEEE) | ⚠️ à vérifier | NON (peu de différence vs PentestGPT pour notre angle) |
| **HackingBuddyGPT** | arXiv 2310.11409 (TU Wien) | ✅ | NON (privilege escalation Linux mono-host, trop minimaliste) |

→ **Recommandation C : CAI (P1) + PentestGPT (P1) + VulnBot (P2).**

---

## 5. Catégorie D — Ablations internes du pipeline

Pour prouver que **chaque** module du pipeline contribue, donc que les choix architecturaux sont défendables.

| Variante | Ce qu'elle teste | Hypothèse |
|---|---|---|
| **w/o Phase 1 (graph)** | Apport du graph-guidance | Score chute sur patterns gateway/hub-star/IT-OT (qui imposent un pivot) |
| **w/o Phase 3a scanner** | Apport du scanner déterministe | Score chute (LLM seul rate des trivial findings) |
| **w/o Phase 4 micro-agents** | Apport de la confirmation per-vuln | Precision chute (Phase 3 hallucine) |
| **w/o Phase 5 intrusion** | Apport du lateral movement | MHR₂/MHR₃ chute à 0 |
| **w/o knowledge store (RAG)** | Apport de ChromaDB | Score chute sur protocoles spécialisés (LoRaWAN, Modbus) |

→ **Recommandation D : 5 ablations, 1 run par scénario suffit** (variance moins critique pour les ablations).

---

## 6. Recommandation finale — plan minimal défendable

### Minimum vital (avant freeze 2 mai)
| Priorité | Item | Effort | Why |
|---|---|---|---|
| 1 | **Nmap NSE** complet sur 7 scénarios | 1 j | Lower bound non-LLM, déjà dans le repo |
| 2 | **CAI** sur 7 scénarios (1 run/scénario) | 3 j | Concurrent canonique 2025 — incontournable |
| 3 | **PentestGPT** sur 7 scénarios (1 run/scénario) | 2 j | Référence USENIX'24 historique |
| 4 | **Ablation w/o Phase 1 (graph)** sur 7 scénarios | 1 j | Prouve le claim "graph-guided" |
| 5 | **Ablation w/o Phase 5 (intrusion)** sur 7 scénarios | 1 j | Prouve la valeur du multi-hop |

**Total : ~8 jours** de travail expérimental + la mesure (calculer R/P/F1/Score/MHR pour tous).

### Bonus (si temps)
| Item | Effort | Value |
|---|---|---|
| NetExec credential spraying baseline | 2 j | Couvre la catégorie "framework traditionnel auto-pilotable" |
| Nuclei templates IoT | 1 j | Renforce la baseline scanner |
| VulnBot adapté | 3-4 j | Comparaison structurelle (multi-agent vs multi-agent) |
| 3 autres ablations (P3a, P4, RAG) | 3 j | Renforce la pile d'ablations |

### À ne PAS faire (perte de temps)
- OpenVAS — lourd, gain marginal sur Nmap NSE + Nuclei
- Metasploit auto — déprécié, pas de comparaison défendable
- AutoPentester / xOffense / CurriculumPT — pas de code public clair
- BloodHound — AD-only, inutilisable

---

## 7. Sur les outils traditionnels — la phrase à mettre dans le papier

Section §2.5 ou §7.2 :

> *"Traditional network pentest frameworks like Metasploit, Cobalt Strike, and the BloodHound + CrackMapExec combo demonstrate multi-host attack capability but rely on a human operator to drive the workflow. They are the lineage from which autonomous LLM agents take inspiration, not a comparable autonomous baseline. We benchmark instead against (i) autonomous network scanners (Nmap NSE, Nuclei), (ii) auto-pilotable frameworks (NetExec credential spraying), and (iii) state-of-the-art LLM agents (CAI, PentestGPT, VulnBot). Our pipeline aims to automate decisions that traditional frameworks delegate to the operator while raising the depth of evidence beyond what scanners can produce."*

C'est le paragraphe-bouclier anti-reviewer. Ne pas l'oublier.

---

## 8. TL;DR pour décider maintenant

**3 catégories, 5 outils à tester, ~8 jours d'effort expérimental :**

1. **Scanner non-LLM** : Nmap NSE (1 j)
2. **LLM agents canoniques** : CAI (3 j) + PentestGPT (2 j)
3. **Ablations internes** : Phase 1 off (1 j) + Phase 5 off (1 j)

Si tu valides cette liste, on commence par **Nmap NSE** (le plus rapide à mettre en place, débloque l'évaluateur sur un format de baseline) puis on enchaîne CAI.
