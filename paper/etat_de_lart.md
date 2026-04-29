# Rapport — État de l'art et méthodologie d'évaluation
## Pour la soumission ACSAC 2026 — *IoTBench (benchmark) + harness (TBD name)*

> Document de travail (français) accompagnant `paper/sections/02_related_work.tex`
> et `paper/sections/07_evaluation.tex`. Objectif : (i) consolider la connaissance
> des travaux concurrents, (ii) durcir notre positionnement, (iii) verrouiller
> une méthodologie d'évaluation qui rend la comparaison **lisible, défendable
> et reproductible** pour les reviewers ACSAC.

---

## 1. Cartographie de la littérature

On peut regrouper les travaux pertinents en **quatre clusters**. Les trois
premiers concernent les agents LLM-pentest ; le quatrième les benchmarks et
infrastructures de lab. Chaque cluster fait apparaître un *trou* que IoTBench
prétend combler.

### 1.1. Cluster A — Agents LLM mono-hôte (origine du domaine)

| Système | Année / Venue | Idée centrale | Cible d'évaluation | Limite pour nous |
|---|---|---|---|---|
| **PentestGPT** [Deng+'24, USENIX Sec] | 2024 | Premier agent LLM avec interface human-in-the-loop ; trois sous-modules (Reasoning / Generation / Parsing) | 13 machines HackTheBox, 7 VulnHub, 182 sous-tâches | Mono-hôte, web/OS uniquement, pas de protocoles IoT. |
| **VulnBot** [arXiv:2501.13411] | 2025 | Décomposition multi-agents en 3 phases (recon / scan / exploit) coordonnées par un *Penetration Task Graph* (PTG) | AUTOPENBENCH | Idée du PTG intéressante, mais le graphe est sur les *tâches*, pas sur l'*infrastructure*. |
| **AutoPentester** [arXiv:2510.05605] | 2025 | 5 agents (summarizer, strategy, command-gen, verifier, reporter) + RAG + Pentest Tree | HackTheBox + custom OWASP | Ne couvre que web/OS classique. |
| **PentestAgent** [AsiaCCS'25] | 2025 | Pipeline multi-étapes avec RAG | Custom | Pas IoT, pas réseau. |
| **xOffense** [arXiv:2509.13021] | 2025 | Fine-tuning Qwen3-32B sur corpus offensif | CTF (79% sub-task) | Ne s'attaque qu'à des cibles isolées. |
| **Pentest-R1** [arXiv:2508.07382] | 2025 | RL en deux étapes sur traces de raisonnement | AUTOPENBENCH | Idem. |

**Constat :** ce cluster est très actif (≥6 papiers en 12 mois) mais
**tous évaluent sur un hôte isolé** — la sortie est soit la capture d'un flag,
soit un taux de complétion de sous-tâches. Aucun ne raisonne à l'échelle d'une
plage IP /24 hétérogène.

### 1.2. Cluster B — Agents LLM long-running, mémoire, planning

| Système | Année | Apport | Pourquoi c'est utile à connaître |
|---|---|---|---|
| **CHAP** [NDSS LAST-X'26] | 2026 | *Context relay* : transférer un protocole distillé entre instances successives d'agents pour des engagements longs | Notre Phase 5 (intrusion) a justement le problème de fenêtre de contexte saturée — on peut citer CHAP comme état de l'art du *long-running pentest*. |
| **AWE** [NDSS LAST-X'26] | 2026 | Mémoire persistante + vérification *browser-backed* pour pentest web | Reconnaît la même limite que nous (vérification ≠ hallucination) mais sur le web. |
| **CheckMate** [arXiv:2512.11143] | 2025 | LLM **+ planning classique** (PDDL-like) → sélection d'actions déterministe, +20 pts vs baseline | Baseline forte à mentionner ; notre graphe joue un rôle similaire (guider la sélection). |

**À exploiter dans le papier :** ces travaux *reconnaissent* la limite des
agents purement reactives. Notre graphe d'infrastructure + taxonomie de
vulnérabilités joue un rôle équivalent à leur planner / mémoire, mais ancré
sur la **topologie** plutôt que sur le langage.

### 1.3. Cluster C — Frameworks "production"

| Système | Année | Particularité |
|---|---|---|
| **CAI** [arXiv:2504.06017] | 2025 | Auteurs PentestGPT → framework bug-bounty open-source, modulaire, leaderboard public. |
| **PentAGI** | 2024-25 | Framework open-source orienté entreprise, peu de littérature académique. |

CAI nous concerne particulièrement parce que c'est le framework de référence
à adapter en *baseline* pour la comparaison "agents LLM mono-hôte adaptés à
une cible réseau" (cf. §3.2 ci-dessous).

### 1.4. Cluster D — Benchmarks et infrastructures de lab

| Ressource | Type | Verrou levé | Ce qui manque pour nous |
|---|---|---|---|
| **AUTOPENBENCH** [arXiv:2410.17141] | Benchmark VulnHub-derived, scripted flag checkers | Référence académique partagée par VulnBot, Pentest-R1 | Mono-hôte, web/OS, pas de réseau, pas de protocoles IoT. |
| **CAIBench / RCTF2** [arXiv:2510.24317] | Méta-benchmark : Jeopardy CTF + attack/defense + cyber-range + privacy | **Premier benchmark à inclure 27 défis CPS/robotics** | Chaque défi reste un CTF isolé, pas un réseau déployé. |
| **HackTheBox / VulnHub** | Catalogue communautaire | Très utilisé, signal connu | Pas de ground truth lisible par machine ; reproductibilité aléatoire. |
| **Ludus** [ludus.cloud] | Cyber-range Proxmox + Ansible | Méthodologie *idempotente* identique à la nôtre | Outil d'entraînement humain, pas d'évaluation LLM publiée, pas de ground truth machine-readable. |
| **GOAD** (Game Of Active Directory) | Lab AD pré-câblé | Multi-hôte, scénarios réalistes | AD-only, no IoT, pas de ground truth pour scoring auto. |

**Synthèse cluster D :** AUTOPENBENCH = benchmark dominant côté agents LLM ;
Ludus/GOAD = lab dominant côté humains. **Personne ne croise les deux pour
l'IoT/CPS à l'échelle d'un /24.**

---

## 2. Le *gap* — résumé en une page

```
                Évalué sur                 Évalué sur réseau
                hôte isolé                 multi-device

Sans IoT     ┌───────────────────────┐   ┌──────────────────────┐
             │ PentestGPT, VulnBot,  │   │ Ludus, GOAD          │
             │ AutoPentester,        │   │ (training only,      │
             │ PentestAgent,         │   │  no LLM eval,        │
             │ Pentest-R1, xOffense, │   │  no GT YAML)         │
             │ CAI, CheckMate, CHAP, │   │                      │
             │ AWE                   │   │                      │
             └───────────────────────┘   └──────────────────────┘

Avec IoT     ┌───────────────────────┐   ┌──────────────────────┐
             │ CAIBench/RCTF2        │   │  ★ IoTBench (nous)   │
             │ (27 CPS challenges,   │   │                      │
             │  isolated CTF style)  │   │                      │
             └───────────────────────┘   └──────────────────────┘
```

**Notre positionnement = quadrant bas-droite.** À l'intersection de quatre
contraintes simultanées :

1. **Network-scale** — un /24 multi-device, pas un host.
2. **Protocoles IoT/OT** — MQTT, Modbus, LoRaWAN, CoAP, en plus de SSH/HTTP.
3. **Ground truth machine-readable par vulnérabilité** — YAML annoté
   OWASP-IoT + MITRE ATT&CK ICS.
4. **Granularité d'évidence** au-delà du flag binaire — niveaux L1 (détection),
   L2 (exploitation), L3 (exfiltration).

Aucun travail publié ne combine les 4. **C'est notre titre de propriété.**

---

## 3. Méthodologie d'évaluation : comment se comparer

C'est la partie la plus stratégique : comment construire des chiffres qui
**(a) prouvent le gap**, **(b) résistent au scrutin des reviewers**, et
**(c) ne dépendent pas que de nous-mêmes**.

### 3.1. Le triplet de baselines à reproduire

Il faut absolument **trois familles de baselines** sinon le reviewer dira
"vous comparez votre système à rien".

#### Baseline 1 — Scanners non-LLM (lower bound déterministe)
- **OpenVAS / Greenbone** — scanner CVE-driven, signatures.
- **Nmap NSE** — scripts (mqtt-subscribe, mqtt-info, modbus-discover, http-default-accounts, ssh-auth-methods, ssl-cert).
- **Nuclei** (templates IoT) si pertinent.

**Hypothèse à tester (RQ4)** : les scanners attrapent les CVE connues mais
manquent les *misconfigurations* (anonymous MQTT, root sans mot de passe,
default creds non-CVE). Notre Tableau 4 (catégories) montre que
**>60%** de la GT n'est PAS du `known_cve`, donc les scanners doivent
mécaniquement plafonner. C'est notre argument fort.

#### Baseline 2 — Agents LLM mono-hôte adaptés au réseau
- **CAI** (open-source, le plus simple à câbler).
- **VulnBot** (PTG, à reproduire si dispo).
- **PentestGPT** dans sa version "auto" si possible.

**Méthode d'adaptation** : on les lance avec comme cible **chaque IP de la
GT séparément**, puis on agrège. Cela leur **donne déjà l'information de
discovery** (cadeau qu'on ne se fait pas à nous-mêmes — *fair to them, hard
on us*). On reporte F1 et Score sur cet upper bound naïf.

**Hypothèse à tester (RQ4)** : même avec discovery offerte, les agents
mono-hôte perdent le **signal cross-device** (credentials réutilisés,
chemins de pivot, orchestration MQTT inter-équipements) → leur F1
**sous-performe** notre harness.

#### Baseline 3 — Ablations internes de notre pipeline
- **w/o graph context** : retirer Phase 1 (`graph_analysis`) et l'output
  qui descend en Phase 2/3.
- **w/o knowledge store** : retirer ChromaDB skills RAG.
- **w/o Phase 4 (exploitation)** : ne reporter que les findings Phase 3.
- **single-call (no agent loop)** : un seul appel LLM par device, pas de
  multi-turn.

**Hypothèse à tester (RQ2)** : chaque module contribue ; en particulier le
graphe contribue principalement sur les patterns **Gateway-centric** et
**Hub-star** où le pivot est imposé par le firewall.

### 3.2. Métriques — ce qu'on rapporte et pourquoi

Le pipeline expose déjà :

| Métrique | Définition | Justification |
|---|---|---|
| **Recall** | TP / (TP+FN) | Détection brute — comparable à toute la littérature. |
| **Precision** | TP / (TP+FP) | Mesure du bruit — critique vu que les LLMs hallucinent. |
| **F1** | Harmonique recall/precision | Métrique principale du tableau 1. |
| **Weighted Score** | Σ w(g)·match(g) / Σ w(g) avec w∈{4,3,2,1} | Pondère par criticité — un default-creds critique vaut plus qu'un missing-header. |
| **L1/L2/L3 coverage** | Fraction des TP qui atteignent l'évidence niveau k | **Notre métrique différenciante** — impossible sur HTB/AUTOPENBENCH. |
| **Coût (USD)** | Prix tokens prompt+completion via `cost_tracker` | Pareto coût/perf — argument pratique. |
| **Wall-clock** | Durée totale | Comparabilité opérationnelle. |

**À ajouter pour la robustesse statistique** (à vérifier sur `output/agent/`) :

- **Variance inter-runs** : 3 runs par (modèle × scénario), reporter
  l'écart-type sur F1 et Score. Sans ça, un reviewer ACSAC dira "single-run, garbage".
- **Significativité** : test de Mann-Whitney U entre notre harness et
  chaque baseline, par scénario. Mentionné en footnote du Tableau 2.
- **Bootstrap CI 95%** sur les agrégats (recall global, score global).

### 3.3. La grille de comparaison étendue

Reprendre la table 1 de `02_related_work.tex` mais ajouter trois colonnes
qui forcent le visuel :

| System | Scope | IoT proto | Pivot? | GT | Scoring | L1/L2/L3 | Reproducible | LLM-evaluable |
|---|---|---|---|---|---|---|---|---|
| PentestGPT | host | – | – | hand | sub-task | – | partial | yes |
| VulnBot | host | – | – | AUTOPENBENCH | task-graph | – | yes | yes |
| AutoPentester | host | – | – | HTB+custom | sub-task | – | yes | yes |
| Pentest-R1 | host | – | – | AUTOPENBENCH | sub-task | – | partial | yes |
| CAI | host | – | – | CAIBench | CTF | – | yes | yes |
| CAIBench/RCTF2 | host | mixed | – | yes | CTF | – | yes | yes |
| Ludus / GOAD | network | AD | yes | – | training | – | yes | **no** |
| **IoTBench (ours)** | **/24** | **MQTT/Modbus/LoRa/CoAP** | **yes (5 patterns)** | **YAML/vuln** | **L1/L2/L3 + weighted** | **yes** | **yes** | **yes** |

La colonne "LLM-evaluable" est la **subtilité** : Ludus/GOAD pourrait
techniquement nous battre sur "scope = network", mais il **n'a pas de
ground truth** ni de scoring — il ne peut pas être utilisé pour évaluer un
LLM. C'est ce qui rend l'union réseau+GT+IoT unique.

### 3.4. Plan de campagne expérimentale

Pour 7 scénarios (S1–S7 de `benchmarks/ground_truth/`), 5 modèles
(Claude Sonnet 4 / Gemini 2.5 / GPT-4.1 / DeepSeek-V3 / Qwen3 ou MiniMax),
3 runs : **105 runs LLM** + baselines = ~150 runs. Pour chaque run on dump :

```
output/agent/<ts>/
  03_vuln_analysis.json     # findings
  04_exploitation.json      # findings + L2/L3 evidence
  05_intrusion.json         # lateral movement
  06_report.md
  cost_summary.json         # tokens, USD
  evaluator_score.json      # generated post-hoc
```

Puis un script `scripts/aggregate_paper_metrics.py` produit :
- `tab_main.csv` (Tab. 2 RQ1)
- `tab_evidence.csv` (Tab. 3 RQ2)
- `fig_heatmap.pdf` (Fig. 5 — scénario × modèle)
- `fig_pareto.pdf` (Fig. 6 — coût vs Score)
- `fig_baselines.pdf` (Fig. 4 — RQ4)

### 3.5. Pièges à anticiper (reviewer-mode)

| Critique probable | Réponse à pré-câbler |
|---|---|
| "Vous testez sur *votre* benchmark, pas sur AUTOPENBENCH" | Ajouter une **section §7.X "Sanity check on AUTOPENBENCH"** : faire tourner notre harness sur 10–20 challenges AUTOPENBENCH pour montrer qu'il est compétitif (ou pas pire) — sinon on est accusés de overfit benchmark. |
| "La GT est subjective, c'est vous qui l'avez écrite" | (i) GT = vulnérabilités **injectées par Ansible** → existence prouvée par construction, (ii) catégories ancrées dans OWASP-IoT et MITRE ATT&CK ICS, (iii) évaluateur publie ses 4 passes de matching. |
| "L'évaluateur est trop laxiste / trop strict" | Reporter F1 sous **3 régimes de matching** : strict (CVE-only), normal (par défaut), lâche (severity-only). Montrer que le ranking des modèles est stable. |
| "Pourquoi pas Metasploit comme baseline ?" | MSF n'est pas autonome — il faut un pilote. Le pilote serait soit humain (hors comparaison) soit un agent LLM (=cluster A déjà couvert). On peut citer ça en footnote. |
| "Single-run results" | Variance + IC bootstrap (cf. §3.2). |
| "Résultats dépendant du provider LLM" | C'est *justement* ce qu'on étudie en RQ3 — 5 fournisseurs, 1 pipeline. |
| "LLM data contamination — les modèles ont vu OpenVAS reports en pré-training" | Les vulnérabilités sont **injectées** dans des VMs nouvellement provisionnées avec des IPs internes ; aucun output OpenVAS public ne peut correspondre. La GT n'est jamais publique avant la soumission. |

### 3.6. Tableau récapitulatif des Research Questions

| RQ | Question | Métriques | Tableau / Figure |
|---|---|---|---|
| **RQ1** | Quelle perf brute atteint chaque LLM sur IoTBench /24 ? | R, P, F1, Score, $USD | Tab. 2 + variance |
| **RQ2** | Quelle profondeur d'évidence (L1/L2/L3) ? | L1/L2/L3 coverage | Tab. 3 |
| **RQ3** | Quel pattern d'architecture casse les LLM ? | Score par scénario × modèle | Fig. 5 (heatmap) |
| **RQ4** | Notre harness bat-il les baselines ? | F1 vs scanners et LLM mono-hôte | Fig. 4 (bar chart) |
| **RQ5** *(suggéré)* | Chaque module du pipeline contribue-t-il ? | Ablations (graph / RAG / Phase 4) | Tab. 5 (à ajouter) |
| **RQ6** *(suggéré)* | Quelle est l'envelope coût/temps ? | Pareto USD vs Score | Fig. 6 |

---

## 4. Recommandations concrètes pour les 4 prochaines semaines

### 4.1. Verrouiller la position dans `02_related_work.tex`
- **OK** : la table 1 actuelle est solide, garder.
- **À ajouter** : un paragraphe explicite **"Why network scale matters"**
  citant CHAP/AWE comme reconnaissance du problème de mémoire long-running,
  positionnant notre graph d'infra comme analogue structurel.
- **À durcir** : le paragraphe sur Ludus/GOAD doit terminer par "they have
  not been used to evaluate LLM agents in the published literature" (déjà
  présent ✓).

### 4.2. Étoffer §7 (`07_evaluation.tex`)
1. Ajouter §7.0 *"Experimental protocol"* avec les 3 runs/cellule, IC95,
   Mann-Whitney.
2. Ajouter §7.7 *"AUTOPENBENCH sanity check"* (parade au reviewer).
3. Réordonner : RQ1 → RQ2 → RQ4 (baselines) → RQ3 (per-arch) → RQ5 (ablation)
   → RQ6 (cost). Le reviewer doit voir les **baselines tôt** pour être
   convaincu avant les analyses fines.

### 4.3. Nouveaux artefacts à produire
- [ ] Script de baselines : `scripts/run_baselines.py {openvas, nmap_nse, cai}`
- [ ] Script d'agrégation : `scripts/aggregate_paper_metrics.py`
- [ ] Figure 1 : 5 patterns side-by-side (TikZ ou OmniGraffle).
- [ ] Figure 4 : bar chart F1 baselines.
- [ ] Figure 5 : heatmap scenario × modèle.
- [ ] Figure 6 : Pareto coût/perf.
- [ ] Tableau 5 : ablations (à ajouter dans §7).

### 4.4. Citations à ajouter / vérifier dans `references.bib`
- ✅ Tous les papiers du cluster A présents.
- ⚠️ **PentAGI** absent — à ajouter (mentionné dans `target_conferences.md`).
- ⚠️ **Nuclei / Greenbone OpenVAS / Nmap NSE** — à ajouter comme
  références baselines.
- ⚠️ **Mayoral-Vilches et al.** — leur travail sur la robotique/CPS pré-CAI
  pourrait être cité pour montrer la lignée.
- ⚠️ Vérifier que les preprints arXiv ont leurs vraies refs (Anonymous est
  un placeholder dans `references.bib` pour `pentestr125`, `xoffense25`,
  `chap26`, `awe26`, `checkmate25`, `autopenbench24` — à corriger pour la
  camera-ready, OK pour double-blind submission).

---

## 5. TL;DR pour la conf

> **L'argument unique en une phrase :** *Tous les benchmarks LLM-pentest publiés
> évaluent un hôte à la fois ; aucun n'évalue à l'échelle d'un réseau IoT
> déployé avec ground-truth par vulnérabilité — IoTBench est le premier, et
> nous le démontrons sur 7 scénarios × 5 modèles × 3 runs avec L1/L2/L3 de
> profondeur d'évidence.*

> **L'argument méthodologique en une phrase :** *Notre comparaison croise
> 3 familles de baselines (scanners non-LLM, agents LLM mono-hôte adaptés,
> ablations internes), reportée avec variance et intervalle de confiance,
> et rejouée en sanity-check sur AUTOPENBENCH pour réfuter l'overfit.*

C'est ce qui doit ressortir de l'abstract et de la première figure.
