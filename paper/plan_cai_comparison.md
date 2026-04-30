# Plan d'implémentation — Comparaison baselines LLM vs notre pipeline (ACSAC 2026)

> Document opérationnel. Complète `paper/plan.md` (chantier C), `paper/baselines.md` (§4) et `paper/integration_cai.md` (architecture v2). Ne duplique pas — se concentre sur l'**ordonnancement chronologique exécutable**, le **gate pilote**, et les **commandes concrètes**.
>
> **Date de référence :** 29 avril 2026 — **Deadline :** 26 mai 2026 (27 j)
> **Baselines LLM lockées :** CAI + PentestGPT + VulnBot (mises à jour 2026-04-29)
> **Effort total :** 5–6 j calendrier (~4 j homme + ~2 j calcul)
> **Coût LLM estimé :** $0 (MiniMax Coding Plan, cf. `plan.md` F0)

---

## 1. Vue d'ensemble et positionnement

Cette comparaison fournit la **table headline §7.1** du papier :

| Système | F1 / Score | MHR_1/2/3 | Crown jewel |
|---|---|---|---|
| Notre pipeline complet | à mesurer | à mesurer | yes/no |
| Notre pipeline w/o Phase 1 (ablation graph) | à mesurer | à mesurer | yes/no |
| Notre pipeline w/o Phase 5 (ablation multi-hop) | à mesurer | à mesurer | **0** attendu |
| CAI Variante A1 (per-IP) | à mesurer | MHR_2 ≈ 0 | no |
| CAI Variante B (CIDR) | à mesurer | à mesurer | likely no |
| **VulnBot** (multi-agent + task-PTG) | à mesurer | à mesurer | likely no |
| PentestGPT (single-agent) | à mesurer | MHR_2 ≈ 0 | no |
| Nmap NSE (non-LLM) | à mesurer | MHR_2 = 0 | no |

**Contraintes de fairness verrouillées (cf. `integration_cai.md` §5) :**
- LLM unique : `MiniMax-M2.7` des deux côtés.
- Budget de turns identique : ~200 turns/scénario.
- Même contrat d'entrée : CIDR + liste d'IPs.
- Même évaluateur : `src/benchmark/evaluator.py` (avec MHR ajouté).

**Variantes testées (cf. `integration_cai.md` §4) :**
- **CAI A (primaire)** : per-IP, CAI relancé pour chaque IP de la GT.
- **CAI B (fairness)** : 1 session CAI sur tout le CIDR.
- **PentestGPT** : per-IP autonome (analogue à CAI A).
- **VulnBot** : per-IP avec son PTG (analogue à CAI A, mais avec ordonnancement task-graph).
- (A2 CAI multi-agent `offsec_pattern` reporté en optionnel — cf. §8 plan de repli.)

**Argument scientifique de chaque baseline :**
- CAI A → "single-host architecture appliquée N fois → pas de pivot"
- CAI B → "même avec CIDR scope, pas de structure multi-hop dédiée"
- PentestGPT → "single-agent ne suffit pas"
- VulnBot → **"multi-agent + graph ne suffit pas si le graph est task-graph et pas infrastructure-graph"** (le contraste le plus précis)

---

## 2. Phases chronologiques

### Phase 0 — Pré-requis infra (0.25 j) — **bloquante**

| # | Tâche | Fichier / commande | Risque |
|---|---|---|---|
| P0.1 | Vérifier Python 3.12 sur LXC 200 (`nato-master`) | `ssh nato-master 'python3.12 --version'` | Si absent → `apt install python3.12 python3.12-venv` (Debian 12 : via deadsnakes ou source) |
| P0.2 | Confirmer route `192.168.100.0/24` depuis master | `ssh nato-master 'ip route get 192.168.100.11'` | Déjà OK selon CLAUDE.md |
| P0.3 | Vérifier `MINIMAX_API_KEY` dans `group_vars/all/vault_master.yml` | `ansible-vault view ...` | Déjà OK (subscription active) |

**Livrable :** snapshot env confirmé dans `paper/notes/p0_env.txt`.

### Phase 1 — Évaluateur MHR (0.5 j) — **bloquante pour pilote**

> Recouvre `plan.md` chantier A2/A3. À faire **avant** tout run CAI.

| # | Action | Fichier | Détail |
|---|---|---|---|
| P1.1 | Ajouter champs MHR au dataclass | `src/benchmark/evaluator.py` (`EvaluationResult`) | `mhr_1: float`, `mhr_2: float`, `mhr_3: float` (Optional[float], None si pas de GT à cette profondeur) |
| P1.2 | Implémenter `compute_mhr(matches, ground_truth, k)` | `src/benchmark/evaluator.py` | Numérateur = TPs avec `hop_depth >= k` ; dénominateur = GT entries `hop_depth >= k` ; renvoie `None` si dénominateur = 0 |
| P1.3 | Câbler dans `evaluate()` | `src/benchmark/evaluator.py` | Calculer MHR_1/2/3, sérialiser dans `evaluator_score.json` |
| P1.4 | Tests unitaires | `tests/test_evaluator.py` (étendre) | Cas : (a) GT plat → MHR_2/3 = None ; (b) GT à 3 niveaux, matches partiels ; (c) un match ambigu côté CVE et profondeur |
| P1.5 | Exposer MHR dans la route API | `src/api/routes/runs.py` (`/api/runs/{id}/score`) | Champ déjà sérialisé via `asdict` |

**Validation :** `python3 -m pytest tests/test_evaluator.py -v -p no:pytest_ethereum -p no:web3` tout vert.

### Phase 2 — Annotation `hop_depth` du ground truth (0.5 j) — **bloquante**

| # | Action | Fichier | Convention |
|---|---|---|---|
| P2.1 | Définir convention de profondeur | `paper/notes/hop_depth_convention.md` | `0` = directement joignable depuis l'attaquant ; `1` = derrière 1 firewall/segment/pivot ; `2+` = profondeur croissante. Pour scénario flat (S1/S2) → tous `0`. Scénario IT/OT (S3) → router 0, IT 1, OT 2. |
| P2.2 | Annoter 7 fichiers GT | `benchmarks/ground_truth/scenario_{1..7}.yaml` | ~50–60 entrées sur les 7 scénarios cibles (87 au total tous scénarios). Ajouter `hop_depth: N` à chaque vuln |
| P2.3 | Audit cohérence | Script ad-hoc dans `paper/notes/audit_hop.py` | Pour chaque GT, ressortir histogramme `hop_depth` ; cas suspects = scénario flat avec `>0` |

**Livrable :** `paper/notes/hop_depth_summary.md` avec table par scénario.

### Phase 3 — Ré-établir baseline interne avec MHR (0.5 j calcul)

| # | Action | Commande | Sortie attendue |
|---|---|---|---|
| P3.1 | Run pipeline complet sur scenario_3 | `python3 -m src.agent --scenario 3 --provider minimax --model MiniMax-M2.7` | `output/agent/<ts>/04_exploitation.json` + `evaluator_score.json` avec MHR |
| P3.2 | Run ablation P5 off | `python3 -m src.agent --scenario 3 --provider minimax --model MiniMax-M2.7 --phases 1 2 3 4 6` | idem ; doit montrer MHR_2/3 chuter |

**Validation :** MHR_2(complet) − MHR_2(P5off) > 0.20 → critère pilote pré-rempli.

### Phase 4 — Intégration baselines LLM : code (2 j) — **bloquante pour pilote**

#### 4.1 Création de l'arbre

```
scripts/baselines/
├── __init__.py
├── common/
│   ├── findings_schema.py     # Pydantic models partagés (Finding, ScenarioReport)
│   └── adapter_base.py        # classes parent réutilisées par chaque baseline
├── cai/
│   ├── cai_schema.py          # CAIReport (per-IP) + ScenarioReport (CIDR)
│   ├── run_cai.py             # CLI launcher (variantes A et B)
│   ├── cai_to_findings.py     # Pydantic → 04_exploitation.json
│   └── cai_jsonl_fallback.py
├── pentestgpt/
│   ├── run_pentestgpt.py      # CLI launcher per-IP
│   └── pentestgpt_to_findings.py
└── vulnbot/
    ├── run_vulnbot.py         # CLI launcher per-IP
    └── vulnbot_to_findings.py # parser de leur output (texte ou JSONL selon mode)
```

**Stratégie de réutilisation** : 80% du code commun entre les 3 baselines LLM (boucle sur IPs, retry MiniMax, sérialisation findings). Schema Pydantic identique (`Finding` partagé). Adapters spécifiques par outil pour parser leur sortie native.

#### 4.2 Spécifications par fichier

**`cai_schema.py`** — copier le bloc Pydantic de `integration_cai.md` §3 verbatim (`Finding`, `CAIReport`, `ScenarioReport`). Aligner `vuln_type` sur les types canoniques de `src/agent/vuln_taxonomy.py` (`CANONICAL_TYPES`) — sinon le matching évaluateur sera fragile.

**`run_cai.py`** — CLI avec args :
- `--variant {A,B}`
- `--scenario N`
- `--target IP` (variante A uniquement)
- `--scope CIDR`
- `--max-turns N` (default 200 pour B, 200/N_ips pour A)
- `--model MiniMax-M2.7`
- `--output-dir PATH`
- `--retries 3` (gestion 400 MiniMax)

Logique :
1. Charge GT du scénario, extrait CIDR.
2. Appelle `cai --continue --prompt "<target=IP, scope=CIDR>"` via subprocess avec `output_type=CAIReport` (Variante A) ou `ScenarioReport` (B).
3. Capture stdout/JSONL + sérialise le Pydantic en `<output-dir>/<ip|scenario>.json`.
4. Retry × 3 sur erreurs HTTP 400 (tool-calling MiniMax).
5. En cas d'échec output_type → fallback `cai_jsonl_fallback.py`.

**`cai_to_findings.py`** — adapter Pydantic → format évaluateur :
```python
{
  "tests": [
    {
      "vuln_id": "<auto>",
      "device_ip": finding.target_ip,
      "vuln_type": canonicalize(finding.vuln_type),
      "severity": finding.severity.upper(),
      "evidence": finding.evidence,
      "evidence_level": {"L1":1, "L2":2, "L3":3}[finding.evidence_level],
      "cve_ids": [finding.cve_id] if finding.cve_id else [],
      "status": "CONFIRMED" if finding.evidence_level != "L1" else "DETECTED"
    }
  ]
}
```

Réutilise `canonicalize()` de `src/agent/vuln_taxonomy.py` — point critique pour l'équité de matching.

#### 4.3 Structure de sortie

```
output/baselines/cai/<scenario>/<variant>/
├── raw/                       # JSONL bruts CAI + Pydantic sérialisés
│   ├── 192.168.100.11.json
│   └── ...
├── 04_exploitation.json       # format évaluateur
├── evaluator_score.json       # produit par evaluator.py
└── run_meta.json              # turns consommés, durée, retries, échecs
```

**Validation :** `python -m scripts.baselines.cai.run_cai --variant A --scenario 3 --target 192.168.100.11 --scope 192.168.100.0/24 --max-turns 40 --dry-run` doit afficher la commande CAI sans l'exécuter.

### Phase 5 — Pilote sur scenario_3 (1 j calcul, ~6h) — **GO/NO-GO**

> Aligné avec `integration_cai.md` §6.

6 configs à exécuter (1 run chacune sur scenario_3, le scénario IT/OT segmenté qui exige du multi-hop) :

```bash
# Config 1 — pipeline complet (référence)
python3 -m src.agent --scenario 3 --provider minimax --model MiniMax-M2.7

# Config 2 — pipeline sans P1 (ablation graph d'infrastructure)
python3 -m src.agent --scenario 3 --provider minimax --model MiniMax-M2.7 --phases 2 3 4 5 6

# Config 3 — pipeline sans P5 (ablation multi-hop)
python3 -m src.agent --scenario 3 --provider minimax --model MiniMax-M2.7 --phases 1 2 3 4 6

# Config 4 — CAI Variante A (per-IP)
for ip in $(yq '.vulnerabilities[].ip' benchmarks/ground_truth/scenario_3.yaml | sort -u); do
  python -m scripts.baselines.cai.run_cai \
    --variant A --scenario 3 --target $ip --scope 192.168.100.0/24 \
    --max-turns 40 --model MiniMax-M2.7 \
    --output-dir output/baselines/cai/scenario_3/A/
done
python -m scripts.baselines.cai.cai_to_findings output/baselines/cai/scenario_3/A/

# Config 5 — VulnBot per-IP
for ip in $(yq '.vulnerabilities[].ip' benchmarks/ground_truth/scenario_3.yaml | sort -u); do
  python -m scripts.baselines.vulnbot.run_vulnbot \
    --scenario 3 --target $ip --scope 192.168.100.0/24 \
    --max-steps 15 --model MiniMax-M2.7 \
    --output-dir output/baselines/vulnbot/scenario_3/
done
python -m scripts.baselines.vulnbot.vulnbot_to_findings output/baselines/vulnbot/scenario_3/

# Config 6 — PentestGPT per-IP
for ip in $(yq '.vulnerabilities[].ip' benchmarks/ground_truth/scenario_3.yaml | sort -u); do
  python -m scripts.baselines.pentestgpt.run_pentestgpt \
    --scenario 3 --target $ip --scope 192.168.100.0/24 \
    --max-iterations 50 --model MiniMax-M2.7 \
    --output-dir output/baselines/pentestgpt/scenario_3/
done
python -m scripts.baselines.pentestgpt.pentestgpt_to_findings output/baselines/pentestgpt/scenario_3/

# Évaluation des 6 configs
for config in agent baselines/cai/scenario_3/A baselines/vulnbot/scenario_3 baselines/pentestgpt/scenario_3; do
  python -m src.benchmark.evaluator \
    --run-dir output/$config \
    --ground-truth benchmarks/ground_truth/scenario_3.yaml
done
```

**Critères GO (les 5 doivent être vrais) :**

| # | Critère | Seuil | Action si KO |
|---|---|---|---|
| G1 | F1(notre complet) − F1(CAI A) | > 0.10 | Investiguer matching évaluateur (canonicalize, severity normalisation) |
| G2 | MHR_2(complet) − MHR_2(P5off) | > 0.20 | Vérifier annotation `hop_depth` scenario_3 |
| G3 | MHR_2(CAI A) ET MHR_2(VulnBot) ET MHR_2(PentestGPT) | < 0.10 chacun | Confirmer architecture (per-IP = pas de pivot) — résultat attendu |
| G4 | F1(notre complet) − F1(VulnBot) | > 0.05 | **Critère sensible** : VulnBot est le concurrent le plus proche. Si gap < 0.05, retravailler la narrative *"infra-graph vs task-graph"* ; si VulnBot bat notre pipeline, blocker rouge |
| G5 | Schéma Pydantic correctement rempli | 100% des runs (3 outils) | Activer fallbacks parsing texte (+1 j) |

**Livrable pilote :** `paper/notes/pilot_scenario_3.md` avec les 4 `evaluator_score.json` et décision GO/NO-GO horodatée.

### Phase 6 — Campagne complète (1.5 j calcul)

Si GO :

#### 6.1 Variante A sur 7 scénarios

```bash
for s in 1 2 3 4 5 6 7; do
  cidr=$(yq '.network_cidr // "192.168.100.0/24"' benchmarks/ground_truth/scenario_${s}.yaml)
  for ip in $(yq '.vulnerabilities[].ip' benchmarks/ground_truth/scenario_${s}.yaml | sort -u); do
    python -m scripts.baselines.cai.run_cai \
      --variant A --scenario $s --target $ip --scope $cidr \
      --max-turns 40 --model MiniMax-M2.7 \
      --output-dir output/baselines/cai/scenario_${s}/A/
  done
  python -m scripts.baselines.cai.cai_to_findings output/baselines/cai/scenario_${s}/A/
  python -m src.benchmark.evaluator \
    --run-dir output/baselines/cai/scenario_${s}/A \
    --ground-truth benchmarks/ground_truth/scenario_${s}.yaml \
    --output output/baselines/cai/scenario_${s}/A/evaluator_score.json
done
```

Effort calcul attendu : 7 × ~5 IPs × ~10 min (MiniMax rapide) ≈ 6h en série, ~2h en parallèle (3 jobs).

#### 6.2 Variante B sur 7 scénarios

```bash
for s in 1 2 3 4 5 6 7; do
  cidr=$(yq '.network_cidr // "192.168.100.0/24"' benchmarks/ground_truth/scenario_${s}.yaml)
  python -m scripts.baselines.cai.run_cai \
    --variant B --scenario $s --scope $cidr \
    --max-turns 200 --model MiniMax-M2.7 \
    --output-dir output/baselines/cai/scenario_${s}/B/
  python -m scripts.baselines.cai.cai_to_findings output/baselines/cai/scenario_${s}/B/
  python -m src.benchmark.evaluator \
    --run-dir output/baselines/cai/scenario_${s}/B \
    --ground-truth benchmarks/ground_truth/scenario_${s}.yaml \
    --output output/baselines/cai/scenario_${s}/B/evaluator_score.json
done
```

Effort : 7 × ~30 min ≈ 4h.

#### 6.3 Re-runs notre pipeline (déjà couvert dans `plan.md` B3)

À synchroniser : utiliser le **même** scénario × même horodatage de GT que les runs CAI (sinon mismatch annotations).

### Phase 7 — Agrégation et table headline (0.5 j)

```
scripts/baselines/cai/aggregate.py    # collecte tous les evaluator_score.json
                                       # → output/baselines/cai/aggregate.csv
                                       # → paper/tables/tab_cai_comparison.tex
```

Colonnes du CSV : `scenario, system, variant, recall, precision, f1, weighted_score, mhr_1, mhr_2, mhr_3, crown_jewel_reached, n_turns, n_retries`.

**Livrable :** `paper/tables/tab_cai_comparison.tex` (LaTeX prêt-à-include dans §7.1).

---

## 3. Dépendances entre phases

```
P0 (env) ──┐
           ├──> P1 (MHR evaluator) ──┐
           │                         ├──> P3 (re-baseline interne)
P2 (hop_depth GT) ───────────────────┤
                                     │
P4 (code CAI) ───────────────────────┴──> P5 (pilote scenario_3) ──[GO]──> P6 (campagne)
                                                                     │
                                                                     └──[NO-GO]──> §8 repli
                                                                            │
                                                                            P7 (agrégat) ──> table §7.1
```

**Chemin critique :** P0 → P1 → P2 → P4 → P5 → P6 → P7 ≈ **4 jours homme + 1.5 j calcul**.

---

## 4. Effort résumé

| Phase | Effort homme | Calcul | Calendrier |
|---|---|---|---|
| P0 | 0.25 j | — | J0 |
| P1 | 0.5 j | — | J0–J1 |
| P2 | 0.5 j | — | J1 |
| P3 | 0.1 j | 0.25 j | J1 |
| P4 | 1.0 j | — | J2 |
| P5 (pilote) | 0.25 j | 0.5 j | J3 |
| **Gate GO/NO-GO** | — | — | **fin J3** |
| P6 | 0.25 j | 1.5 j | J4–J5 |
| P7 | 0.5 j | — | J5 |
| **Total** | **~3.3 j** | **~2.25 j** | **5–6 j calendrier** |

Synchronise avec `plan.md` Semaine 2 (chantier C). Pilote = J3 = fin de S1 / début S2 paper-wide.

---

## 5. Registre des risques

| # | Risque | Probabilité | Impact | Mitigation |
|---|---|---|---|---|
| R1 | MiniMax 400 sur tool-calling (cf. provider.py) | Moyenne | Run CAI échoue | Retry × 3 dans `run_cai.py` ; documenter taux d'échec dans `run_meta.json` (donnée utile en soi) |
| R2 | CAI ignore `output_type` Pydantic | Moyenne | Pas de findings structurés | Fallback `cai_jsonl_fallback.py` (+0.5 j budgété) |
| R3 | Variante B fait du multi-hop ad-hoc | Faible-moyenne | Narrative §7 fragilisée | Pivoter vers narrative *"unstructured ad-hoc vs structured Phase 5 reproducible"* (cf. `integration_cai.md` §8.4) ; ajouter métrique reproductibilité de chaîne |
| R4 | Master VM sans Python 3.12 | Faible | Bloque P0 | `apt install python3.12-venv` ou env Conda dédié pour CAI uniquement |
| R5 | Annotation `hop_depth` subjective | Moyenne | Réviseur conteste MHR | Documenter convention dans `paper/notes/hop_depth_convention.md` ; baser sur règles ACL Ansible objectives |
| R6 | CAI consomme >>200 turns (Variante B) | Faible | Budget exploded en temps | Cap dur `--max-turns 200` ; arrêt si dépassé |
| R7 | Vuln types CAI ≠ taxonomie nôtre | Élevée | Faux négatifs au matching | Forcer `vuln_type` enum dans Pydantic schema (ajuster `cai_schema.py` à `CANONICAL_TYPES`) |
| R8 | GT nouvellement annoté incohérent (S2 a 4 IPs flat, S3 segmenté) | Moyenne | MHR difficile à interpréter | P2.3 audit + résumé histogramme |
| R9 | Pilote NO-GO (G1 ou G2 KO) | Faible | Reporter de 1–2 j | §8 plan de repli ; basculer A2 multi-agent |

---

## 6. Pilote — porte de décision (résumé)

**Date cible :** fin J3 (≈ 2 mai 2026, fin S1 paper).
**Coût :** $0 (MiniMax sub).
**Durée d'exécution :** ~4h CPU.
**Décision documentée dans :** `paper/notes/pilot_scenario_3.md`.

| Issue | Action |
|---|---|
| 4/4 critères verts | GO campagne complète Variante A + B (J4–J5) |
| G1 ou G3 KO mais G2/G4 OK | Investigation 0.5 j (matching, taxonomie) puis re-pilote |
| G2 KO | Bug dans annotation `hop_depth` ou compute_mhr → revoir P1/P2 |
| G4 KO | Activer fallback JSONL (+0.5 j) puis re-pilote |
| Variante B fait trop bien | Documenter ; renforcer narrative reproductibilité (§7.4 papier) ; ajouter A2 sur 7 scénarios |
| Échec total CAI install | Repli sur PentestGPT (cf. `plan.md` C5/C6) |

---

## 7. Livrables par phase

| Phase | Livrables |
|---|---|
| P0 | `paper/notes/p0_env.txt` |
| P1 | `src/benchmark/evaluator.py` (MHR), `tests/test_evaluator.py` (étendu) |
| P2 | 7 fichiers GT annotés, `paper/notes/hop_depth_summary.md` |
| P3 | 2 runs internes scenario_3 (complet + P5off) avec `evaluator_score.json` MHR |
| P4 | `scripts/baselines/cai/{__init__,cai_schema,run_cai,cai_to_findings,cai_jsonl_fallback}.py` |
| P5 | 4 runs scenario_3, `paper/notes/pilot_scenario_3.md`, décision GO/NO-GO |
| P6 | 14 runs CAI (7 scénarios × 2 variantes), `output/baselines/cai/**/evaluator_score.json` |
| P7 | `output/baselines/cai/aggregate.csv`, `paper/tables/tab_cai_comparison.tex` |

---

## 8. Plan de repli détaillé

Cf. `integration_cai.md` §8 pour les 5 scénarios d'échec (install plante, output_type ignoré, B ne pivote pas, B trop bien, baselines KO).

**Coupes en cas de retard (priorisées) :**

1. Sacrifier Variante A2 multi-agent (déjà optionnelle).
2. Réduire à 5 scénarios sur 7 (garder S1 flat, S3 IT/OT, S5 hub-star, S6, S7).
3. Variante B uniquement sur 3 scénarios représentatifs (S1, S3, S5).
4. Renoncer aux retries × 3 → documenter comme limite.

**À ne JAMAIS sacrifier :**
- L'évaluateur MHR (P1) — base de toutes les autres lignes.
- Le pilote scenario_3 — sans lui, pas de gate.
- Au moins Variante A sur les 7 scénarios — c'est la table headline.

---

## 9. Fichiers de référence

- `paper/plan.md` — calendrier global du papier (chantier C ≡ ce plan)
- `paper/baselines.md` — justification du choix CAI (§4)
- `paper/integration_cai.md` — architecture v2, schéma Pydantic, variantes
- `src/benchmark/evaluator.py` — évaluateur à étendre (P1)
- `src/agent/vuln_taxonomy.py` — taxonomie partagée (verrou matching)
- `benchmarks/ground_truth/scenario_*.yaml` — GT à annoter (P2)

---

## 10. Action immédiate (J0)

1. **P0.1** — `ssh nato-master 'python3.12 --version'` (5 min)
2. **P1.1** — ouvrir `src/benchmark/evaluator.py`, ajouter champs `mhr_*` au dataclass `EvaluationResult` (15 min)
3. **P2.1** — fixer la convention `hop_depth` dans `paper/notes/hop_depth_convention.md` (15 min)

P0, P1 et P2 peuvent démarrer **en parallèle** — aucune dépendance entre eux.
