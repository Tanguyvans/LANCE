# Plan d'intégration CAI comme baseline (v2 — révisé après ultrathink)

> Document opérationnel pour brancher **CAI** (Alias Robotics) dans notre cadre d'évaluation.
> **Effort estimé v2 : 2-3 jours** (réduit grâce à `output_type` structuré).
> **Coût LLM estimé : $80-150** selon les variantes activées.

---

## 0. Pourquoi cette v2

La v1 reposait sur un *parsing JSONL post-hoc* fragile et sur **une seule variante de test**. Après réflexion :
- CAI expose un mécanisme `output_type` (Pydantic) pour des sorties structurées natives → on n'a plus besoin de parser le JSONL.
- Une seule variante (per-IP) est attaquable par un reviewer (*"vous avez crippled CAI"*) ; il en faut deux.
- Le budget de turns et la stratégie de discovery doivent être verrouillés explicitement.
- Un **pilote sur 1 scénario** doit précéder la campagne complète pour dérisquer.

---

## 1. Ce qu'est CAI (résumé technique)

| Aspect | Détail |
|---|---|
| **Type** | Framework agent CLI Python autonome |
| **Distribution** | Package PyPI `cai-framework` (édition recherche gratuite) |
| **Python requis** | 3.12 |
| **CLI** | Commande `cai` après install |
| **Mode autonome** | `cai --continue --prompt "..."` |
| **Configuration** | `.env` (clés LLM via LiteLLM, multi-provider) |
| **Outils intégrés** | `nmap_scan`, `http_get`, `LinuxCmd`, `Code`, `SSHTunnel`, `WebSearch` |
| **Agents disponibles** | `bug_bounter_agent`, `redteam_agent`, `dfir_agent` |
| **Patterns multi-agent** | `offsec_pattern` (redteam + bug_bounter en parallèle) |
| **Sorties** | JSONL log (logs/cai_*.jsonl) **+** sortie structurée Pydantic via `output_type` |
| **Repository** | https://github.com/aliasrobotics/cai |

---

## 2. Architecture d'intégration v2

```
┌─────────────────────────────────────────────────────────────┐
│  Pydantic Schema (output unifié)                            │
│  CAIReport { target_ip, findings: List[Finding], summary }  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  scripts/baselines/run_cai.py                               │
│                                                             │
│  Mode A — per-IP (Variante A1 mono-agent, A2 offsec_pattern)│
│    for ip in scenario.gt_ips:                               │
│      cai.run(target=ip, scope=cidr, output_type=CAIReport)  │
│                                                             │
│  Mode B — session unique sur tout le réseau                 │
│    cai.run(scope=cidr, output_type=ScenarioReport)          │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
              output/baselines/cai/{scenario}/{variante}/
                         │
                         ▼
              Adaptateur findings → schema unifié évaluateur
                         │
                         ▼
              src/benchmark/evaluator.py
                         │
                         ▼
              R / P / F1 / Score / MHR / L1L2L3
```

---

## 3. Le schéma Pydantic forcé sur CAI

C'est le levier qui simplifie tout. Au lieu de parser le log post-hoc, on **force CAI à produire directement** un objet structuré que l'évaluateur sait lire.

```python
# scripts/baselines/cai_schema.py

from pydantic import BaseModel, Field
from typing import Literal, List, Optional

class Finding(BaseModel):
    vuln_type: str = Field(
        description="Vulnerability type: default_credentials, no_authentication, "
                    "known_cve, misconfiguration, info_disclosure, weak_crypto, "
                    "data_exposure, code_injection, privilege_escalation"
    )
    severity: Literal["critical", "high", "medium", "low", "info"]
    target_ip: str
    target_port: Optional[int] = None
    target_service: Optional[str] = None  # ssh, http, mqtt, modbus, ...
    evidence: str = Field(description="Raw output proving the finding (≤500 chars)")
    cve_id: Optional[str] = None
    evidence_level: Literal["L1", "L2", "L3"] = Field(
        description="L1=detected (banner/port), L2=exploited (auth ok), "
                    "L3=exfiltrated (sensitive content retrieved)"
    )

class CAIReport(BaseModel):
    """Per-IP report — used in Variante A (per-IP runs)."""
    target_ip: str
    scope: str  # CIDR
    findings: List[Finding]
    summary: str = Field(description="One-paragraph summary of session")
    duration_turns: int

class ScenarioReport(BaseModel):
    """Whole-network report — used in Variante B (one session)."""
    scope: str  # CIDR
    discovered_ips: List[str]
    findings: List[Finding]  # findings span all IPs
    pivot_chains: List[List[str]] = Field(
        default_factory=list,
        description="Multi-hop chains: list of ordered IP sequences from entry to deepest"
    )
    summary: str
    duration_turns: int
```

---

## 4. Les variantes de test (et pourquoi chacune)

### Variante A1 — CAI mono-agent, per-IP, no shared state ⭐ (principale)
- Pour chaque IP de la GT, lancer CAI avec target=IP, scope=CIDR
- Pas de partage d'état entre IPs (sessions indépendantes)
- **But :** mesurer la limite architecturale "single-host design appliqué N fois"
- **Hypothèse :** MHR₁ raisonnable, MHR₂/MHR₃ ≈ 0 par construction

### Variante A2 — CAI offsec_pattern (multi-agent), per-IP
- Idem A1 mais avec le pattern multi-agent recommandé par CAI (redteam + bug_bounter)
- **But :** parer la critique *"vous avez utilisé CAI en mode dégradé mono-agent"*
- **Coût :** ~2× A1 (deux agents tournent par IP)

### Variante B — CAI session unique sur le réseau entier
- **Une** session CAI avec target=CIDR
- L'agent fait sa propre discovery, partage du state nativement via sa mémoire
- **But :** test de fairness ultime — donner toutes les chances à CAI de faire du multi-hop ad-hoc grâce à ses primitives `LinuxCmd` + `nmap_scan`
- **Hypothèse principale :** échoue quand même parce que pas de structure Phase 5
- **Hypothèse alternative (à anticiper) :** CAI réussit partiellement → narrative pivot vers *"unstructured ad-hoc multi-hop vs structured Phase 5"*

### Stratégie d'échantillonnage
| Variante | Couverture | Justification |
|---|---|---|
| A1 | 7 scénarios × 1 run | Donnée principale du tableau |
| A2 | 3 scénarios représentatifs × 1 run | Robustesse — on s'attend à des résultats similaires à A1 |
| B  | 7 scénarios × 1 run | Donnée critique pour défendre la fairness |

---

## 5. Les contrats à verrouiller

### Contrat de budget (turns)
| Système | Budget total / scénario | Per-IP |
|---|---|---|
| Notre pipeline complet | ~200 turns (P1=10, P2=20, P3=20×N, P4=15×V, P5=80, P6=10) | n/a |
| CAI Variante A1 (per-IP) | ~200 turns total | 200 / N_IPs |
| CAI Variante A2 (multi-agent) | ~200 turns total | 200 / N_IPs |
| CAI Variante B (session unique) | ~200 turns total | n/a |

**Implémentation :** chaque appel CAI passe `--max-turns <budget>` (ou config équivalente).

### Contrat de discovery
| Variante | Notre pipeline reçoit | CAI reçoit |
|---|---|---|
| Per-IP (A1, A2) | CIDR + liste IPs (mode discovery désactivé) | CIDR + liste IPs |
| Session unique (B) | CIDR seulement (mode discovery activé Phase 2) | CIDR seulement |

→ Symétrie totale d'information.

### Contrat de modèle LLM — VERROUILLÉ
- **MiniMax-M2.7 partout** (notre pipeline + CAI + PentestGPT + toutes les ablations + tous les scénarios)
- Justification :
  1. **Fairness incontestable** : modèle identique des deux côtés isole l'architecture
  2. **Coût $0** grâce au MiniMax Coding Plan subscription
  3. **Support natif** : LiteLLM (Day 0 sur M2.5, M2.7 disponible via 4 providers) + notre `cost_tracker.py`
- Configuration côté CAI :
  ```bash
  MINIMAX_API_KEY=<ta_clé>
  CAI_MODEL=minimax/MiniMax-M2.7
  OPENAI_API_KEY=sk-123    # placeholder requis par CAI
  ```
- Configuration côté nous :
  ```bash
  python3 -m src.agent --provider minimax --model MiniMax-M2.7
  ```
- **Risque connu** : tool-calling MiniMax parfois capricieux (cf. issue LiteLLM #18834, commentaires `provider.py` ligne 202+267). Affecte les deux côtés → fairness préservée.
- **Mitigation** : en cas de run en échec côté CAI dû à un 400 MiniMax, retry 3× max ; si 3× échec, consigner comme "tool-call failure" (donnée intéressante en soi)

### Contrat de prompt système
- Notre pipeline a ses prompts (engineered) dans `src/agent/prompts/`
- CAI a ses prompts (engineered) intégrés
- **Décision :** on n'écrit PAS un prompt sur-mesure pour CAI. On utilise le `bug_bounter_agent` ou `redteam_agent` tel que fourni, avec juste le `target_ip` et `scope` injectés.
- Cela parre la critique *"vous avez sous-promptué CAI"*.

---

## 6. Le pilote — étape obligatoire avant campagne

### Setup (jour 1, 4 heures)
1. Install CAI : `pip install cai-framework`
2. Configurer `.env` avec Anthropic key
3. Définir le schéma Pydantic (`cai_schema.py`)
4. Smoke test : `cai --continue --prompt "List ports on localhost"`

### Pilote (jour 1, 4 heures, ~$10 LLM)
- **Scénario** : scenario_3 (IT/OT segmenté — *conçu* pour exiger du multi-hop)
- **LLM** : Claude Sonnet 4
- **Configs** : 4 runs
  1. Notre pipeline complet
  2. Notre pipeline avec `--skip-phase 5`
  3. CAI Variante A1 (per-IP, mono-agent)
  4. CAI Variante B (session unique sur le CIDR)

### Critères de succès du pilote
| Métrique | Seuil |
|---|---|
| Notre pipeline F1 > CAI A1 F1 | différence > 0.10 |
| MHR₂(nous complet) > MHR₂(nous sans P5) | différence > 0.20 |
| MHR₂(CAI A1) ≈ 0 | < 0.10 |
| MHR₂(CAI B) | observation, pas seuil |
| Schéma Pydantic correctement extrait | 100% des findings |

### Décisions post-pilote
| Observation | Action |
|---|---|
| Pattern attendu, schéma OK | Go campagne complète Variante A1 + B sur 7 scénarios + A2 sur 3 |
| CAI Variante B fait du multi-hop | Renforcer narrative *"unstructured vs structured"*, ajouter A2 sur 7 scénarios |
| Schéma Pydantic mal rempli | Fallback parser JSONL, +0.5 j |
| F1 trop proche entre nous et CAI | Investiguer évaluateur, peut-être problème de matching |
| Budget LLM cramé en B (>$50 sur un run) | Cap dur à 200 turns, terminer si dépassé |

---

## 7. Étapes concrètes après pilote validé

### Jour 2 — Variante A1 sur tous les scénarios

```bash
for s in scenario_{1..7}; do
  for ip in $(yq '.[] | .ip' benchmarks/ground_truth/${s}.yaml | sort -u); do
    python scripts/baselines/run_cai.py \
      --variant A1 \
      --scenario $s \
      --target $ip \
      --scope $(get_cidr $s) \
      --model claude-sonnet-4-5 \
      --max-turns 40 \
      --output-dir output/baselines/cai/$s/A1/
  done
done
```

Effort calcul : 7 × ~5 IPs × 30 min = ~17h en série, ~3h en parallèle.

### Jour 2-3 — Variante B sur tous les scénarios

```bash
for s in scenario_{1..7}; do
  python scripts/baselines/run_cai.py \
    --variant B \
    --scenario $s \
    --scope $(get_cidr $s) \
    --model claude-sonnet-4-5 \
    --max-turns 200 \
    --output-dir output/baselines/cai/$s/B/
done
```

Effort calcul : 7 × ~1h = ~7h en série.

### Jour 3 — Variante A2 sur 3 scénarios échantillonnés

Choisir 3 scénarios représentatifs : un flat (S1), un gateway (S3), un hub-star (S5).

### Jour 3 — Agrégation et évaluation

```bash
python scripts/baselines/aggregate_cai.py output/baselines/cai/
# produit aggregate_score.csv avec R/P/F1/Score/MHR pour chaque {variante × scénario}
```

---

## 8. Plan de repli si CAI ne marche pas

### Scénario d'échec 1 — Install CAI plante
- Tester sur Linux (Ubuntu 22.04) au lieu de macOS
- Tester en Docker : `docker pull aliasrobotics/cai` (s'il existe)
- Fallback : PentestGPT à la place (effort similaire, moins riche en features)

### Scénario d'échec 2 — `output_type` Pydantic ignoré par CAI
- Fallback : parser JSONL (le plan v1)
- Coût : +0.5 jour de dev

### Scénario d'échec 3 — CAI ne pivote pas du tout en Variante B (timeout, boucle)
- C'est une **donnée intéressante en soi** : "même en mode session unique, CAI ne pivote pas"
- Documenter : `cai_failure_modes.md` avec exemples concrets

### Scénario d'échec 4 — CAI Variante B fait *trop* bien
- Pivoter narrative : *"CAI a les primitives ad-hoc, mais nos métriques structurelles (chains explicites, crown_jewel_reached, evidence levels) sont reproductibles ; CAI ne donne que des findings agrégés sans traçabilité de chaîne"*
- Ajouter une métrique différenciante : **chain reproducibility** (sur 3 runs, combien de fois la même chain est produite ?)

### Scénario d'échec 5 — Aucune des baselines ne marche
- §8 discussion honnête : *"Adapting single-host LLM agents to a network scope is non-trivial. We attempted CAI/PentestGPT/VulnBot ; partial results in Appendix B"*
- Compenser par baseline non-LLM solide (Nmap NSE + Nuclei) qui plafonne mécaniquement

---

## 9. Livrables attendus

```
scripts/baselines/
├── cai_schema.py                    # Pydantic models (CAIReport, ScenarioReport, Finding)
├── run_cai.py                       # CLI launcher (variantes A1, A2, B)
├── cai_to_findings.py               # adapter Pydantic → schema unifié évaluateur
├── cai_jsonl_fallback.py            # parser JSONL de secours
└── aggregate_cai.py                 # agrégation par scénario × variante

output/baselines/cai/
├── scenario_1/
│   ├── A1/
│   │   ├── 192.168.100.X.json       # CAIReport sérialisé par IP
│   │   └── findings.json            # agrégé per-IP
│   ├── A2/...
│   └── B/
│       └── scenario_report.json     # ScenarioReport unique
├── ...
└── aggregate_score.csv

paper/
└── integration_cai.md               # ce document
```

---

## 10. TL;DR

1. **Install CAI** + `.env` (5 min)
2. **Schéma Pydantic** dans `cai_schema.py` (30 min) — *le levier critique*
3. **Smoke test** + 1 run CAI réel pour valider que `output_type` marche (1 h)
4. **Pilote** sur scenario_3 × 4 configs (½ journée, ~$10) — **GO/NO-GO**
5. Si GO :
   - Jour 2 : Variante A1 × 7 scénarios (~$30)
   - Jour 2-3 : Variante B × 7 scénarios (~$50)
   - Jour 3 : Variante A2 × 3 scénarios (~$15)
6. **Agrégation** + intégration au tableau §7 du papier

**Total : ~3 jours, ~$120 LLM.**

**Critères de succès :**
- Variante A1 perd ≥ 0.10 de F1 vs notre pipeline complet sur les patterns gateway/IT-OT/hub-star
- MHR₂ et MHR₃ < 0.10 pour CAI A1
- Variante B documentée (même si elle réussit partiellement, la donnée est utile)
- Schéma Pydantic correctement extrait sur ≥ 95% des runs
