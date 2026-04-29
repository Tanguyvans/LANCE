# IoTBench — ACSAC 2026 Submission

## Target

- Conference: **ACSAC 2026** (Annual Computer Security Applications Conference)
- Deadline: **26 May 2026 (23:59 AoE)**
- Format: 11 pages double-column IEEEtran `[conference,compsoc]` (+ 5 pages refs/appendix, max 16)
- Review: double-blind, 2 rounds
- Hard topic: Security and Privacy of Agentic Systems
- See `target_conferences.md` for full details.

## Working documents (internal — not for submission)

| Doc | Contenu | Quand le consulter |
|---|---|---|
| `etat_de_lart.md` | État de l'art (4 clusters de littérature) + méthodologie d'évaluation + grille de comparaison étendue | Avant d'écrire / mettre à jour §2 Related Work |
| `baselines.md` | Sélection détaillée des 4 catégories de baselines + outils traditionnels (Metasploit, BloodHound) avec phrase-bouclier | Avant d'écrire §7.2 et de lancer les baselines |
| `plan.md` | Calendrier semaine par semaine (S1→S5), dépendances, plan de repli, lot F robustesse | Référence d'exécution principale, à mettre à jour à chaque jalon |
| `integration_cai.md` | Plan opérationnel d'intégration CAI comme baseline (install, prompt, parser JSONL) | Avant de coder l'adaptateur CAI |
| `target_conferences.md` | ACSAC 2026 details + internal timeline + comparison grid (legacy) | Référence conférence |

## Build

Requires TeX Live with the `ieeetran` and `ieeetran-bst` packages.

```bash
# install once (if missing)
sudo tlmgr install ieeetran
# or: brew install --cask mactex  # full MacTeX ships with it

make         # builds main.pdf
make clean   # removes aux/log/bbl/blg/out
make watch   # rebuild on change (requires latexmk)
```

## Structure

```
paper/
├── main.tex                  # entry point, IEEEtran compsoc conference
├── references.bib            # bibliography
├── Makefile
├── README.md                 # this file
├── target_conferences.md     # conference target + timeline
├── sections/
│   ├── 01_introduction.tex
│   ├── 02_related_work.tex
│   ├── 03_threat_model.tex
│   ├── 04_iotbench.tex
│   ├── 05_harness.tex
│   ├── 06_setup.tex
│   ├── 07_evaluation.tex
│   ├── 08_discussion.tex
│   ├── 09_ethical.tex
│   ├── 10_conclusion.tex
│   └── 11_llm_usage.tex      # outside page-limit per ACSAC CFP
├── figures/                  # PDF/PNG figures (fig1_patterns.pdf, …)
└── appendix/                 # optional appendix material
```

## Double-blind hygiene

- No author names, affiliations, hostnames (Tailscale, Proxmox node names) in text or figures.
- Cite own prior work in the third person.
- Anonymize the artifact repository before submission (strip `.git`, replace maintainer emails).
- Review figures for screenshots containing identifying info.

## Page budget (11 p target)

| Section | Budget |
|---|---|
| §1 Introduction | 1.0 p |
| §2 Background & Related Work | 1.5 p |
| §3 Threat Model | 0.5 p |
| §4 IoTBench | 2.0 p |
| §5 Harness | 2.0 p |
| §6 Experimental Setup | 0.75 p |
| §7 Evaluation | 2.25 p |
| §8 Discussion | 0.5 p |
| §9 Ethical Considerations | 0.25 p |
| §10 Conclusion | 0.25 p |
| **Total** | **11 p** |
| §11 LLM Usage Statement | (outside) |
| Refs + Appendix | ≤ 5 p |

## Do-not-claim list

- Hardware tools (HackRF/Flipper/Proxmark) are recommendation templates, not executable — **do not market as functional**.
- "Autonomous exploitation" — Phase 4 *verifies* via default creds / unauth services, it does not chain RCEs. Say "verification with evidence levels L1/L2/L3".
- "Graph-guided" — VulnBot's PTG collides with this term. **Mitigation décidée:** prouver l'apport par ablation Phase 1 on/off (cf. `plan.md` chantier B). Si l'ablation valide, OK pour garder le terme avec une note de différenciation (graph d'infra vs PTG de tâches).
- "Multi-hop chain" — **promu en contribution conditionnelle** depuis l'introduction de la métrique MHR (Multi-Hop Reach). Si MHR_2 et MHR_3 sont mesurés et significatifs sur les baselines, multi-hop devient un résultat majeur de §7. Cf. `plan.md` chantier A.
- "7 diverse architectures" — only true once firewall rules by pattern are merged; until then say "5 architectural patterns".
