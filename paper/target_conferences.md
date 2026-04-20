# Target Conference

## Primary Target (locked)

### ACSAC 2026 — Annual Computer Security Applications Conference
- **Website**: https://www.acsac.org/2026/submissions/papers/
- **Submission deadline**: **May 26, 2026 (23:59 AoE — firm)**
- **Early reject notification**: July 13, 2026
- **Author response period**: August 18–25, 2026
- **Final notification**: September 8, 2026
- **Camera-ready**: October 22, 2026
- **Conference**: December 7–11, 2026, Los Angeles, CA, USA
- **Format**: 11 pages double-column IEEEtran (+ 5 pages refs/appendix, max 16 total)
- **Template**: `\documentclass[conference,compsoc]{IEEEtran}`
- **Review**: Double-blind, 2 rounds
- **Publication**: IEEE Xplore (IEEE + IEEE CS + IEEE TC on Security & Privacy co-sponsored)
- **Acceptance rate**: ~20-22% (2024: 21.8%, 2025: 20.7%)
- **Hard topic theme 2026**: **Security and Privacy of Agentic Systems**

### Why ACSAC
- Explicit hard topic match: *Security and Privacy of Agentic Systems*
- Listed topics of interest match directly:
  - Cyber-Physical Systems, Embedded Systems, and IoT Security
  - Automated Detection and Patching of Software Vulnerabilities
  - Machine Learning Security
  - Intrusion Detection and Prevention
  - Security Applications of Generative AI
- Applied/systems focus — values solid evaluation and reproducible benchmarks over theoretical novelty
- Artifact evaluation track — our 7-scenario benchmark + ground truth = strong asset
- Distinguished Paper with Artifacts Award available

### ACSAC Submission Requirements
- **Anonymization**: full double-blind. No author names/affiliations. Cite own prior work in third person. Repository (if provided) must be anonymized.
- **Ethical Considerations section**: mandatory (we exploit vulnerabilities → must describe lab isolation, responsible disclosure).
- **LLM Usage Statement**: mandatory section at end (does not count toward page limit). Must disclose LLM use in methodology and for editing.
- **Artifacts submission**: separate submission after acceptance. Flag intent at submission time.
- **No parallel submission** to other venues with proceedings.

## Internal Timeline (5 weeks + 1 day)

| Week | Dates | Milestone |
|---|---|---|
| **S1** | 27 Apr – 3 May | Freeze benchmark (S1–S7 × all providers), LaTeX outline, HotCRP account |
| **S2** | 4 May – 10 May | Draft: Introduction, Related Work, Method |
| **S3** | 11 May – 17 May | Draft: Experimental Setup, Evaluation (tables, figures) |
| **S4** | 18 May – 24 May | Draft: Discussion, Ethical Considerations, LLM Usage Statement, Abstract. Native-speaker proofreading. |
| **S5** | 25 May – 26 May | Repo anonymization, format check, final PDF, submit on HotCRP |

### Hard internal deadlines
- **Fri 2 May**: benchmark frozen (no more pipeline iteration)
- **Fri 17 May**: all figures/tables final (no new numbers after)
- **Fri 23 May**: paper frozen (anonymization + format only after this)

## Paper Outline (target ~11 pages)

1. **Introduction** (~1 p) — Manual IoT pentest is slow/costly; LLM agents promise automation; contribution = graph-guided multi-agent pipeline + reproducible benchmark.
2. **Related Work** (~1.5 p) — PentestGPT, PENTEST-AI (MITRE ATT&CK), AWE, PentAGI, CHAP. Position on IoT-specific, graph-based, benchmark-grounded.
3. **Method** (~3 p) — Graph modeling of IoT infrastructure, 5-phase pipeline (graph analysis → recon → vuln analysis → exploitation → report), vulnerability taxonomy, tool abstraction.
4. **Experimental Setup** (~1.5 p) — 7 Proxmox scenarios, ground truth YAML, multi-provider setup, weighted scoring (CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1).
5. **Evaluation** (~2.5 p) — Recall/Precision/F1/Score per scenario, multi-LLM comparison (Anthropic, MiniMax, GLM, Qwen, DeepSeek), cost per run, ablation on phases.
6. **Discussion & Limitations** (~1 p) — closed models, reproducibility, LLM hallucination bias, scope boundaries.
7. **Conclusion** (~0.5 p)

*Plus*: Ethical Considerations section, LLM Usage Statement (end of paper, outside page count).

## Working Title

> *Graph-Guided Multi-Agent LLM Pipeline for Automated IoT Penetration Testing: A Reproducible Benchmark Study*

## Related Work Comparison

| | PentestGPT (USENIX'24) | PENTEST-AI / AWE / PentAGI | Our approach |
|---|---|---|---|
| Targets | Web CTF (HackTheBox, VulnHub) | Web/network targets | Physical IoT lab + 7 Proxmox benchmark scenarios |
| Vulnerabilities | OWASP web (SQLi, XSS, IDOR) | General web/network | IoT protocols (LoRaWAN, Zigbee, MQTT) + device CVEs |
| Architecture | Single agent + human-in-loop | Multi-agent, no graph | Multi-agent pipeline (5 phases) + graph-guided |
| Infra modeling | None | None | Directed graph + Dijkstra attack paths + betweenness |
| Hardware tools | None | None | SDR, Flipper Zero, Proxmark3 (declarative YAML) |
| Scoring | Binary (flag captured or not) | Task-level success | Composite weighted (CVSS + exposure + centrality) + severity-aware eval |
| Evaluation | 104 Docker challenges, 86.5% | Ad hoc | 7 reproducible scenarios × multi-LLM × ground truth YAML |
| Reproducibility | Partial (Docker) | Limited | Full benchmark + ground truth + artifact submission |

## Research Questions

- **RQ1** — Detection effectiveness: Does the pipeline detect injected vulnerabilities across the 7 scenarios? (Recall, F1)
- **RQ2** — Graph-based risk relevance: Do composite risk scores (CVSS + exposure + centrality) correlate with real exploitability outcomes in Phase 4?
- **RQ3** — Multi-LLM comparison: How do Anthropic/MiniMax/GLM/Qwen/DeepSeek compare on the same pipeline?
- **RQ4** — Cost/time envelope: What is the per-phase token cost and wall-clock time across providers?

## No Backup (decision)

Decision 2026-04-20: single target, no backup conference. Rationale: focused effort, no split attention. If ACSAC rejects, re-evaluate options post-decision (AsiaCCS 2027 C1 on Aug 21 and NDSS 2027 C2 on Aug 19 remain viable fallbacks if early reject on July 13).
