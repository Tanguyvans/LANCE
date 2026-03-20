# Target Conferences

## Primary Target

### RAID 2026 — 29th International Symposium on Research in Attacks, Intrusions and Defenses
- **Website**: https://raid2026.org/
- **Submission deadline**: April 16, 2026 (firm, AoE)
- **Notification**: July 10, 2026
- **Camera-ready**: August 13, 2026
- **Conference**: October 11–14, 2026, Lancaster, UK
- **Format**: 20 pages LNCS (excl. references), appendices illimitées
- **Review**: Double-blind, ≥3 reviewers
- **Publication**: Springer LNCS
- **Acceptance rate**: ~20-25%
- **Topics match**: IoT security, vulnerability analysis and exploitation, network security, ML for security, intrusion detection

## Backup Targets

### IEEE ISC2 2026 — 12th IEEE International Smart Cities Conference
- **Website**: https://dei.fe.up.pt/ieee-isc2-2026/
- **Submission deadline**: ~May 31, 2026 (à confirmer)
- **Conference**: October 26–29, 2026, Porto, Portugal
- **Publication**: IEEE Xplore
- **Acceptance rate**: ~25-30%
- **Topics match**: Smart city, IoT infrastructure security, graph-based modeling

### IEEE GLOBECOM 2026 — Workshops
- **Website**: https://globecom2026.ieee-globecom.org/
- **Submission deadline**: July 15, 2026
- **Notification**: September 20, 2026
- **Conference**: December 7–11, 2026, Macao, China
- **Publication**: IEEE Xplore
- **Topics match**: ML/DL for wireless security, IoT protocol security

### ESORICS 2026 — 31st European Symposium on Research in Computer Security
- **Website**: https://sites.google.com/di.uniroma1.it/esorics2026/
- **Submission deadline**: April 21, 2026 (Spring cycle, firm)
- **Notification**: June 12, 2026
- **Conference**: September 14+, 2026, Rome, Italy
- **Format**: 16 pages LNCS (excl. bibliography), max 20 total
- **Review**: Single-blind
- **Publication**: Springer LNCS
- **Acceptance rate**: ~15% (Tier A)
- **Topics match**: Security and Privacy in the IoT and CPS, AI for security, network security, vulnerability analysis

## Strategy

1. **Now → April 16**: Write paper targeting RAID (20 pages LNCS, double-blind)
2. **If RAID missed**: Adapt to ISC2 Porto (deadline ~May 31) or ESORICS (deadline April 21)
3. **Fallback**: GLOBECOM workshop (deadline July 15) — shorter format, more time

## Comparison with Related Work

| | PentestGPT (USENIX'24) | Our approach |
|---|---|---|
| Targets | Web CTF (HackTheBox, VulnHub) | Physical IoT lab (15 devices) |
| Vulnerabilities | OWASP web (SQLi, XSS, IDOR) | IoT protocols (LoRaWAN, Zigbee, MQTT) |
| Architecture | Single agent + human-in-loop | Multi-agent pipeline (5 phases) |
| Graph modeling | None | Directed graph + Dijkstra attack paths |
| Hardware tools | None | SDR, Flipper Zero, Proxmark3 |
| Risk scoring | Binary (flag captured or not) | Composite (CVSS + betweenness + hop distance) |
| Evaluation | 104 Docker challenges, 86.5% success | Real lab exploitation + multi-LLM comparison |

## Evaluation Plan (for RAID)

- **RQ1**: Does the pipeline detect known vulnerabilities? → Success rate on lab
- **RQ2**: Does graph-based risk scoring correlate with real exploitability? → Risk scores vs exploitation outcome
- **RQ3**: How do different LLMs compare? → Claude vs Gemini vs GPT on same phases
- **RQ4**: What is the cost and time? → Per-phase cost/time tracking
