# Plan de publication — IoTPentBench / MeshScout

Ce document est synchronisé avec `paper/paper_full.tex`. L'ancien plan
`IoTBench` en 7 scénarios / 87 vulnérabilités est obsolète.

## Cible actuelle

| Élément | Choix |
|---|---|
| Papier | `paper/paper_full.tex` |
| Nom benchmark | IoTPentBench |
| Nom harness | MeshScout |
| Format courant | IEEEtran double-colonne, 10 pages compilées |
| Cible éditoriale | ACSAC / IEEE CNS selon deadline et format final |
| État | Méthode et benchmark rédigés ; résultats encore à produire |

## Question de recherche

Les agents LLM de pentest évalués sur des cibles single-host mesurent-ils
réellement la capacité à auditer une infrastructure IoT en réseau, où les
vulnérabilités importantes dépendent de pivots, de zones et de preuves
d'exploitation ?

Sous-questions :

- Q1 : Quelle part du recall disparaît quand les vulnérabilités sont derrière
  un pivot ou une transition de zone ?
- Q2 : La topologie préalable améliore-t-elle le triage et la priorisation ?
- Q3 : Une phase dédiée d'intrusion/lateral movement augmente-t-elle MHR et
  les preuves L2/L3 ?
- Q4 : Quels protocoles et catégories restent mal couverts par les LLMs ?

## Contributions retenues

1. **IoTPentBench** : 15 scénarios Proxmox/Ansible, 145 devices, 229
   vulnérabilités injectées, 2 scénarios hardened, ground truth YAML.
2. **MeshScout** : pipeline LLM en 6 phases : topology prior, discovery,
   per-device triage, per-vulnerability verification, intrusion, report.
3. **Métriques réseau** : Evidence levels L1/L2/L3 et Multi-Hop Reach
   `MHR_k`, avec `hop_depth=0` pour les vulnérabilités directement joignables.
4. **Évaluation architecturale** : modèle LLM maintenu constant, comparaison
   principale entre MeshScout full, `w/o Phase 1`, `w/o Phase 5`, et Nmap NSE.

## Benchmark actuel

| Groupe | Scénarios | Devices | Vulns | Rôle |
|---|---:|---:|---:|---|
| Main scenarios | 10 | 64 | 144 | Couverture des patterns |
| Scalability stressors | 3 | 67 | 85 | Taille réseau et zones |
| Hardened controls | 2 | 12 | 0 | Faux positifs |
| **Total** | **15** | **145** | **229** | |

Distribution des vulnérabilités : misconfiguration 68, no_authentication 41,
data_exposure 38, default_credentials 29, info_disclosure 13, code_injection
11, cve 9, insecure_update 9, weak_crypto 6, missing_header 3,
privilege_escalation 2.

## Travail restant avant soumission

- Finaliser les figures : patterns, pipeline, Phase 3 parallelization,
  résultats F1/MHR, heatmap, Pareto coût/performance.
- Exécuter `k=3` runs pour MeshScout full, `w/o Phase 1`, `w/o Phase 5`.
- Produire la baseline Nmap NSE et convertir les sorties au schéma évaluateur.
- Générer les tableaux : main results, evidence levels, per-protocol,
  hardened controls false-positive rate.
- Remplacer les `TODO` de `paper_full.tex` par les résultats gelés.
- Recompiler LaTeX et corriger warnings bloquants / overfull boxes.

## Baselines externes

PentestGPT, CAI et VulnBot restent dans le related work. Ils ne doivent entrer
dans les tableaux de résultats que si un runner local reproductible existe et
respecte le même modèle, le même budget de tours et le même périmètre réseau.
