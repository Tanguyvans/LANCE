# Plan : Scalabilité contexte Phase 5 + nettoyage dead code

## Contexte

Avec 35 devices (S12), `04_exploitation.json` contient 109 entrées avec leur champ `evidence` (texte brut long). L'agent Phase 5 le lit entièrement via `read_deliverable("04_exploitation.json")` → surcharge de contexte qui dépasse les limites des modèles avec peu de fenêtre contextuelle.

**Point clé découvert lors de l'audit** : `_run_device_agents()` (`pipeline.py:887`) qui charge `vuln_device.txt` n'est **jamais appelée** — dead code. Le chemin actif est `_run_phase3()` → `_analyze_device()` → `analyze_device.txt` qui injecte déjà `{{scan_results}}` directement (données nmap par device). Le problème de bloat par device (lire `02_recon.md` 35 fois) est donc déjà résolu par l'architecture scanner.

---

## Analyse du problème

### Ce qui est déjà OK

- **Phase 3b par device** : chaque micro-agent reçoit `{{scan_results}}` (données nmap de son device uniquement) via `analyze_device.txt`. Aucun appel à `read_deliverable("02_recon.md")`.
- **Phase 4 par vuln** : chaque exploit agent est indépendant, contexte minimal.
- `_list_previous_deliverables()` retourne uniquement les noms de fichiers, pas le contenu.

### Bottlenecks réels

| Phase | Problème | Estimation |
|-------|----------|------------|
| Phase 5 report | Lit `04_exploitation.json` complet (109 entrées × evidence) | ~150-300 KB |
| Phase 5 report | Lit `03_vuln_analysis.json` complet | ~80-150 KB |
| Phase 5 report | Lit `02_recon.md` (34 services) | ~30-50 KB |
| **Total Phase 5** | **~300-500 KB → 75-125K tokens** | Dépasse Sonnet (200K total) |

---

## Correctif A — PRINCIPAL : summary compact avant Phase 5

**Fichiers** : `src/agent/pipeline.py` + `src/agent/prompts/report.txt`

### A1 — Nouvelle méthode `_generate_exploitation_summary()` dans `pipeline.py`

```python
def _generate_exploitation_summary(self) -> None:
    """Write a compact 04_exploitation_summary.json without evidence fields.

    Reduces Phase 5 context from ~200KB to ~10KB for large scenarios.
    The full evidence remains in 04_exploitation.json for traceability.
    """
    src = self.run_dir / "04_exploitation.json"
    if not src.exists():
        return
    data = json.loads(src.read_text(encoding="utf-8"))
    compact_tests = [
        {
            "vuln_id": t.get("vuln_id", ""),
            "device_id": t.get("device_id", ""),
            "device_ip": t.get("device_ip", ""),
            "vuln_type": t.get("vuln_type", ""),
            "severity": t.get("severity", ""),
            "status": t.get("status", ""),
        }
        for t in data.get("tests", [])
    ]
    out = {
        "summary": data.get("summary", {}),
        "tests": compact_tests,
    }
    out_path = self.run_dir / "04_exploitation_summary.json"
    out_path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Generated exploitation summary: %d entries → 04_exploitation_summary.json", len(compact_tests))
    print(f"  [summary] 04_exploitation_summary.json ({len(compact_tests)} entries, no evidence)")
```

### A2 — Appel dans la boucle principale de `run()` (~ligne 357)

Insérer juste avant `status = self._run_agent(agent_config, stream_callback)` :

```python
            # Generate compact exploitation summary for Phase 5 (reduce context size)
            if agent_config.phase == 5:
                self._generate_exploitation_summary()

            # Run the agent
            status = self._run_agent(agent_config, stream_callback)
```

### A3 — `report.txt` : lire le summary au lieu du fichier complet

Remplacer :
```
   b. read_deliverable("04_exploitation.json")
```
Par :
```
   b. read_deliverable("04_exploitation_summary.json")
      Note: compact version — vuln_id, device_ip, severity, status, vuln_type only.
      Full evidence is in 04_exploitation.json — do NOT read it (context too large).
```

---

## Correctif B — Déplacer le noise filter vers `analyze_device.txt`

**Fichiers** : `src/agent/prompts/analyze_device.txt` + `src/agent/prompts/vuln_device.txt`

`vuln_device.txt` est dead code (jamais chargé par le pipeline). Tout filtre anti-bruit doit aller dans `analyze_device.txt`.

Ajouter à la fin de la section `## Rules` dans `analyze_device.txt` :

```
- LOW/INFO CVE findings (CVSS < 4.0): only include if the CVE is directly exploitable
  on this device (confirmed version match). Skip informational CVEs that require local access.
- Do NOT create findings for missing HTTP headers (missing_header) — the scanner handles those.
```

Marquer `vuln_device.txt` comme deprecated :
```
# DEPRECATED — use analyze_device.txt. This file is not loaded by the pipeline.
```

---

## Correctif C — Supprimer `_run_device_agents()` (dead code)

**Fichier** : `src/agent/pipeline.py` lignes 887-1070

`_run_device_agents()` n'est appelée nulle part. La supprimer nettoie ~180 lignes de code obsolète.

Vérifier avant suppression :
```bash
grep -n "_run_device_agents" src/agent/pipeline.py tests/test_pipeline.py
```

---

## Fichiers modifiés

| Fichier | Changement |
|---------|-----------|
| `src/agent/pipeline.py` | + `_generate_exploitation_summary()`, appel avant Phase 5, suppression `_run_device_agents()` |
| `src/agent/prompts/report.txt` | `04_exploitation.json` → `04_exploitation_summary.json` |
| `src/agent/prompts/analyze_device.txt` | + règle anti-bruit CVE LOW/INFO |
| `src/agent/prompts/vuln_device.txt` | + commentaire DEPRECATED en première ligne |

---

## Ordre d'implémentation

1. `pipeline.py` — `_generate_exploitation_summary()` + appel avant Phase 5
2. `report.txt` — remplacer la lecture
3. `analyze_device.txt` — noise filter CVE
4. `vuln_device.txt` — commentaire deprecated
5. `pipeline.py` — suppression `_run_device_agents()` (après vérification tests)

---

## Vérification

```bash
# Tests ne doivent pas régresser
python3 -m pytest tests/test_pipeline.py tests/test_evaluator.py -p no:pytest_ethereum -p no:web3 -q

# Dry-run
python3 -m src.agent --dry-run --scenario 1 --verbose

# Vérifier que 04_exploitation_summary.json est généré
ls output/agent/<timestamp>/04_exploitation_summary.json

# Comparer la taille des deux fichiers (doit être ~10x plus petit)
wc -c output/agent/<timestamp>/04_exploitation.json output/agent/<timestamp>/04_exploitation_summary.json
```
