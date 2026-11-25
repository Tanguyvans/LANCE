# Audit technique du projet LANCE

**Cycle de vie : Conclu** (2026-11-25) — diagnostic statique complet du dépôt au commit `bbaffdf` ; recommandations classées en trois vagues, non encore appliquées.

**Question.** Quels éléments du dépôt `NATO-SmartCity-IoT` doivent être corrigés, optimisés ou supprimés au 25 novembre 2026, et comment la base de code a-t-elle évolué depuis l'audit du 3 octobre 2026 ?

**Statut :** Conclu (diagnostic statique reproductible).

**Début de l'étude :** 2026-11-25.

**Dernière révision du rapport :** 2026-11-25 09:05 (Europe/Brussels, UTC+01:00).

**Travaux antérieurs :** [`research/2026-10-03-organisation-code/`](../2026-10-03-organisation-code/README.md).

## Synthèse

Par rapport au diagnostic du 3 octobre 2026, la base Python de production a grandi de **12,8 %** (53 633 → 60 493 lignes sur 200 fichiers), `src/static/app.js` atteint **4 330 lignes** (+15,1 %), les fichiers de tests passent de 161 à **212** (+31,7 %), et les cycles d'imports de portée fonction passent de 3 à **4**.

L'audit recense **24 actions concrètes** :

- **9 corrections** : conteneur principal exécuté en `root` (`Dockerfile`), lancement de scans non authentifié par défaut (`src/api/auth.py`), téléchargements Docker sans vérification SHA-256 ni épinglage, IP Tailscale `100.76.206.65` codée en dur dans 8 fichiers, 2 `except:` nus et 24 `except Exception: pass` silencieux, 3 erreurs API encore en français en `LANCE_MODE=audit`, 4 cycles d'imports, désynchronisation de l'index `research/README.md` (dossier `2026-11-09-methodo-eval-papier/` non indexé, statuts divergents), et sessions admin en mémoire.
- **7 optimisations** : découpage des fonctions > 650 lignes (`evaluate`, `_openai_loop`, `synthesize_exploit_result`, `_apply_compact_intrusion_tool_contract`), remplacement progressif des 14 mixins de `Pipeline`, modularisation ES de `src/static/app.js`, séparation et verrouillage des dépendances, allègement Docker (`default-jre-headless`), factorisation des 15 workflows CI, et actualisation d'`objectifs/ETAT-COURANT.md`.
- **8 suppressions / nettoyages** : `aiofiles` (0 occurrence), `src/visualize.py` + `pyvis`, vérification/archivage de `src/cve_cli.py` et `src/risk_cli.py`, externalisation de `metric/squelette-latex/` et `paper/`, suppression du répertoire vide `training/`, nettoyage de `.gitignore` et des ~560 Mo d'artefacts locaux non suivis.

## Documents et reproduction

- [Rapport PDF](report.pdf) — rapport de synthèse (mise en page vérifiée visuellement page par page).
- [Source LaTeX](report.tex) — source éditable correspondante.
- [Mesures brutes](audit-metrics.json) — instantané JSON généré au commit `bbaffdfb3b09720d6a57979679593025f5fc7fa2`.

## Limites et note de compilation

- Analyse strictement statique sur la copie locale ; aucun run de laboratoire, déploiement ni exécution réseau n'a été lancé.
- `pdflatex` n'étant pas installé sur la machine de développement, `report.pdf` a été généré via Chromium headless depuis une mise en page HTML/CSS synchronisée avec `report.tex`, puis inspecté visuellement page par page.
- Statut de relecture indépendante : **à relire** par un agent distinct si une publication formelle est souhaitée.
