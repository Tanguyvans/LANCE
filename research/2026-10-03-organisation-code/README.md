# Organisation du code LANCE

**Cycle de vie : Conclu** (inventaire du 2026-10-12) — diagnostic reproduit et réorganisation proposée ; mise en œuvre partielle depuis (contextes de phase isolés, commit `c3dbe94` du 2026-10-12). Ne rouvrir que pour un nouveau diagnostic daté.

**Question.** Comment rendre les responsabilités, les dépendances et les points
de modification du projet plus explicites, sans modifier ses contrats de preuve ?

**Statut :** diagnostic logiciel reproduit ; réorganisation proposée, non implémentée.

**Début de l'étude :** 2026-10-03.

**Dernière révision du rapport :** 2026-10-03 12:12
(Europe/Brussels, UTC+02:00). Relecture indépendante achevée.

Le périmètre couvre l'agent, l'API, l'interface, le benchmark, l'entraînement et
leurs tests. L'analyse porte sur la copie de travail, y compris les corrections
locales non commitées. Aucun laboratoire, déploiement, entraînement ou audit réseau
n'est exécuté.

## Synthèse

Les grands ensembles sont déjà séparés, mais les phases restent souvent des
méthodes d'un hôte partagé : `Pipeline` hérite de 14 classes. Le graphe conserve
un contexte global, `runtime` combine composition et réexports métier, et des
fonctions importantes réunissent plusieurs responsabilités. Le frontend possède
également un fichier `app.js` de 3 761 lignes.

Les 175 sources Python étudiées représentent 53 633 lignes physiques, tests
exclus. Aucun cycle n'apparaît dans les imports explicites de portée module ;
trois composantes circulaires apparaissent en ajoutant les imports de portée
fonction. Cette portée est lexicale, pas temporelle. Aucun échec d'import
circulaire n'est observé ; aucune suppression de code n'est justifiée par
l'absence de références statiques.

Le premier lot proposé extrait l'autorité pure d'authentification et le contrôle
commun des destinations. Le suivant introduit un contexte de vérification
explicite. Les autres lots traitent graphe, contrat compact/fournisseur,
évaluation/API, frontend et nettoyage vérifié. Leur implémentation et leur
compatibilité restent à établir.

## Documents et reproduction

- [Rapport PDF](report.pdf) et [source LaTeX](report.tex) : neuf pages, deux
  figures TikZ éditables, constats localisés et sept lots avec critères d'acceptation.
- [Mesures statiques](structure.json), générées par
  [le script d'analyse](../../scripts/analysis/code_organisation.py) avec Python 3.12+.
- [Organisation de référence](../../docs/README.md) et
  [structure actuelle des phases](../../src/agent/phases/README.md).
- [Étude sur le contexte](../2026-09-29-context-scalability/README.md), complémentaire.
- [Observation du contexte de graphe](graph-context-probe.json), produite par
  [un probe en mémoire](../../scripts/analysis/graph_context_probe.py).
- [Validation locale](validation.json) : commande, résultat et empreintes des
  tests ciblés et des scripts d'analyse.

```sh
python scripts/analysis/code_organisation.py \
  --output research/2026-10-03-organisation-code/structure.json
```

Les mesures d'imports sont syntaxiques ; elles ne démontrent ni une erreur
d'import à l'exécution, ni l'absence d'utilisation d'un module.

Le JSON identifie le commit de base et l'empreinte de chaque fichier de la copie
de travail. Les scripts d'analyse, les tests et les fichiers ignorés sont exclus
des tailles de production. Les 161 fichiers Python de tests comptés incluent
leurs fixtures et fichiers d'initialisation. Reproduire le probe depuis la racine :

```sh
PYTHONDONTWRITEBYTECODE=1 python -m scripts.analysis.graph_context_probe
```

Il charge deux contextes fictifs en mémoire et remplace le chargement réel du
laboratoire par un mock. L'audit hook observe les connexions, processus et
ouvertures d'écriture ; il n'est pas une sandbox native exhaustive.

## Vérifications

Le 3 octobre 2026, Python 3.12.2 :

```sh
python -m pytest -q tests/test_phase_modules.py \
  tests/test_scope_destination_boundary.py \
  tests/test_knowledge_policy_isolation.py tests/test_run_artifact_isolation.py
```

Résultat : **79 passed in 4.62s**. Les imports relatifs, portées lexicales et
composantes de l'analyseur ont aussi été vérifiés sur des cas synthétiques ; le
JSON a été reproduit à l'identique. La suite complète, le réseau, le déploiement
et le GPU n'ont pas été exécutés pour cette étude. Ces tests vérifient l'état
analysé, pas les futures implémentations proposées.

La compilation intégrée Codex et l'export local LaTeX ont réussi : neuf pages,
aucun débordement ni renvoi non résolu. Les commandes copiables et les
destinations du sommaire sont vérifiées dans le PDF final. `git diff --check`
est également réussi.

### Relecture indépendante

Relecteur : agent distinct `/root/phase3_reviewer`, le 3 octobre 2026.
Version relue : rapport révisé à **12:12 (Europe/Brussels, UTC+02:00)**.
Périmètre : source LaTeX complète, méthode et mesures reproduites, lecture des
propriétaires cités, puis inspection visuelle des neuf pages du PDF. Une
étiquette de figure et le rendu des commandes ont été corrigés ; les pages
finales concernées ont été revérifiées, les autres rendus étant identiques à
ceux déjà inspectés. Les 79 tests ciblés passent aussi dans la reproduction
indépendante (3,04 s).

Empreintes SHA-256 de la version approuvée :

```text
report.tex  1eeb623a9208ff466a25b4be8231cd30412feb40f90ec978cd09b1d174f18030
report.pdf  316d9509e05121b4070d00a4454993da4d968af997a69b5a25036659695681b3
```

Aucune réserve restante sur le diagnostic ou le rendu. L'implémentation des
lots, la suite complète, les usages externes du code ancien et les résultats
de laboratoire/GPU restent hors de cette validation.

## Points ouverts

- Définir un premier lot de refactoring et ses critères de non-régression.
- Confirmer les usages dynamiques avant toute suppression de code ancien.
