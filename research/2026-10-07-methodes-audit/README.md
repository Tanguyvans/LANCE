# Méthodes d'audit et architectures de preuve pour LANCE

## Question et périmètre

Comment rendre l'audit IoT plus instructif et ses conclusions plus vérifiables,
à partir des mêmes observations, sans confondre hypothèse, preuve, absence
d'information et conformité ? Cette étude compare les architectures de
traitement des preuves et les méthodes d'audit défensif susceptibles de prolonger
LANCE. Elle complète les études précédentes sans les remplacer.

**Statut : exploration et protocole proposé ; quatre rapports compilés et relus.**
Début de l'étude : **2026-10-07**. Aucun résultat de comparaison expérimentale
n'est disponible. La lecture du code est statique : la copie de travail comprend
des changements locaux et des conflits Git non résolus, conservés pendant ce
travail. Elle ne représente pas une version exécutable validée.

**Dernière révision du rapport principal : 2026-10-07 13:56
(Europe/Brussels, UTC+02:00).** Dernière mise à jour du dossier : 2026-10-07.

## Synthèse et priorité proposée

LANCE possède déjà un journal d'observations, un registre de candidats et une
restitution déterministe. La lecture révèle aussi un chemin où la sortie
d'outil est filtrée ou tronquée avant journalisation : une référence ne garantit
pas une capture native complète. Ce constat statique ne mesure pas la fréquence
des erreurs et ne démontre pas une invalidité générale des preuves.

La proposition prioritaire est de relier chaque conclusion à une propriété,
à sa portée, aux observations et aux obligations de preuve, en conservant
contradictions et inconnus. Les sept familles examinées sont la couverture
normative, la provenance, l'argumentation de preuve, les propriétés comparées,
l'applicabilité des avis constructeur, la synthèse citée et la relecture séparée.

Le premier essai proposé reste hors ligne : **E0**, règles fortes sur dossier
normalisé, contre **E1**, mêmes informations et règles avec relations de preuve
explicites. **E2**, E1 avec relecture sémantique LLM bornée, est une comparaison
ultérieure distincte. L'attribution valide est la mesure principale ; les
confirmations abusives, la couverture et les coûts restent visibles. Un gain
limité à la traçabilité ou une équivalence sont des conclusions admissibles.
L'état réel d'une propriété et le soutien accessible dans les observations
sont annotés séparément. Aucun gain de détection ou de temps humain n'est établi.

## Rapports

Commencer par la synthèse ; les trois rapports spécialisés gardent les détails
du diagnostic, les sources primaires et les conditions de l'expérience proposée.

| Rapport | Question | Lecture | Source éditable |
| --- | --- | --- | --- |
| Synthèse et choix proposés | Quelle contribution retenir et dans quel ordre la tester ? | [PDF](report.pdf) | [LaTeX](report.tex) |
| Pipeline actuel et architectures | Quels acquis conserver et quelles extensions comparer ? | [PDF](pipeline.pdf) | [LaTeX](pipeline.tex) |
| Méthodes et sources primaires | Quelles méthodes d'audit sont pertinentes pour notre périmètre ? | [PDF](methodes.pdf) | [LaTeX](methodes.tex) |
| Protocole d'évaluation | Comment mesurer les gains et les dégradations à observations constantes ? | [PDF](protocole.pdf) | [LaTeX](protocole.tex) |

Toutes les révisions ci-dessous sont datées du **2026-10-07**, en
**Europe/Brussels (UTC+02:00)**. Les dates sont fixes dans les sources et PDF.

| Document | Dernière révision | Pages | Auteur de la rédaction | Relecteur indépendant et contrôle final |
| --- | --- | --- | --- | --- |
| Synthèse | 13:56 | 6 | Codex, agent principal | `evaluation_review`, 13:56 ; six pages relues à 13:54, pages 1/6 revérifiées après corrections bibliographiques, pages 2–5 rendues identiques |
| Pipeline | 13:41 | 6 | `pipeline_review` | `methods_review`, 13:46 ; six pages inspectées et assertions principales vérifiées statiquement |
| Méthodes | 13:49 | 7 | `methods_review` | `pipeline_review`, 13:50 ; sept pages finales inspectées après clarification des sigles |
| Protocole | 13:52 | 6 | `evaluation_review` | `methods_review`, 13:54 ; six pages finales inspectées après séparation des annotations et clarification des transformations |

Les relecteurs ne sont pas les auteurs des rapports concernés. Leurs avis
finaux ne comportent aucune réserve bloquante dans le périmètre relu. Le
contrôle porte sur clarté, rigueur documentaire et rendu, pas sur une validation
expérimentale. La revue bibliographique demeure ciblée : notices ou passages
identifiés, sans lecture intégrale systématique ni reproduction des résultats.
Le relecteur de la revue des méthodes n'a pas pu rouvrir sa référence
OpenReview ; cette limite ne constitue pas une vérification supplémentaire
de la source, dont le périmètre de lecture de l'auteur figure dans le rapport.

## Traçabilité et validation

- [Manifeste des sources locales](sources-locales.json) : 54 fichiers consultés par lectures ciblées, empreintes SHA-256 et marqueurs de conflit. Le commit de base ne reproduit pas seul la copie de travail. Les empreintes identifient des fichiers locaux, sans authentifier une provenance distante.
- Quatre PDF, **25 pages** au total, compilés avec `latexmk`/`pdflatex` puis rendus avec Poppler. Figures TikZ modifiables dans les sources ; aucun fichier auxiliaire de compilation conservé dans le dossier.
- Sommaires et références stabilisés ; destinations internes des PDF et liens locaux vérifiés. Aucun débordement ou renvoi indéfini dans les derniers journaux. L'environnement TeX signale l'absence de motifs de césure française ; aucun défaut visuel correspondant n'a été observé.
- Les nouveaux fichiers et la seule ligne ajoutée à l'index ont été vérifiés séparément pour les espaces et marqueurs. `git diff --check` global demeure en échec à cause des conflits préexistants ; aucun n'est résolu par cette étude.
- Aucun test applicatif n'est exécuté : les modifications sont documentaires et la copie en conflit ne fournit pas une référence exécutable. Aucun laboratoire, déploiement ou appel au modèle LANCE n'est lancé.

Les empreintes des PDF finaux identifient les versions relues :

| PDF | SHA-256 |
| --- | --- |
| `report.pdf` | `053e9648c3d76dadfa58611a1cabe9f494dd383485c5f4cab7d6cc0fc11cd535` |
| `pipeline.pdf` | `97ba44b32eb82a885d5567b0c2cce7df42a04c55624ad383114cbe8e44167808` |
| `methodes.pdf` | `16671dbe56a02a7b4713d3b2321794ea88af94888376b6cbaefd161c392f8100` |
| `protocole.pdf` | `1062becbc4520041acf9ac69cbbb8e1f333df35c8f852210ab9335e73288a332` |

Pour recompiler la synthèse depuis la racine du dépôt, sans auxiliaires dans
`research/` :

```bash
build_dir="$(mktemp -d)"
latexmk -pdf -interaction=nonstopmode -halt-on-error \
  -outdir="$build_dir" research/2026-10-07-methodes-audit/report.tex
pdftoppm -r 110 -png "$build_dir/report.pdf" "$build_dir/page"
```

Les trois autres sources sont autonomes : remplacer `report.tex` par le nom
concerné, puis rendre le PDF portant ce même nom. Inspecter les pages avant de
remplacer le livrable. Les prochains outils expérimentaux et leurs tests
appartiendront au module logiciel propriétaire ; aucun replay exécutable n'est
fourni par cette étude documentaire.

## Études liées

- [Apport de l'agent face à l'automatisation](../2026-09-27-agent-vs-automation/README.md) : D1/A1, outils et budgets comparables ; le présent travail approfondit le traitement des preuves à observations constantes.
- [Conservation des preuves et contexte](../2026-09-29-context-scalability/README.md) : contexte et récupération, distincts de la validité de la conclusion.
- [Couverture du benchmark](../2026-09-29-benchmark-coverage/README.md) : validité du corpus et contrôles sains.
- [Organisation du code](../2026-10-03-organisation-code/README.md) : responsabilités logicielles et refactoring.
- [Diagnostic du pipeline et des campagnes](../2026-10-05-corrections-lance/README.md) : observations historiques, distinctes de cette exploration.

## Points ouverts

- Vérifier l'indépendance des familles réservées à l'évaluation.
- Préparer et annoter les dossiers d'observations et leurs contrôles sains.
- Geler le contrat de preuve après résolution des conflits par le travail propriétaire.
- Mesurer l'apport des relations explicites et d'une relecture indépendante sans affaiblir la référence à règles.
- Mesurer séparément le temps de relecture humaine avant d'annoncer une réduction du travail.
