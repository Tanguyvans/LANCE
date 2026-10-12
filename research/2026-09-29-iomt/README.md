# Spécialisation IoMT

**Statut : proposition de sujet de TFE.** Date initiale non renseignée dans la
proposition ; dossier organisé le 29 septembre 2026.
Le préfixe `2026-09-29` est donc la date de classement, pas une date de début
de recherche établie ; il reste fixe lors des révisions.

**Dernière révision du rapport : 2026-10-01 10:23
(Europe/Brussels, UTC+02:00).** Relecture de la proposition et première
version LaTeX/PDF. La date initiale reste inconnue ; aucun résultat
expérimental n'est ajouté.

## Question et synthèse

Comment spécialiser LANCE pour l'audit de réseaux médicaux simulés, puis évaluer
les adaptations par rapport à la version IoT généraliste ? La proposition couvre
la découverte, la vérification, la priorisation et l'évaluation comparative.

Ce dossier décrit un travail envisagé et ses livrables attendus. Il ne démontre
ni la disponibilité des extensions proposées ni leur validation expérimentale.

## Documents

- **[Rapport courant — PDF](report.pdf)** : proposition revue, périmètre simulé,
  preuves, comparaison, limites et références primaires.
- **[Source LaTeX éditable](report.tex)** : document autonome et figure TikZ.
- [Proposition historique](subject.md) : note archivée, remplacée par le rapport.
- [Document Word historique](subject.docx) : conservé tel quel ; non corrigé
  ni rendu pendant cette relecture.

Le rapport distingue observations passives, requêtes actives et actions de
laboratoire modifiant un service. Les contrôles simulés n'établissent ni la
sûreté d'un dispositif médical réel ni l'aptitude à un déploiement hospitalier.
La priorisation clinique et le support BLE restent des propositions à valider.
Les extensions IoMT ne sont pas présentées comme déjà implémentées.

## Relecture du 1er octobre 2026

**Clarté et rendu vérifiés sur la version du rapport horodatée 2026-10-01 10:23
(Europe/Brussels, UTC+02:00).** Deux sous-agents distincts de l'auteur ont
relu le texte (`review_clarity`) et inspecté les pages rendues (`review_figures`).
Les remarques ont été corrigées, puis le texte et le PDF revérifiés. Aucune
réserve bloquante de clarté ou de mise en page ne reste dans le périmètre relu.
Les notes complémentaires et archives ne sont pas couvertes par ce verdict de
rendu. Cette relecture ne constitue pas une nouvelle validation expérimentale.

[Journal et empreintes des PDF relus](../2026-09-27-agent-vs-automation/validation.md#relecture-indépendante-du-1er-octobre-2026).

## Points ouverts et références

Préciser le périmètre des protocoles étudiés, compléter les sources et définir
le protocole d'évaluation avant d'entreprendre les extensions. La faisabilité
et les limites évoquées dans la proposition restent à vérifier.

Les [scénarios actuels](../../docs/benchmark/v1/scenarios.md) et le
[contrat d'évaluation](../../docs/benchmark/v1/evaluation.md) fournissent le point
de départ. Aucune documentation de référence spécifique à l'extension IoMT
n'est établie par cette proposition.
