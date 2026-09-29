# Apport de l'agent face à l'automatisation

**Statut : protocole proposé ; premier incrément logiciel documenté.**
Travaux documentés les 27 et 28 septembre 2026. Dossier organisé le 29 septembre
2026 ; ce classement n'ajoute aucune validation expérimentale.
Revue complémentaire le 29 septembre 2026 : inspection du code, sources
primaires et reproductions logicielles. Aucun résultat de campagne ajouté.
Le préfixe du dossier reprend la première date documentée de l'étude, le
27 septembre ; il reste fixe lors des révisions.

## Question et synthèse

À outils, observations et budgets comparables, quel bénéfice mesurable apporte
une politique LLM à un audit IoT automatisé par des règles ? L'étude distingue
interprétation, planification, adaptation et rédaction du rapport.

Les documents décrivent un premier incrément D1/A1 et sa validation logicielle
locale. Ils ne rapportent pas de résultat démontrant un avantage de l'agent en
laboratoire. Les autres systèmes et extensions du protocole restent proposés.

## Documents et sources

- **[Rapport principal — PDF](report.pdf)** : synthèse des trois axes, comparaisons, règles de décision et limites ; version du 29 septembre 2026.
- **[Source LaTeX éditable](report.tex)** : document autonome, avec figures TikZ et bibliographie intégrées ; support des prochaines retouches.
- [Protocole scientifique](protocol.md) : hypothèses, comparateurs, mesures et limites.
- [État de l'art ciblé](state-of-the-art.md) : références primaires, périmètre de lecture et implications méthodologiques.
- [Plan d'implémentation et suivi](implementation-plan.md) : lots logiciels, validations rapportées et travail restant.
- [Revue actuelle de l'apport LLM](analysis.md) : attribution au scanner/modèle, force de D1, indépendance, reproductibilité et décisions si le gain est absent.
- [Navigation dans la revue](research-review.md) : rapports, notes détaillées et état des contre-revues.
- [Contre-revue et arbitrages](adversarial-review.md) : corrections GPT retenues et état de la demande Muse.
- [Validation du 29 septembre](validation.md) : commandes, environnement, résultats et limites.

Le rapport suit la [structure scientifique classique](../README.md#structure-scientifique-classique) :
résumé, sommaire cliquable, méthode, constats, limites, conclusion et références.

## Références opérationnelles

- [Contrat d'évaluation actuel](../../docs/benchmark/v1/evaluation.md).
- [Guide CLI D1/A1](../../docs/benchmark/agent-vs-automation-cli.md).
- [Guide de campagne](../../docs/benchmark/agent-vs-automation-campaign.md).
- [Manifestes et revue des preuves](../../benchmarks/experiments/policy-comparison/README.md).

## Points ouverts

Préparer et valider les conditions du pilote, fixer les seuils à partir du
développement et établir les résultats par une campagne explicitement autorisée.
L'indépendance du test et les variantes réellement déployables restent des
conditions à vérifier. Suivre le protocole et le plan liés ci-dessus pour le détail.
