# Apport de l'agent face à l'automatisation

**Cycle de vie : Actif** (inventaire du 2026-10-12) — protocole proposé, pilote et campagne à établir ; proposition de recentrage et état des lieux ajoutés le 2026-10-12.

**Statut : protocole proposé ; premier incrément logiciel documenté.**
Travaux documentés les 27 et 28 septembre 2026. Dossier organisé le 29 septembre
2026 ; ce classement n'ajoute aucune validation expérimentale.
Revue complémentaire le 29 septembre 2026 : inspection du code, sources
primaires et reproductions logicielles. Aucun résultat de campagne ajouté.
Le préfixe du dossier reprend la première date documentée de l'étude, le
27 septembre ; il reste fixe lors des révisions.

**Dernière révision du rapport : 2026-10-01 10:23
(Europe/Brussels, UTC+02:00).** Relecture de la clarté et du rendu : définitions, figures, tableaux et
pagination corrigés. Les constats et reproductions restent ceux de la revue
du 29 septembre 2026.

## Question et synthèse

À outils, observations et budgets comparables, quel bénéfice mesurable apporte
une politique LLM à un audit IoT automatisé par des règles ? L'étude distingue
interprétation, planification, adaptation et rédaction du rapport.

Les documents décrivent un premier incrément D1/A1 et sa validation logicielle
locale. Ils ne rapportent pas de résultat démontrant un avantage de l'agent en
laboratoire. Les autres systèmes et extensions du protocole restent proposés.

<a id="methodes-sans-llm"></a>

## Approfondissement : méthodes sans LLM et réponse au comité

**Début de cet approfondissement : 2026-10-07. Statut : recherche ciblée et
protocole proposé, contre-relecture documentaire achevée.** Il répond à la demande de tester des
méthodes plus simples avant de conclure à une plus-value des modèles de langage.
Le dossier historique et les rapports précédents conservent leurs dates ; cet
approfondissement ne leur attribue aucun nouveau résultat expérimental.

Trois agents ont étudié les outils déterministes, le raisonnement classique et
le programme d'expériences. Deux relecteurs distincts des auteurs ont challengé
la force des références, la comparabilité, les oracles, les coûts et les
conditions d'une conclusion favorable ou défavorable au LLM. Les corrections
ont été recompilées, puis les 35 pages finales inspectées indépendamment.

**Décision proposée :** commencer par une référence conditionnelle compétente
et des dossiers communs, avec routine et cas sains en premières expériences.
D1 existe déjà pour les phases 3–4 ; le lecteur à règles sur dossiers est un
adaptateur proposé, distinct de cette implémentation. SQL, une table de droits,
OPA/Cedar ou des contrôles de configuration ne sont ajoutés que si les pièces
et la propriété les justifient. Le gain du LLM reste à mesurer ; garder les
règles ou limiter le modèle à la restitution est une issue recevable.

Les livrables sont :

| Rapport | Lecture | Source éditable | Pages | Dernière révision |
| --- | --- | --- | ---: | --- |
| Synthèse et programme de décision sans LLM | [PDF](sans-llm.pdf) | [LaTeX](sans-llm.tex) | 8 | 2026-10-07 14:44 |
| Méthodes et outils classiques | [PDF](sans-llm-outils.pdf) | [LaTeX](sans-llm-outils.tex) | 9 | 2026-10-07 14:27 |
| Raisonnement relationnel, politiques et vérification | [PDF](sans-llm-raisonnement.pdf) | [LaTeX](sans-llm-raisonnement.tex) | 9 | 2026-10-07 14:28 |
| Comparateurs et fiches d'expériences | [PDF](sans-llm-experiences.pdf) | [LaTeX](sans-llm-experiences.tex) | 9 | 2026-10-07 14:43 |

Tous ces horodatages utilisent **Europe/Brussels, UTC+02:00**. Les six fiches
couvrent routine, cas sains/faible prévalence, autorisation, information répartie,
variations équivalentes et restitution humaine. Chacune indique données, oracle,
comparateurs, contrôles, mesures, coûts et conditions d'arrêt/poursuite.

- [Registre bibliographique consolidé](sans-llm-sources.json) : 29 lectures,
  27 URL primaires distinctes, sections réellement consultées et limites ; ce
  nombre n'est pas un nombre d'articles ni une preuve d'exhaustivité.
- Registres spécialisés : [outils](sans-llm-outils-sources.json),
  [raisonnement](sans-llm-raisonnement-sources.json),
  [expériences et empreintes du code](sans-llm-experiences-sources.json).
- [Objections, corrections et empreintes finales relues](validation.md#relecture-sans-llm-2026-10-07) :
  contre-revue des méthodes terminée à 14:34, des expériences à 14:45 et de la
  synthèse à 14:46, le 7 octobre 2026, dans le même fuseau.

Les points ouverts sont l'éligibilité des données, l'oracle indépendant, la
compétence de la référence, l'indépendance des familles, les marges utiles et
l'effectif. Les coûts et compatibilités des outils restent non mesurés.
Aucune comparaison réelle, supériorité ou équivalence n'est établie par la
préparation de ces documents ; aucun run de laboratoire n'a été ajouté.

## Que signifient D1 et A1 ?

Ce sont les identifiants des deux politiques comparées dans l'étude :

- **D1 — automatisation conditionnelle sans LLM** (`rules`) : des règles
  programmées choisissent les contrôles et les suites à donner aux observations,
  avec des reprises bornées. Elle peut donc réagir à un résultat sans IA.
- **A1 — agent adaptatif avec LLM** (`llm`) : le modèle participe aux décisions
  et peut les réviser à partir des réponses des outils.

Les deux partent du même inventaire public et utilisent le même scanner initial.
La comparaison actuelle porte sur les phases 3 et 4 (analyse et vérification),
avec un contrat de preuve commun. La question est : **les décisions du LLM
apportent-elles un bénéfice mesurable par rapport aux règles seules, à ressources
comparables ?** Aucun gain expérimental n'est encore établi. Ces codes
identifient des variantes du protocole, pas des scores.

## Documents et sources

- **[Rapport principal — PDF](report.pdf)** : synthèse des trois axes, comparaisons, règles de décision et limites ; révision horodatée ci-dessus.
- **[Source LaTeX éditable](report.tex)** : document autonome, avec figures TikZ et bibliographie intégrées ; support des prochaines retouches.
- **[État des lieux plateforme — PDF](etat-des-lieux-plateforme.pdf)** · [LaTeX](etat-des-lieux-plateforme.tex) : architecture à changer (6 chantiers), objectifs plateforme mesurables et métriques comportementales, feuille de route vers la décision du 2026-11-16. **Dernière révision : 2026-10-12 22:11 (Europe/Brussels, UTC+02:00). Statut : état des lieux et propositions, aucun résultat expérimental nouveau.** Consolidation de trois analyses parallèles du 2026-10-12 (architecture, objectifs, métriques).
- **[Proposition de recentrage — PDF](proposition-conditions.pdf)** · [LaTeX](proposition-conditions.tex) : question conditionnelle « sous quelles conditions A1 dépasse-t-il D1 ? », six conditions, hypothèses H0–H3 falsifiables, protocole apparié et critères d'arrêt/poursuite. **Dernière révision : 2026-10-12 21:25 (Europe/Brussels, UTC+02:00). Statut : protocole proposé, aucun résultat expérimental nouveau.** Recherche multi-agents (littérature, protocole, deux contre-revues) du 2026-10-12 ; relecture indépendante du PDF final consignée ci-dessous.
- [Protocole scientifique](protocol.md) : hypothèses, comparateurs, mesures et limites.
- [État de l'art ciblé](state-of-the-art.md) : références primaires, périmètre de lecture et implications méthodologiques.
- [Plan d'implémentation et suivi](implementation-plan.md) : lots logiciels, validations rapportées et travail restant.
- [Revue actuelle de l'apport LLM](analysis.md) : attribution au scanner/modèle, force de D1, indépendance, reproductibilité et décisions si le gain est absent.
- [Contre-revue et arbitrages](adversarial-review.md) : corrections GPT retenues et état de la demande Muse.
- [Validation du 29 septembre](validation.md) : commandes, environnement, résultats et limites.

Le rapport suit la [structure scientifique classique](../README.md#structure-scientifique-classique) :
résumé, sommaire cliquable, méthode, constats, limites, conclusion et références.

### Études liées et conservation des notes

- [Couverture du benchmark](../2026-09-29-benchmark-coverage/README.md).
- [Conservation du contexte](../2026-09-29-context-scalability/README.md).
- [Scripts de reproduction locale](../../benchmarks/experiments/research-review/README.md).

Nettoyage documentaire du 1er octobre 2026 : l'ancienne page de navigation
`research-review.md` est remplacée par ce README et le rapport principal ;
son historique reste dans Git. Les autres notes Markdown conservent le protocole
détaillé, les sources, le suivi logiciel ou les preuves complémentaires : elles
ne doivent pas être supprimées en bloc comme de simples copies du PDF.
Le rapport n'a pas été révisé lors de ce nettoyage.

## Relecture du 1er octobre 2026

**Clarté et rendu vérifiés sur la version du rapport horodatée 2026-10-01 10:23
(Europe/Brussels, UTC+02:00).** Deux sous-agents distincts de l'auteur ont
relu le texte (`review_clarity`) et inspecté les pages rendues (`review_figures`).
Les remarques ont été corrigées, puis le texte et le PDF revérifiés. Aucune
réserve bloquante de clarté ou de mise en page ne reste dans le périmètre relu.
Les notes complémentaires et archives ne sont pas couvertes par ce verdict de
rendu. Cette relecture ne constitue pas une nouvelle validation expérimentale.

[Journal et empreintes des PDF relus](validation.md#relecture-indépendante-du-1er-octobre-2026).

## Références opérationnelles

- [Contrat d'évaluation actuel](../../docs/benchmark/v1/evaluation.md).
- [Guide CLI D1/A1](../../docs/benchmark/agent-vs-automation-cli.md).
- [Guide de campagne](../../docs/benchmark/agent-vs-automation-campaign.md).
- [Manifestes et revue des preuves](../../benchmarks/experiments/policy-comparison/README.md).

## Relecture de la proposition du 12 octobre 2026

Proposition relue le 2026-10-12 par un sous-agent relecteur distinct de l'auteur,
sur la source LaTeX et les 8 pages du PDF rendu (vérification visuelle des pages,
figure 1 et tableau 1 inclus). Verdict initial : bloquant sur la définition de
strict-v3 à première occurrence et sur la cohérence des critères H0/H1/H2 ;
mineur sur les citations, un chiffre Fang et le placement du tableau 1.
Corrections appliquées puis PDF recompilé (8 pages, citations résolues) :
définitions ajoutées en section 1, critère de décision unique (borne inférieure
de l'intervalle à 95 % supérieure à delta après Holm), H2 réécrite en pentes par
bras, citations dans le corps, entrée Cybench ajoutée comme non relue,
tableau 1 en placement fixe. Cette relecture ne constitue ni validation
logicielle ni validation expérimentale.

## Points ouverts

Préparer et valider les conditions du pilote, fixer les seuils à partir du
développement et établir les résultats par une campagne explicitement autorisée.
L'indépendance du test et les variantes réellement déployables restent des
conditions à vérifier. Suivre le protocole et le plan liés ci-dessus pour le détail.
La proposition de recentrage ci-dessus ajoute : split par famille (et non par
scénario), génération procédurale de variantes déployables avec canaris, seuil
delta à calibrer sur le pilote, et décision d'extension aux phases 2 et 5
subordonnée à un écart en vrais positifs confirmés.
