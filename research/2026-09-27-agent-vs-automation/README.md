# Apport de l'agent face à l'automatisation

**Cycle de vie : Actif** (mise à jour du 2026-10-15) — catalogue et comparaison guidée livrés ; une paire exploratoire S1 complète, campagne et revue expérimentale des preuves à établir.

**Statut : implémentation guidée validée ; un résultat descriptif réel, aucune supériorité générale établie.**
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

Les documents historiques décrivent le protocole et ses premiers incréments
logiciels. Le complément du 15 octobre ci-dessous ajoute l'interface livrée et
une paire réelle S1 ; les autres systèmes et extensions du protocole restent proposés.

## Automatisations et comparaison guidée — 15 octobre 2026

**Dernière révision du complément : 2026-10-15 20:25
(Europe/Brussels, UTC+02:00).** Cette révision remplace la proposition statique
de 11:35 par un bilan de réalisation ; la provenance de cette revue initiale
et ses trois avis spécialisés est conservée dans le registre des sources.
Les autres rapports du dossier gardent leur date et leur périmètre historiques.

- [Rapport PDF](lancement-automatisations.pdf) · [source LaTeX éditable](lancement-automatisations.tex) :
  catalogue, lancement guidé, suivi, historique, protocole, corrections et résultats ; huit pages.
- [Registre des sources et validations](lancement-automatisations-sources.json) :
  commits, empreintes du code, CI, revue initiale et relecture de cette version.
- [Agrégats des essais et provenance](lancement-automatisations-resultats.json) :
  paramètres, identifiants, empreintes des exports et métriques, sans grosses traces brutes.
- [Guide opérationnel de la comparaison](../../docs/benchmark/agent-vs-automation-campaign.md)
  et [journal de relecture](validation.md#automatisations-et-paire-s1-du-15-octobre-2026).

Le catalogue décrit quatre procédures intégrées : découverte, inventaire TCP,
audit par règles d'un scénario public et diagnostic hors ligne. L'historique
sépare les sorties opérationnelles des scores d'évaluation. Le parcours
« Comparer règles / LLM » réserve nato, restaure avant chaque méthode, vérifie
les playbooks et la surface TCP publique, puis conserve les audits, le nettoyage
et le résultat du comparateur existant. Il ne permet pas l'import libre de scripts.

La réalisation passe par `347451b` (catalogue/inventaire), `39a50ec` (effets et
états incomplets), `e64bd03` (historique), `38d8f26` (comparaison guidée),
`4547c91` (suivi visible), `711f966` (réservation jusqu'à finalisation) et
`b8a415a` (suppression des plafonds de coût et de durée dans ce seul parcours).
Le dernier essai a été lancé après la
[CI réussie de b8a415a](https://github.com/Tanguyvans/LANCE/actions/runs/38768357489) :
**3 972 tests réussis, deux ignorés, deux avertissements**. Les tests logiciels
simulent outils et modèles ; ils ne prouvent pas une performance en laboratoire.

L'inventaire réel `2026-10-15_123829_42ecb36bbe68` observe quatre hôtes et
dix services TCP. Son scénario n'étant pas enregistré dans l'artefact, aucun
score S1 ne lui est attribué.

La paire réelle complète
[`2026-10-15_165709_11c3405c5607`](http://100.103.253.86:8502/#comparison/2026-10-15_165709_11c3405c5607)
utilise S1, Qwen 3.8 27B via `ollama-umons`, les règles d'abord et 2 000 appels
maximum par audit, sans plafond de durée ni de coût. Les précontrôles ont la
même empreinte TCP ; les deux audits sont complets, le nettoyage réussi et
le comparateur ne signale aucun motif d'incomparabilité.

| Mesure des confirmations | Règles D1 | Qwen A1 |
| --- | ---: | ---: |
| Vrais positifs / faux positifs / failles manquées | 11 / 3 / 1 | 12 / 3 / 0 |
| Précision / rappel | 78,6 % / 91,7 % | 80,0 % / 100,0 % |
| F1 | 84,6 % | 88,9 % |
| Appels d'outils / erreurs | 73 / 0 | 132 / 0 |
| Durée des audits, hors préparation/nettoyage | 179,8 s | 1 239,9 s |

Les quatre tentatives précédentes restent décrites : accès modèle indisponible,
sélection erronée de MiniMax (exclue de l'évaluation Qwen), puis deux arrêts
pendant la vérification aux plafonds de 600 et 1 200 secondes. Aucun score absent
n'est remplacé par zéro. Le relais UMONS a été rétabli par l'opérateur ; sa
persistance après redémarrage n'a pas été qualifiée.

**Portée : une seule paire exploratoire.** Le F1 augmente ici de 4,3 points,
avec davantage de temps et d'appels ; aucun avantage général ni intervalle de
confiance n'est établi. Les contrôles de préparation ne certifient pas tout
l'état du laboratoire ; les preuves et la vérité terrain de cette paire
attendent une adjudication expérimentale indépendante. Les 1 029 775 tokens
conduisent à une estimation générique de 1,141787 USD : ce n'est pas une facture
UMONS et ce n'est pas une limite d'exécution.

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
comparables ?** Le complément du 15 octobre rapporte un contraste descriptif S1,
sans établir de gain général. Ces codes
identifient des variantes du protocole, pas des scores.

## Documents et sources

- **[Rapport principal — PDF](report.pdf)** : synthèse des trois axes, comparaisons, règles de décision et limites ; révision horodatée ci-dessus.
- **[Source LaTeX éditable](report.tex)** : document autonome, avec figures TikZ et bibliographie intégrées ; support des prochaines retouches.
- [Recentrage et structuration (2026-10-12)](../2026-10-12-recentrage-corpus/README.md) : proposition conditionnelle, état des lieux plateforme et structuration du corpus, déplacés dans leur propre dossier daté.
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

## Relecture de la structuration du corpus du 12 octobre 2026

Rapport relu le 2026-10-12 par un sous-agent distinct (source + 5 pages PDF) :
aucun bloquant, quatre mineurs corrigés puis recompilés (définitions H0-H3 et
S4h ajoutées, maturité EC1/EC2 contre EC3/EC4 précisée, flèche directe
Horizon 1 vers Horizon 2 supprimée au profit de la porte de décision,
colonnes du tableau 1 élargies). Ne constitue ni validation logicielle ni
validation expérimentale.

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
