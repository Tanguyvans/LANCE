# Évaluer l'apport de l'agent face à l'automatisation classique

**Statut : objectif de recherche retenu ; protocole proposé, 27 septembre 2026.**
Ce document prépare une comparaison ; il ne rapporte aucun résultat expérimental.
Un [premier incrément CLI D1/A1](../../docs/benchmark/agent-vs-automation-cli.md) implémente l'analyse,
la vérification et la comparaison d'une paire sur inventaire public commun.
Les autres systèmes et campagnes ci-dessous restent proposés.
Le [guide de campagne](../../docs/benchmark/agent-vs-automation-campaign.md) décrit l'extension D1,
le bilan de tous les essais et le modèle du pilote réduit à 24 exécutions.
Aucun run de laboratoire n'a été lancé pour cette analyse.
Le [contrat V1](../../docs/benchmark/v1/evaluation.md) reste la référence des mesures actuelles.

## 1. Objectif scientifique du projet

**Établir expérimentalement dans quelles conditions, dans quelle mesure et à
quel coût un agent fondé sur un modèle de langage améliore un audit de sécurité
IoT autorisé par rapport à une automatisation classique à règles bien conçue.**

Cet objectif porte sur la détection étayée, les faux positifs, l'adaptation à des
variantes indépendantes et la fiabilité d'exécution, à outils et budgets
comparables. L'évaluation doit isoler les apports de l'interprétation des
observations, de la planification initiale, des décisions adaptatives et de la
rédaction. Une réduction du travail humain nécessite une mesure dédiée.

L'hypothèse est qu'un modèle de langage peut améliorer certaines décisions
d'audit : interpréter des observations variables, proposer des hypothèses,
sélectionner des vérifications et réviser la suite selon les résultats.
Une absence de gain ou une dégradation constitue également un résultat utile.

Comparer plusieurs modèles dans LANCE répond à « quel modèle convient à cette
architecture ? ». Cela ne répond pas à « cette architecture bénéficie-t-elle
d'un modèle pour décider des actions ? ». Il faut une référence sans LLM.

L'automatisation classique peut déjà utiliser des conditions, un état partagé,
des reprises et des algorithmes de planification. Les
[workflows Nuclei](https://docs.projectdiscovery.io/templates/workflows/overview)
illustrent notamment l'enchaînement conditionnel et le transfert de données.
La référence principale doit exploiter ces capacités, sans être volontairement
affaiblie. Une victoire sur un script fixe seul serait une conclusion trop limitée.

Deux études doivent être distinguées :

- **Attribution** : mêmes outils, observations initiales, règles de preuve et
  contraintes ; seule la politique de décision étudiée change autant que possible.
- **Utilité pratique** : systèmes complets dans leurs configurations pertinentes,
  avec leurs coûts de développement, de maintenance et d'exploitation. Une
  différence porte alors sur les systèmes complets, pas seulement sur le LLM.

Les choix ci-dessous constituent notre proposition expérimentale. Les publications
citées motivent certaines précautions ; elles ne valident pas les performances
de LANCE.

## 2. Systèmes à comparer

| ID proposé | Système | Décisions pendant l'audit | Usage dans l'étude |
| --- | --- | --- | --- |
| D0 | Procédure fixe | Suite de sondes et paramètres issus de l'inventaire, ordre prédéfini | Référence simple, secondaire |
| D1 | Automatisation conditionnelle | Règles explicites, état partagé, extraction de données, reprises bornées et priorité définie | Référence principale sans LLM |
| D1-R | D1 avec rédaction par LLM | Strictement les mêmes décisions et résultats techniques que D1 ; rédaction après clôture | Isoler la qualité de restitution |
| A0 | Plan produit par LLM puis figé | Plan construit depuis un état initial commun ; branchements déjà écrits autorisés, sans révision par le modèle | Isoler l'apport d'une planification initiale |
| A1 | Agent adaptatif | Décisions révisées à partir des observations, dans les contraintes communes | Système étudié |

D1-R réutilise les artefacts techniques de D1. Il n'appelle pas de sonde et ne
modifie ni les hypothèses ni les confirmations. Ses scores techniques doivent
rester identiques : un écart signalerait une contamination de la mesure par le
rapport. Si l'on veut étudier une réinterprétation des hypothèses par LLM, il
faut une expérience différente, décrite plus bas.

D1 doit disposer des contrôles protocolaires pertinents, des règles métier
documentées et des mécanismes de reprise communs. Une lacune manifeste se corrige
sur le développement avant le gel. Consigner les heures consacrées aux règles
et aux prompts. Les connaissances préentraînées du LLM ne peuvent pas être
égalisées parfaitement : le contraste mesure l'apport de cette politique avec
ses connaissances, pas une faculté de raisonnement isolée de toute connaissance.

Un outil externe, par exemple Nuclei avec une configuration revue, pourra former
une référence pratique supplémentaire. Il faudra déclarer sa couverture IoT et
ses différences d'outils ; son résultat n'isolera pas l'effet causal du LLM.
Un planificateur classique plus avancé peut devenir nécessaire si les conclusions
prétendent dépasser la comparaison avec notre D1.

## 3. Hypothèses falsifiables et expériences

| Question | Comparaison | Situation expérimentale | Mesure et conclusion possible |
| --- | --- | --- | --- |
| H1 — Les contrôles routiniers ont-ils besoin du modèle ? | A1 / D1 | Services stables, contrôles connus | F1 final et coûts ; D1 peut être équivalent ou meilleur |
| H2 — L'agent résiste-t-il mieux à la variation ? | A1 / D1, avant/après variation | Présentation ou composition nouvelle, difficulté documentée | Variation de l'écart de F1 ; gain d'adaptation seulement si l'effet se maintient sur des variantes indépendantes |
| H3 — Le retour des outils améliore-t-il la décision ? | A1 / A0 | Obstacle ou information révélé après le plan initial | Objectifs étayés, F1, coût de reprise ; absence de gain remet en cause la boucle adaptative |
| H4 — Le LLM interprète-t-il mieux les observations ? | Interpréteur LLM / règles | Dossier d'observations strictement identique, sans nouveaux outils | Précision/rappel des hypothèses et attribution aux observations ; aucune preuve d'exploration autonome |
| H5 — L'agent utilise-t-il mieux les ressources ? | A1 / D1 | Plusieurs plafonds communs, fixés à l'avance | Qualité selon le temps, la charge de sondage et le coût ; le gain peut disparaître avec le coût du modèle |
| H6 — L'agent réduit-il le travail humain ? | A1 / D1, D1-R pour la restitution | Étude distincte avec auditeurs et tâches comparables | Temps actif, corrections et résultat contrôlé ; ne pas l'inférer des tokens ou de l'absence d'intervention |

Contraste principal proposé : **A1 contre D1 sur le F1 final des scénarios
positifs**, à budget de ressources fixé, avec faux positifs sur les contrôles
sains et taux de runs évaluables rapportés séparément. Fixer avant le test le
gain minimal utile, la dégradation maximale acceptable sur les contrôles et
les plafonds opérationnels. Ces seuils restent à calibrer sur le pilote de
développement ; aucun seuil arbitraire n'est présenté comme une exigence métier.

Pour H2, si la variante conserve les mêmes vulnérabilités et possibilités de
vérification, calculer par famille :

```text
avantage_reference = F1(A1, reference) - F1(D1, reference)
avantage_variante  = F1(A1, variante)  - F1(D1, variante)
effet_variation    = avantage_variante - avantage_reference
```

Présenter aussi les quatre scores : un effet relatif positif peut coexister
avec deux systèmes devenus inutilisables. Une modification de densité, de
population de failles ou d'accessibilité forme une autre strate ; elle ne doit
pas être décrite comme un simple changement de présentation.

## 4. Jeux d'expériences

Le [catalogue actuel](../../docs/benchmark/v1/scenarios.md) sert de base de développement. Un intitulé
de scénario ne constitue ni une validation du déploiement ni une capacité
démontrée. Les groupes suivants sont des catégories expérimentales à organiser.

| Groupe | Construction | Ce qu'il permet de tester |
| --- | --- | --- |
| Routine | S1 et contrôles de services connus | Performance de base ; situations favorables aux scripts |
| Faible prévalence | S14 et contrôles sains validés | Faux positifs, retenue et couverture sans présumer que tout est vulnérable |
| Sémantique applicative | S15 ; S16–S17 en extension | Autorisations et états applicatifs ; distinguer description de la politique et réponse observée |
| Variation de surface | Noms neutres, formats et ordre de champs variables, adresses ou paramètres compatibles | Robustesse aux changements qui conservent la propriété de sécurité |
| Recomposition | Relations nouvelles entre composants connus, définies avant le gel | Transfert d'une méthode au-delà d'une suite mémorisée |
| Retour inattendu | Une voie devient indisponible, une réponse exige un ajustement, une hypothèse est réfutée | Révision de décision ; mêmes conditions de perturbation pour chaque système |

Les variantes de surface doivent préserver l'information utile pour les deux
systèmes. Un renommage d'hôte seul est un contrôle de robustesse, pas une preuve
forte de généralisation. Une transformation illisible uniquement par le parseur
de D1 mesure d'abord une différence de parseurs. Il faut la distinguer des
expériences où tous reçoivent des observations structurées équivalentes.

Inclure des cas proches mais sécurisés : service joignable avec authentification
effective, contenu public non sensible, action correctement refusée. « Aucun
finding » ne mérite un crédit de contrôle sain que si l'analyse a effectivement
été menée selon le contrat d'évaluation.

Les perturbations doivent être reproductibles, dépendre de conditions externes
déclarées et ne pas favoriser un système par leur calendrier. Journaliser leur
activation. Une panne de laboratoire accidentelle ne devient pas rétrospectivement
un test de résilience. Une panne produite par les actions du système est un
résultat de celui-ci, pas une exclusion commode.

### Limites du générateur actuel

[scenario_alterations.py](../../src/benchmark/scenario_alterations.py) distingue
des transformations d'aperçu, dont `rotate_ports`, `service_availability`,
`tool_output_profile` et `failure_mode`. Leur déclaration ne prouve pas leur
exécution en laboratoire. Les autres transformations restent soumises aux
capacités du fournisseur de déploiement et à ses validations.

Chaque variante expérimentale nécessite une correspondance vérifiée entre
spécification, services déployés, sondes et vérité terrain. Modifier seulement
le YAML, les preuves attendues ou les étiquettes de failles n'est pas une
expérience sur l'adaptation réelle. Les mesures sur observations enregistrées
restent clairement identifiées comme expériences hors ligne.

### Indépendance du test

S20–S29 sont publics et leur indépendance historique reste non vérifiée.
Ils ne suffisent pas à établir une nouvelle généralisation. Préparer un corpus
distinct réservé au test, avec familles ou recompositions non utilisées pour
choisir les règles, prompts, outils et budgets. Séparer par famille d'origine,
pas seulement par fichier ou graine. Des variantes d'un même scénario restent
apparentées. Documenter également les familles techniques communes aux deux jeux.

Les auteurs des contrôleurs n'accèdent pas à la vérité terrain de ce nouveau
corpus avant le gel. L'entrée publique ne doit pas révéler le statut vulnérable
via les noms, descriptions de scénario ou objectifs détaillant la solution.
Conserver le mode avec topologie fournie et le mode de découverte aveugle dans
des expériences distinctes. La mémoire inter-runs reste désactivée en benchmark.

## 5. Conditions d'une comparaison équitable

Pour l'étude d'attribution, conserver un exécuteur, une politique de périmètre,
des journaux et un validateur de preuves communs. Partager le catalogue d'outils,
ses versions et ses contraintes de paramètres. Ne pas attribuer au modèle le
gain d'une sonde disponible uniquement pour son groupe.

Une référence à règles peut utiliser toute information observable autorisée,
mais aucun identifiant de scénario pour sélectionner la solution, aucune vérité
terrain ni aucun artefact privé de préparation. Les mêmes restrictions valent
pour l'agent. Les mécanismes automatiques de secours doivent être partagés ou
déclarés comme facteurs distincts ; leurs actions et coûts restent comptés.

Geler le modèle et sa version accessible, les paramètres d'échantillonnage,
les prompts, compétences, règles Python, outils, limites, dépendances et état du
code. Le SHA Git seul ne suffit pas si le checkout est modifié. Le manifeste
actuel de prompts ne couvre que certains fichiers : enregistrer aussi les
règles et ressources effectivement utilisées, ainsi que le diff local éventuel.

Prévoir plusieurs vues de budget, sans mélanger leurs conclusions :

- Temps écoulé maximal commun, incluant les décisions du modèle et les reprises.
- Charge de sondage commune : appels, plages de ports, cibles et limites de débit.
  Un appel Nmap pouvant encapsuler de nombreuses sondes, le nombre d'appels seul
  ne mesure pas toute la charge réseau.
- Coût d'exploitation total observé : modèle et calcul, avec hypothèses de prix.
  Zéro token ne signifie pas zéro coût. Distinguer coût marginal et coûts fixes.

Conserver les budgets financiers propres aux fournisseurs pour éviter les
dépassements, mais ne pas faire d'un budget de tokens commun une contrainte
artificielle sur un système sans LLM. Séparer temps d'audit et de rapport, puis
afficher également le temps complet jusqu'au livrable utilisable. Les temps de
préparation et de nettoyage sont enregistrés à part.

Réinitialiser le laboratoire entre essais, appliquer le même état initial dans
chaque paire et varier l'ordre des systèmes par blocs. Les expériences en
laboratoire restent séquentielles tant que l'isolation complète n'est pas
validée. Une même graine de génération ne garantit pas une réponse LLM identique.

## 6. Mesures et présentation des résultats

Réutiliser les définitions du [contrat de preuves](../../docs/benchmark/v1/evaluation.md), sans
créer de score global mélangeant détection, intrusion, rapidité et style.

| Dimension | Mesure | Disponibilité / travail nécessaire |
| --- | --- | --- |
| Détection étayée | Précision, rappel, F1 final, VP/FP/FN | Présents dans l'évaluateur ; même contrat pour chaque système |
| Contrôles sains | Spécificité par scénario, violations des contrôles | Présents sous conditions de complétude ; ne pas créditer un run vide ou inexploitable |
| Preuves | Acceptées, rejetées, manquantes ; raisons | Présentes ; distinguer une affirmation sans preuve d'un résultat étayé hors référentiel |
| Fiabilité d'exécution | Statuts, couverture d'évaluation, causes terminales | Présents ; nécessaires même si un run partiel a un bon F1 |
| Ressources | Coût, temps écoulé, tokens, appels et erreurs | Présents en partie ; normaliser leur collecte sans LLM, compléter la charge réseau |
| Progression | Temps et coût jusqu'aux premiers VP, courbe de VP vérifiés | À dériver avec des événements horodatés et une règle d'attribution testée |
| Adaptation | Effet de variation, objectifs après perturbation | Nouvelle analyse expérimentale ; pas un score actuel |
| Utilité des actions | Reprises, duplications injustifiées, information acquise | Annotation ou instrumentation à ajouter ; une sonde négative peut être utile |
| Intrusion | Accès et objectifs corroborés | Séparés du F1 ; limites actuelles sur les transitions réseau |
| Travail humain | Temps actif, corrections, maintenance | Étude et journal dédiés ; actuellement non démontré |

Les ratios coût/VP restent indéfinis lorsque VP = 0. Les exécutions concernées
restent visibles, avec leur coût. Pour comparer à qualité constante, fixer sur
le développement un objectif de rappel et un minimum de précision ; traiter
« objectif non atteint avant le plafond » explicitement, pas comme une durée
manquante à éliminer. Une courbe de compromis complète est préférable à un seul
ratio choisi après observation des résultats.

Une « action utile » ne signifie pas nécessairement un test positif. Un test
négatif peut éliminer une hypothèse et éviter plusieurs actions. Une repetition
peut être justifiée par un changement d'état. Ne pas transformer des heuristiques
de déduplication en jugement automatique sur la qualité du raisonnement.

La causalité des pivots réseau n'est pas attestée actuellement. Des connexions
directes multiples, la profondeur d'une faille ou une chaîne écrite par le modèle
ne démontrent pas un pivot. Reporter les expériences multi-hop probantes jusqu'à
la disponibilité d'une attestation de l'origine, de l'accès et de la transition.

Présentation attendue, avec données réelles uniquement : tableau par famille et
budget, écarts appariés A1–D1, courbes qualité/coût, effet des variations et quelques
trajectoires vérifiées. Les cas illustratifs comprennent aussi des victoires de
D1 et des échecs de A1 ; ils expliquent les agrégats sans les remplacer.

## 7. Répétitions, données manquantes et analyse

Déclarer à l'avance les essais prévus. Commencer le pilote avec trois répétitions
par configuration pour détecter les problèmes de collecte, sans prétendre que
trois essais suffisent à conclure. Dimensionner ensuite l'évaluation finale à
partir de la variabilité de développement et du gain minimal utile choisi.
Des répétitions d'un même scénario ne remplacent pas de nouvelles familles.

Moyenner les répétitions dans une variante, puis les variantes dans leur famille.
Donner le même poids aux familles dans l'analyse proposée pour éviter de multiplier
artificiellement le poids d'une topologie. Cette analyse supplémentaire ne change
pas l'agrégation officielle existante par scénario et par groupe dev/test.

Pour l'écart principal, conserver les paires de systèmes sur les mêmes instances.
Estimer des intervalles de confiance à 95 % par rééchantillonnage apparié des
familles, en préservant leur structure interne ; publier le nombre de familles
indépendantes et la sensibilité aux répétitions. Sur peu de familles, ces
intervalles sont fragiles et la généralisation reste descriptive. Ce choix devra
être vérifié sur le schéma de données définitif ; les principes de sélection de
tests sont discutés par [Dror et al., ACL 2018](https://aclanthology.org/P18-1128/).

Publier l'amplitude des écarts et les résultats par famille. Déclarer les analyses
secondaires exploratoires ; si plusieurs tests confirmatoires sont retenus,
prévoir leur correction de multiplicité avant d'observer le jeu final. Ne pas
sélectionner le meilleur essai, ni arrêter la campagne quand un résultat devient
favorable. L'absence de différence significative ne prouve pas l'équivalence.

Une donnée absente reste absente dans les mesures officielles. Rapporter les
essais prévus, exécutés, évaluables et non évaluables, par système et par cause.
Le contraste sur paires évaluables doit être accompagné d'une analyse de
sensibilité aux échecs et à la sélection des paires ; un meilleur score parmi
les seuls survivants ne suffit pas à démontrer un meilleur service.

Un environnement invalide avant toute action est une erreur de préparation,
distincte d'un échec du système. Une perturbation prévue, une mauvaise action
ou l'épuisement du budget font partie de l'expérience. Fixer les règles de
reprise avant la campagne et conserver coûts et artefacts de chaque tentative.
Si un indicateur supplémentaire de réussite opérationnelle est défini, son
dénominateur et le traitement de chaque cause doivent être explicites ; il ne
remplace pas le F1 et ne transforme pas rétroactivement un `null` en zéro.

## 8. Isoler les mécanismes sans surinterpréter

H4 utilise des dossiers d'observations gelés, identiques et sans vérité terrain
visible. Comparer les hypothèses des règles et du modèle avec le même évaluateur.
Un gain établit une meilleure interprétation sur ces données ; il ne démontre
pas que l'agent aurait collecté les observations nécessaires en autonomie.

A0 et A1 reçoivent un préfixe de reconnaissance identique pour l'expérience H3.
Le plan A0 peut contenir des branchements, mais aucune nouvelle décision du
modèle après son gel. Les outils et reprises techniques restent identiques.
Le coût des appels supplémentaires de A1 est compté. Exécuter les deux suites
sur des états réinitialisés : rejouer la trace de A1 à A0 ne constitue pas un
environnement interactif valide lorsque leurs actions diffèrent.

Étudier séparément le retrait du contexte partagé ou des guidages spécifiques,
une fois la comparaison principale opérationnelle. Ne pas changer simultanément
modèle, profil full/compact, outils et budget pour attribuer le résultat à la
mémoire ou à la planification. Ces ablations diagnostiques peuvent réduire
artificiellement la qualité du système et ne remplacent pas D1.

Le journal doit relier chaque action à ses observations disponibles, à la source
de décision (règle, modèle ou secours) et à son résultat. Une brève justification
déclarée peut aider la revue, mais elle n'est ni une preuve ni une observation
fiable des mécanismes internes du modèle. Aucune chaîne de pensée privée n'est
nécessaire à l'évaluation.

Pour la restitution et le temps humain, prévoir une revue aveugle de rapports
comparables, une grille commune et un ordre contrebalancé afin de limiter
l'apprentissage des cas par les auditeurs. Mesurer corrections et qualité en
plus de la durée. Sans cette étude, conclure seulement sur l'automatisation
observée, pas sur les heures économisées.

## 9. Intégration à prévoir dans LANCE

La lecture du code montre les points d'appui et les écarts suivants :

| Élément actuel | Conséquence pour l'implémentation |
| --- | --- |
| [Pipeline par phases](../../src/agent/phases/README.md) et sondes existantes | Réutiliser exécuteur, sécurité et preuves ; introduire une sélection explicite de politique sans dupliquer six pipelines |
| [Règles d'analyse](../../src/agent/phases/analysis/prompts.py) et [contrat de vérification](../../src/agent/phases/verification/contract.py) | Inventorier les connaissances déjà codées, construire D1 et documenter la parité de couverture ; ne pas confondre guidage et preuve |
| [Évaluateur](../../src/benchmark/evaluator.py) | Conserver les exigences sémantiques ; adapter explicitement les artefacts des politiques sans LLM avec leur vraie provenance |
| [Identité de configuration](../../src/benchmark/comparability.py) | Le schéma expérimental accepte un modèle/fournisseur nul pour `rules` et distingue politique, périmètre, limites et instrumentation |
| [Agrégation](../../src/benchmark/aggregate.py) | Agrégation interne conservée ; [comparaison d'une paire](../../src/benchmark/compare_policies.py) et [bilan de campagne](../../src/benchmark/policy_campaign.py) distincts, intervalles par famille restant à faire |
| [Manifestes](../../src/agent/audit_experiment.py) | Empreinte des ressources Python, prompts, compétences, outils et état local sous `src/agent` / `src/benchmark` ; binaires et état du laboratoire à contrôler séparément |
| [Altérations](../../src/benchmark/scenario_alterations.py) et [fournisseurs](../../src/benchmark/manual_execution.py) | Refuser une campagne réelle si une variation demandée n'est disponible qu'en aperçu |

Ne pas fusionner les runs D1 et A1 dans une même moyenne de configuration. Ils
doivent différer par leur identité de système tout en partageant le même contexte
expérimental. L'identité autorisant une moyenne interne et la clé autorisant une
comparaison entre groupes sont deux concepts distincts.

Prévoir dans un manifeste de campagne versionné : protocole, système et politique,
famille/variante/répétition, bloc et ordre d'exécution, budgets, entrée publique,
empreintes de l'environnement et de l'état initial, versions des preuves et
métriques, configuration du modèle lorsqu'il existe, causes d'échec et provenance
des artefacts. La graine ou l'identité privée de scénario utile à l'évaluateur
ne doit pas devenir un indice livré au contrôleur.

Ce manifeste est une proposition de schéma ; aucun nouveau flag CLI n'est supposé
exister. Toute évolution incompatible des métadonnées ou des métriques devra
être versionnée et testée, sans rendre compatibles les anciens runs par défaut.

L'évaluateur partage actuellement certaines règles sémantiques avec le pipeline.
Compléter ses contrôles par une revue aveugle de traces sélectionnées selon un
plan fixé, couvrant succès, rejets, contrôles et observations hors référence.
Une erreur commune au producteur et à l'évaluateur peut sinon passer inaperçue.
Les résultats effectivement étayés hors référence doivent être examinés selon
une procédure commune ; ne pas corriger la vérité terrain uniquement pour le
système préféré.

## 10. Ordre de réalisation et livrables

Le [plan d'implémentation](implementation-plan.md) détaille le
premier incrément D1/A1, les dépendances et les critères de validation logiciels.

1. **Protocole et inventaire** : fixer les hypothèses, la référence D1, les
   ressources communes et les règles de comparaison. Le présent document est
   le premier livrable ; les budgets et seuils finaux restent à calibrer.
2. **Pilote logiciel** : implémenter D0/D1, les métadonnées et la comparaison
   hors ligne ; valider sur fixtures les contrôles sains, preuves mal attribuées,
   budgets épuisés, runs manquants et groupes incompatibles. Tester l'invariance
   des scores techniques D1/D1-R.
3. **Pilote de laboratoire de développement** : proposition initiale S1, S14,
   S15 et un contrôle sain vérifié, avec D0/D1/A1 et trois répétitions, soit
   36 essais planifiés. Ce volume est indicatif, sans estimation de coût validée
   et sans autorisation d'exécution implicite. Il sert à valider la mesure.
   La première étape retenue utilise seulement D1/A1 : **24 exécutions prévues**,
   décrites dans le [modèle de campagne](../../benchmarks/experiments/policy-comparison/README.md).
4. **Expériences de mécanisme** : observations gelées, A0/A1 et premières
   variantes réellement prises en charge. Déterminer le budget et le nombre de
   familles/répétitions de l'évaluation finale sur ce développement.
5. **Gel et évaluation indépendante** : figer contrôleurs, règles, prompts,
   outils, métriques, comparaisons principales et taille de campagne ; utiliser
   le nouveau corpus sans ajustement sur ses résultats.
6. **Restitution** : publier écarts, incertitudes, coûts, couverture d'évaluation,
   limites et exemples vérifiés ; conserver les conclusions défavorables à l'IA.

Les runs et déploiements nécessitent une demande explicite selon le guide du
dépôt. La création de ce protocole n'en exécute aucun.

Une conclusion admissible prendra la forme : « Sur telles familles indépendantes,
avec tels outils et budgets, la politique adaptative obtient tel écart mesuré
face aux règles, avec tel coût et telles limites. » Si l'avantage n'apparaît que
dans la rédaction ou disparaît face à D1, il faudra limiter la revendication
en conséquence. Une victoire sur D1 ne démontre pas une supériorité sur toute
forme d'automatisation classique.

## 11. Appuis bibliographiques et portée

L'[état de l'art ciblé du 28 septembre 2026](state-of-the-art.md)
complète ces appuis avec les benchmarks de pentest, les références sans LLM et
les travaux IoT, en distinguant résultats publiés et recommandations pour LANCE.

- [ReAct, ICLR 2023](https://arxiv.org/abs/2210.03629) étudie l'alternance entre
  décisions et actions. Cette architecture motive H3, sans établir un gain
  pour notre audit IoT.
- [PentestGPT, USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/deng)
  étudie l'assistance au test d'intrusion et les difficultés de contexte. Ses
  comparaisons ne remplacent pas notre référence sans LLM.
- [Demystifying evals for AI agents, Anthropic, 2026](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents)
  distingue essais, trajectoires et états finaux, et discute les évaluateurs
  déterministes, humains et fondés sur un modèle. Ici, le résultat technique
  reste lié aux traces et critères de preuve ; un jugement LLM sur la qualité
  d'un texte ne certifie pas une vulnérabilité.
