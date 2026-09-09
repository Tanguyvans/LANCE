# Audit de fond et proposition de refonte — 8 septembre 2026

> Instantané de l'audit initial. Consulter le [suivi des corrections](SUIVI.md)
> pour distinguer les constats historiques des changements réalisés ensuite.

## Conclusion

Une refonte est justifiée, mais pas une réécriture de toute l'application.
Le problème principal n'est plus le nombre de fichiers : plusieurs composants
ne donnent pas le même sens à « prouvé », « compromis », « pivot » et « terminé ».
Déplacer leurs fonctions conserverait les mêmes erreurs.

La cible proposée est **un moteur, des observations fidèles, des validations
explicites, deux évaluations indépendantes : audit et intrusion**. Les profils
compact/full adaptent le dialogue, les budgets et les outils proposés ; ils ne
changent ni la vérité d'une preuve ni la frontière réseau autorisée.

Ce document et les reproductions sont les seuls ajouts de cet audit. Le moteur,
les scénarios et la production ne sont pas modifiés. La question de validation
de la refonte avant implémentation a été posée ; aucune réponse n'était reçue à
la rédaction. Aucun appel LLM, scan réseau, déploiement ou push n'a été lancé.

## Périmètre et méthode

- Base : branche `main`, HEAD `1fe9962`, **avec les modifications non commitées
  déjà présentes**. Le SHA seul ne décrit donc pas l'état audité.
- Revue des chemins critiques : orchestration, analyse/agrégation, vérification,
  intrusion, attribution des preuves, métriques, outils, budgets, scénarios,
  API, rendu benchmark, configuration de construction/déploiement.
- Inventaire AST : 42 327 lignes Python dans 120 fichiers sous `src/`.
- Suite existante : **1 317 tests passent, 4 ignorés**, en 202,77 s.
- Compilation de `src/` et `git diff --check` : aucun problème relevé.
- Batterie contradictoire ajoutée : **28 cas échouent et 5 contrôles passent**.
  Ce sont 28 variantes d'invariants à garantir, **pas 28 bugs indépendants**.
  Certains exposent une erreur de résultat ; d'autres une protection absente
  ou un choix de conception à rendre explicite.
- Réponses réseau entièrement simulées, adresses de documentation, base
  fournisseurs simulée en mémoire ; aucun secret réel n'est utilisé.

Limites : ce n'est pas une preuve d'absence de tout autre défaut, ni une lecture
exhaustive de chaque fonction. L'ACL Tailscale, les permissions systemd du
mini-PC, les routes/firewalls réels, les performances à grande échelle et les
providers réels restent à vérifier séparément. Aucun oracle de test n'a été
utilisé pour adapter le harness. Le PDF LLMDFA n'a pas été relu dans cet audit.

## 1. Défauts et protections manquantes reproduits

P1 : intégrité des résultats ou frontière d'exécution. P2 : fiabilité de
l'expérience ou de sa lecture. Les numéros R correspondent aux familles des
tests de `contract_regressions.py`.

| ID | Priorité | Constat actuel | Conséquence / correction de principe |
| --- | --- | --- | --- |
| R1 | P1 | Une requête sur la mauvaise IP, le mauvais port ou le mauvais chemin obtient un VP final si les métadonnées de la faille portent la cible attendue. | L'action réellement exécutée doit primer sur le contexte du candidat. Trois variantes reproduites : VP=1 et F1=1 au lieu de VP=0. |
| R2 | P1 | Une IP citée dans le corps d'une réponse peut servir à attribuer cette réponse à la cible. | Une valeur trouvée dans le contenu n'est pas la destination de la requête. |
| R3 | P2 | Deux enregistrements partageant une référence peuvent transférer une preuve entre cibles. | Refuser les identifiants dupliqués ; conserver le lien avec l'enregistrement exact, pas seulement une chaîne de caractères. Le logger crée normalement des UUID : ce cas concerne surtout un artefact corrompu ou modifié. |
| R4 | P1 | En full, HTTP 200 ou un ACK TCP suffit au compteur de cibles compromises ; un `success=true` SSH contradictoire avec un retour 1 est aussi accepté. | Séparer contact de service, authentification, lecture, exécution et contrôle ; ne pas changer leur sens selon le profil. |
| R5 | P1 | Deux connexions SSH directes indépendantes + une chaîne déclarée A→B donnent un pivot vérifié. Même résultat en inversant l'ordre des connexions. | Exiger la provenance causale de l'action depuis A, et une capacité A établie avant l'action vers B. |
| R6 | P1 | Un login SSH ou une bannière Telnet peut confirmer `data_exposure` ; une requête MySQL authentifiée ou un HTTP avec Authorization peut confirmer `no_auth`. Un ACK TCP peut aussi confirmer une fuite de données. | Le succès d'un outil ne prouve pas toute propriété. Validation par type de revendication et par contexte d'authentification. Cinq variantes reproduites. |
| R7 | P1 | Les tokens/coûts d'une phase active ne figurent pas dans les totaux. | Compter l'usage à réception ; réserver les budgets avant les opérations. Le plafond USD actuel n'est contrôlé qu'après une phase entière. |
| R8 | P2 | Deux abonnés SSE consomment la même file ; le second peut ne pas recevoir l'événement reçu par le premier. | Diffusion à chaque abonné, avec événements identifiés et reprise ; pas une file de travail partagée. |
| R9 | P2 | Un outil qui retourne un dictionnaire est journalisé via `str(dict)`, pas en JSON structuré. | Garder l'objet ou sérialiser en JSON ; distinguer texte opaque et données structurées. |
| R10 | P1 | Le même appel hors périmètre atteint l'exécuteur simulé en phase 2/4 compact et en phase 5 full. Il est bloqué en phase 5 compact. | Une frontière d'autorisation commune à tous les appels. Une restriction d'outils/prompt ne remplace pas cette frontière. |
| R11 | P1 | Une erreur d'écriture du journal est silencieuse et l'outil peut retourner un succès. | Le run doit devenir explicitement non vérifiable/partiel ; ne pas continuer à présenter ses preuves comme intègres. |
| R12 | P2 | L'agrégateur accepte plusieurs modèles/profils/modes blind sous le même scénario sans garde de comparabilité. | Protection absente, pas preuve qu'un appelant les mélange aujourd'hui : figer l'identité d'expérience ou imposer un regroupement explicite. |
| R13 | P2 | `macro_verified_f1` vaut 1 avec un essai parfait et un essai non évaluable ; ce dernier disparaît de cette moyenne. | Le nouveau funnel conserve correctement l'indisponibilité, mais les champs historiques restent divergents. Ne pas publier une moyenne partielle sans dénominateur. |
| R14 | P2 | Le statut affiché est `done` avec un rapport présent et `run_meta.status=failed`. | Utiliser l'état terminal produit par le moteur ; présence d'un Markdown ≠ réussite. |
| R15 | P1 | Deux messages MQTT ayant les mêmes clés JSON mais des valeurs différentes : le second est remplacé par le premier. | Supprimer cette réécriture de la preuve. Une compression destinée au prompt doit être une projection séparée. |
| R16 | P1 conditionnel | Une modification de provider sans authentification renvoie 200 dans l'application réelle, avec DB simulée. | Toute personne pouvant joindre l'API peut utiliser ses routes non protégées. L'exposition effective dépend du réseau/proxy, non vérifiés ici. |
| R17 | P2 | Des tokens disponibles sont masqués si les compteurs de validation de format sont incomplets. | Disponibilité par métrique, pas un indicateur global pour toute la consommation. Reproduit sur la fonction JS réelle. |

### Localisation des causes

- R1–R3 : `src/benchmark/evaluator.py:1359`, `:1515`, `:1585`.
  `src/agent/core/runner.py:604` ajoute le contexte de la vulnérabilité au journal,
  ce qui rend R1 pertinent pour de vraies traces, pas seulement des JSON inventés.
- R4–R5 : `src/benchmark/evaluator.py:990`, `:1047`, `:1228`.
  `src/agent/phases/intrusion/run.py:420` synthétise aussi des chaînes depuis
  les indices du contexte et des actions individuelles, sans preuve de causalité.
- R6 : `src/agent/exploit_evidence.py:176`, notamment `:402`, `:422`, `:434`.
- R7 : `src/agent/cost_tracker.py:203`, `src/agent/pipeline.py:517`.
- R8 : `src/api/routes/pipeline.py:334`, `:755`.
- R9–R11 : `src/agent/core/runner.py:608`, `:641`, `:665`.
- R12–R13 : `src/benchmark/aggregate.py:178`, `:290`, `:329`.
- R14 : `src/api/routes/runs.py:493`, contrairement à l'état déjà enregistré par
  `src/agent/pipeline.py:199`.
- R15 : `src/agent/tools/tool_loader.py:44`, `:228`, `:238`.
- R16 : `src/api/main.py:28`, `:36`, `src/api/routes/providers.py:49`.
- R17 : `src/static/app.js:2587`.

## 2. Problèmes structurels et scientifiques

### Un hop n'est pas encore défini de manière uniforme

`compute_mhr` (`evaluator.py:894`) calcule un rappel de vulnérabilités annotées
avec `hop_depth`, pas une preuve d'accès depuis un point de vue intermédiaire.
Dans le scénario **dev S15**, trois failles sur la même IP ont des profondeurs
1, 2 et 3 : il s'agit d'étapes d'autorisation applicative, pas de trois pivots
réseau. Les scénarios manuels disposent déjà de `semantics` et
`network_hop_depth`, mais l'évaluateur ne s'appuie pas sur ces champs.

Conséquence : même un rappel parfaitement calculé n'est pas une mesure fiable
de multi-hop réseau si l'annotation mélange ces deux notions. Garder les
séquences applicatives, mais leur donner leur propre dimension.

### La pipeline reste principalement linéaire

`pipeline.py:414` déroule les phases une fois. Une nouvelle capacité acquise
en intrusion ne possède pas de chemin général, explicite, pour rouvrir
reconnaissance → analyse → vérification depuis ce nouveau point d'accès.
La phase 5 compense avec sa propre logique et ses récupérations.

Il faut rendre l'enchaînement dépendant de **faits nouveaux**, sans créer trois
moteurs. Une action à répéter doit l'être parce que son contexte a changé, pas
parce qu'un livrable manque ou qu'un modèle reformule sa demande.

### Un objectif métier n'est pas un ensemble obligatoire de failles

Le score de chemins vérifiés combine encore le matching de failles et la
chaîne phase 5 (`evaluator.py`, calcul de `verified_attack_paths`). Cela ne
répond pas directement à « l'objectif a-t-il été atteint par une voie valide ? ».
Trouver toutes les ouvertures d'une machine et obtenir une capacité utile sont
deux résultats différents. L'un ne doit pas servir de substitut à l'autre.

`scenario_spec.py` valide le type liste/dictionnaire de `objectives` et
`evaluation`, mais pas un contrat exécutable générique d'objectif. Leur présence
dans un YAML n'implique pas que le moteur les exécute ou les vérifie.

### La frontière entre moteur, outils et évaluateur est insuffisante

- `python_exec` lance du Python avec les permissions du backend ; l'option `-I`
  et le timeout ne créent pas une isolation de fichiers/réseau.
- `ssh_login` accepte un `bash -c` libre. Le parseur de périmètre compact n'est
  pas une preuve générale de confinement d'un shell arbitraire.
- Les sorties peuvent être filtrées/tronquées dans le loader **avant** leur
  archivage ; le journal n'est donc pas toujours une copie brute de l'observation.
- Les traces publiques vivent avec les artefacts manipulables dans le contexte
  du run. Un évaluateur qui les relit ne devient pas automatiquement un témoin
  indépendant. Le worker sealed a des protections utiles de séparation d'oracle,
  mais cette propriété ne doit pas être présumée pour tous les modes publics.
- Les routes de lecture/export peuvent exposer les traces d'outils contenant
  credentials, en-têtes ou données sensibles. Il faut une vue expurgée et un accès
  restreint aux preuves brutes, sans détruire ces dernières.

À vérifier sur le mini-PC avant implémentation du confinement : utilisateur du
service, fichiers accessibles, séparation worker/API, règles réseau et droits
nécessaires aux sondes. Aucun test d'évasion n'a été exécuté pendant cet audit.

### Les fichiers ont été séparés, l'état pas encore

Les dossiers par phase sont utiles et doivent rester. En revanche les mixins
partagent largement le même `Pipeline`, et outils/validateurs conservent des
variables globales. Le fichier `phases/README.md` documente déjà cette limite.

Quelques concentrations mesurées, sans en faire des objectifs de taille :

| Fichier | Lignes | Plus grande fonction |
| --- | ---: | --- |
| `benchmark/evaluator.py` | 3 261 | `evaluate` : 900 |
| `agent/scanner.py` | 2 280 | `run_scanner` : 129 |
| `phases/intrusion/compact.py` | 1 548 | contrat compact : 704 |
| `phases/analysis/aggregation.py` | 954 | agrégation : 818 |
| `phases/analysis/run.py` | 929 | phase 3 : 625 |
| `phases/verification/run.py` | 762 | workers : 469 |
| `static/app.js` | 3 179 | plusieurs vues et leur état |

La taille du scanner reflète aussi une diversité réelle de protocoles : ne pas
supprimer des sondes utiles uniquement pour réduire un compteur de lignes.

### Fiabilité de service et reproductibilité

- La file SSE est non bornée ; sans consommateur, les événements peuvent
  s'accumuler. Un service avec plusieurs processus ne partagerait pas non plus
  `_state`/le verrou Python : la configuration doit imposer un propriétaire de run.
- Les retries du provider utilisent des délais bloquants ; l'arrêt est vérifié
  autour des tours et certains outils savent coopérer, mais pas à chaque attente.
  Ne pas promettre un arrêt instantané d'une requête externe en cours.
- La tarification distingue déjà abonnement/estimation dans `CostTracker`, mais
  cette information n'est pas entièrement transmise au tableau. Un coût marginal
  à zéro sous abonnement ne signifie pas une consommation nulle.
- La pagination benchmark et le cache sont déjà présents : ne pas les réécrire
  comme s'ils n'existaient pas. Le listing parcourt encore les métadonnées de tous
  les runs ; mesurer avant d'ajouter une nouvelle base/index.
- Si l'évaluateur passe dans des sous-dossiers, le fingerprint actuel limité à
  `benchmark/*.py` devra évoluer. Un déplacement peut sinon laisser des scores
  périmés dans le cache.
- `requirements.txt` emploie des bornes minimales ; Docker récupère aussi des
  sources/templates mobiles. Déployer le même commit ne garantit donc pas le
  même environnement. Garder un fichier de dépendances lisible, et figer l'image
  ou la résolution effectivement testée ; ne pas multiplier les requirements.
- Le déploiement cible bien le commit testé, mais le redémarrage du service
  n'est pas coordonné avec l'état d'un run actif. La migration devra drainer ou
  refuser un déploiement actif, et permettre le retour au dernier artefact sain.

## 3. Ce qu'on garde et ce qu'on supprime

À garder : les six responsabilités de phase, les sondes pertinentes, les
snapshots des candidats, l'attribution structurelle stricte, la séparation
dev/test, l'absence de mémoire épisodique en benchmark, le corpus CVE figé, les
contrôles sans vulnérabilité, les sévérités, les tokens, les profils de dialogue,
le cache/pagination et la séparation des artefacts sealed.

À supprimer lors de la refonte :

1. La reconstruction de pivots à partir de deux accès indépendants et d'un indice
   de graphe ; elle n'a pas de version « simplifiée » acceptable comme preuve.
2. La réécriture MQTT des observations par structure de message. La branche
   de cache HTTP qui restitue exactement les mêmes octets n'évite pas non plus
   l'appel réseau : supprimer si aucun consommateur ne dépend de son diagnostic.
3. Les confirmations génériques « outil réussi ⇒ faille prouvée ».
4. Les règles concurrentes full/compact sur le sens de « compromis » ou sur
   l'autorisation d'une cible. Garder les adaptations de présentation utiles.
5. Le second calcul d'état « fichier présent ⇒ done », sauf lecture historique
   explicitement marquée quand les métadonnées n'existent pas.
6. Les scores composites/pondérés historiques des surfaces de comparaison
   actives. Conserver une lecture legacy pour les archives réellement utilisées ;
   retirer leurs branches de production après inventaire des consommateurs
   batch, CLI, apprentissage et dashboard.
7. Les copies de compteurs entre rapport, API et tableau : chacun lit la même
   projection calculée ; le texte LLM ne recrée pas les chiffres.

Ne pas recréer des dossiers `full`, `shared` ou trois pipelines parallèles.
Ne pas ajouter de système de plugins, bus externe ou microservices pour obtenir
une séparation logique que quelques modules et un processus worker suffisent
à fournir.

## 4. Structure cible, orientée responsabilités

Les noms suivants sont une proposition de modules propriétaires, pas une liste
de fichiers à créer vides. Déplacer la logique seulement quand sa responsabilité
et ses entrées/sorties sont définies.

| Propriétaire | Responsabilité exclusive | Réutilisation / changement |
| --- | --- | --- |
| `agent/pipeline.py` | Cycle du run et sélection du travail éligible | Point d'entrée unique conservé ; boucle pilotée par progrès/capacités plutôt que phases uniquement linéaires. |
| `agent/core/state.py` | État d'un run : candidats, capacités, travail et état terminal | Remplace progressivement les globals/mixins omniscients par des dépendances explicites. |
| `agent/core/executor.py` | Autoriser, budgéter, exécuter et journaliser une action | Extrait du runner ; passage obligatoire pour tout profil/phase. Frontière d'isolation effective à déployer avec le worker. |
| `agent/core/runner.py` | Dialogue provider, appels demandés et format de sortie | Ne décide plus si une faille/pivot est vrai. |
| `agent/evidence/records.py` | Schéma de trace et lecture validée | IDs uniques, origine, cible effective, bornes temporelles, intégrité/complétude explicites. |
| `agent/evidence/validation.py` | Vérifier une propriété à partir d'observations | Remplace les règles trop génériques ; fonctions pures, verdict justifié, indépendantes du modèle et du profil. |
| `agent/evidence/capabilities.py` | Dériver accès et transitions causales | Un login donne une capacité située, pas automatiquement une chaîne ni un succès d'objectif. |
| `agent/phases/*` | Proposer et réaliser le travail métier de chaque phase | Dossiers actuels conservés ; ils consomment les contrats communs. |
| `agent/cost_tracker.py` | Usage actif/terminé, snapshots et tarification connue/inconnue | Conserver le module existant ; pas de renommage cosmétique requis. |
| `benchmark/evaluator.py` | Charger les entrées et assembler le résultat | Façade de composition, pas matching + preuves + intrusion + présentation dans une fonction de 900 lignes. |
| `benchmark/matching.py` | Association déterministe prédictions ↔ vérité terrain | Logique existante extraite, sans accès aux décisions du modèle. |
| `benchmark/funnel.py` | Évaluation audit aux trois étapes | Garder et consolider le module déjà ajouté. |
| `benchmark/intrusion.py` | Objectifs et transitions validés contre l'oracle privé | Ne dépend pas de la découverte de toutes les vulnérabilités alternatives. |
| `benchmark/aggregate.py` | Comparabilité et agrégation des essais attendus | Inclut les essais absents/incomplets et leurs raisons. |
| `benchmark/scenario_spec.py` et composer | Contrat public de tâche et oracle séparé | Réutiliser les modules existants ; valider les objectifs et distinguer profondeur réseau/étapes applicatives. |
| API et dashboard | Lire l'état et les trois projections audit/intrusion/usage | Diffusion fiable des événements, pas reconstruction locale du résultat scientifique. |

### Les objets métier à fixer avant le déplacement du code

1. **Observation** : réponse réelle d'une action précise, conservée avant résumé
   ou filtrage. La version courte destinée au LLM n'est pas la preuve brute.
2. **Finding** : revendication ciblée + évolution candidat/filtré/testé. Un test
   peut être concluant, indéterminé, en erreur ou non effectué. Une tentative
   échouée ne réfute pas à elle seule une faille.
3. **Preuve de propriété** : « ces observations, dans ce contexte d'identité,
   établissent cette propriété sur cette cible ». Sinon indéterminé, pas succès.
4. **Capacité** : lecture d'une ressource, session authentifiée, exécution ou
   privilège obtenu, avec portée et action justificative.
5. **Transition** : action réellement lancée depuis une capacité précédente,
   vers une cible, avec ordre causal. L'accès direct depuis le runner ne compte
   jamais comme A→B simplement parce que A et B figurent dans une liste.
6. **Objectif** : condition d'effet vérifiable, distincte des chemins possibles.
   Le vérificateur indépendant peut valider une voie non prévue sans exiger toutes
   les failles du scénario. Le secret/critère privé ne part pas dans le prompt.

La journalisation doit enregistrer le contexte d'exécution au moment où
l'exécuteur réalise l'action, et non accepter un `origin` écrit par le modèle.
Un shell libre ne doit pas bénéficier d'une provenance détaillée inventée a
posteriori : utiliser une exécution distante structurée ou laisser le pivot
non vérifiable. Les échecs d'intégrité doivent être visibles dans l'évaluation.

### Sélection du travail et règle d'arrêt

Une unité de travail identifie une cible, une propriété/action et son contexte
d'accès. Un nouvel accès ou privilège peut rendre du travail supplémentaire
éligible. Sans fait nouveau, ne pas rouvrir indéfiniment la même investigation.

- L'audit mesure l'ensemble attendu des failles, même si certaines n'ont pas
  été testées à cause d'un budget ou d'un arrêt.
- L'intrusion s'intéresse aux capacités et à l'objectif : une voie suffisante
  peut réussir sans tester toutes les autres ouvertures d'une machine.
- Les catégories de scénarios audit/intrusion/mixte **n'imposent pas trois modes
  internes**. Les priorités et règles d'arrêt sont de la politique de campagne.
- Pour un scénario mixte, proposition à valider : poursuivre l'audit après le
  premier objectif dans le budget total fixé, et figer une mesure d'usage au
  premier objectif. On obtient les deux résultats sans faire disparaître les FN.

Il faut une limite explicite de tours, outils et temps en plus des USD, en
particulier sous abonnement. Le coût futur d'un appel LLM n'étant pas connu
exactement, distinguer limite de réservation et consommation finale ; ne pas
promettre un plafond financier strict impossible à garantir avec des appels
concurrents dont le tarif ou l'usage manque.

## 5. Métriques à publier

| Vue | Mesures utiles | Précautions |
| --- | --- | --- |
| Audit | Pred, VP, FP, FN, précision/rappel/F1 pour candidats, filtrés et confirmés ; pertes entre étapes | Le VP final exige attribution et preuve valide. Une confirmation non soutenue reste un FP de rapport, avec FN correspondant. Sans vérité terrain, pas de VP/FP/FN inventés. |
| Intrusion | Objectifs validés, capacités obtenues par type, transitions réseau prouvées, profondeur causale maximale, essais réussis/attendus | Pas d'équivalence HTTP 200→machine compromise. Afficher séparément les étapes applicatives. Une alternative valide suffit à un objectif existentiel. |
| Ressources | Tokens entrée/sortie/total, tours, appels outils, durée murale, coût réel/estimé/non disponible et abonnement | Total et par phase ; snapshot au premier objectif puis total final. Absence d'objectif = mesure au premier objectif non applicable, pas zéro. |
| Diagnostic | Preuves rejetées/manquantes, erreurs, non-testés, livrables incomplets, statut de nettoyage | La preuve et l'état du run ne se déduisent pas d'un score LLM ou d'un fichier Markdown. |
| Sévérités | Distribution des findings, rappel par sévérité quand défini | Garder les informations ; ne pas cacher une mauvaise précision derrière une pondération de gravité. |

Retirer MHR de toute présentation « pivots réussis ». S'il reste en historique,
l'appeler rappel par profondeur annotée, avec son contrat/version. Pas de score
global fusionnant qualité d'audit et succès d'intrusion.

Une expérience comparable doit identifier au minimum : corpus/oracle et
version, split, scénario/seed, code+harness, modèle(s), profil(s), mode de
découverte, outils disponibles, budget, règle d'arrêt et versions des contrats.
Les agrégats doivent préciser essais attendus, exécutés, évaluables et réussis.
Une moyenne des seuls essais évaluables peut rester diagnostique, jamais se
substituer silencieusement au résultat de la campagne.

Le skill UI/UX Pro Max a orienté la revue vers la visibilité des erreurs et des
états vides : une donnée connue ne doit pas disparaître parce qu'une autre est
absente. Aucun changement esthétique ni revue visuelle exhaustive n'a été fait.

## 6. Migration proposée : un changement d'ensemble, vérifiable par lots

Les lots sont des étapes de livraison de la même architecture, pas des patchs
sans cible commune. Pas de déploiement intermédiaire avec des contrats mélangés.

1. **Figer les invariants et les essais.** Transformer les reproductions en
   tests de régression, ajouter de vrais contrôles positifs pour chaque propriété
   et un exemple causal de pivot. Valider la politique mixte et l'accès à l'API.
2. **Refaire l'exécution et les observations.** Exécuteur commun, limite réseau,
   journal fiable, données brutes séparées des résumés, état/usage de run explicite.
   Supprimer les caches qui réécrivent la preuve. Vérifier la compatibilité des
   outils essentiels et l'isolation du worker avant de lui donner des droits réels.
3. **Unifier preuves et capacités.** Validation par propriété ; même sens pour
   compact/full ; pas de promotion d'un succès générique en faille/compromission.
   Retirer la synthèse de pivots. Provenance causale ou résultat indisponible.
4. **Refaire l'orchestration et les objectifs.** Travail éligible depuis les
   nouveaux accès, politique d'arrêt explicite, objective checker indépendant,
   mêmes sondes réutilisées au lieu d'une seconde analyse cachée en phase 5.
5. **Séparer l'évaluation et aligner le dashboard.** Audit/intrusion/usage,
   agrégats comparables, statuts vrais, événements diffusés à chaque client.
   Déplacer matching et intrusion hors du monolithe, supprimer les calculs actifs
   qui font doublon après vérification de leurs consommateurs.
6. **Valider puis déployer sur le mini-PC.** Suite hors ligne complète, petite
   campagne dev contrôlée et autorisée, contrôle négatif, scénario d'audit ciblé,
   vrai pivot et scénario mixte. Stop/reprise/déconnexion/erreur de journal/budget
   testés. Déploiement seulement hors run actif, avec retour arrière disponible.

Versions : ces changements touchent le sens des résultats ; créer un nouveau
contrat métrique/preuve. Ne pas réétiqueter les runs anciens comme comparables.
Des traces anciennes sans origine ne peuvent pas être « réparées » en pivots
prouvés. Invalider le cache avec tous les nouveaux modules. Les artefacts
historiques restent consultables, clairement étiquetés.

### Définition de « terminé »

- Une mauvaise cible, une référence dupliquée, une réponse sans propriété
  démontrée et deux accès indépendants ne produisent aucun crédit indu.
- Les vrais cas positifs restent reconnus ; on ne fait pas passer les tests en
  refusant systématiquement toute preuve ou en supprimant le multi-hop.
- Une requête depuis une session/pivot réel est reliée à cette origine ; une
  requête directe ne l'est pas. Les workflows API ne gonflent pas la profondeur.
- Un outil hors périmètre est refusé quel que soit le profil ou la phase.
- Usage actif, interruption, absence de preuve et erreur de nettoyage apparaissent
  correctement ; deux clients voient les mêmes événements.
- Audit, intrusion et consommation restent lisibles séparément, sans nouveaux
  modes redondants ni perte des sévérités/tokens.
- Tous les tests concernés passent ; les écarts de scores sont expliqués par le
  nouveau contrat, pas par un assouplissement des preuves ou une retouche du test.

## Rejouer les cas hors ligne

Depuis la racine du dépôt, avec les dépendances de test et Node pour le rendu JS :

```bash
PYTHONPATH=. PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest -q docs/audit/2026-09-08/contract_regressions.py --tb=short
```

Le code de sortie 1 est **attendu sur l'état audité**. Le fichier ne porte pas le
préfixe `test_` pour ne pas injecter silencieusement ces tests rouges dans la suite
standard avant validation de la refonte. Il importe les fixtures déjà présentes
dans `tests/test_evaluation_funnel.py`, donc suppose la conservation de ces
modifications non commitées. Les fixtures produisent leurs fichiers dans les
répertoires temporaires pytest, jamais dans les vrais runs.

Après migration, répartir ces tests dans les modules de test propriétaires et
supprimer ce script de reproduction devenu redondant. Conserver le document
comme trace des hypothèses et des changements de contrat.
