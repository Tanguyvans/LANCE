# Apport mesurable du LLM dans LANCE du 29 septembre 2026

## Statut et périmètre

Recherche exploratoire, lecture du dépôt et de sources primaires. Aucune expérience de laboratoire, aucun déploiement, aucune connexion SSH et aucun test de performance LLM réalisés pour cette étude. Aucun résultat présenté ci-dessous ne démontre une supériorité de LANCE. Les changements livrés portent sur la recherche et ses reproductions locales.

État lu : commit `45c8dab892ecb4e5f513813387090e0cded1b85d`, avec modifications locales notamment de classement documentaire et `research/` non suivi. Le commit seul ne décrit donc pas tous les documents consultés. Lecture d'AGENTS.md, des index [research/README.md](../../research/README.md) et [docs/README.md](../../docs/README.md), des quatre documents `research/2026-09-27-agent-vs-automation/`, des guides D1/A1, du manifeste pilote et du code cité. Les comptes de tests anciens présents dans le plan n'ont pas été reproduits.

Cette revue complète le [protocole existant](protocol.md), sans le remplacer. La [synthèse transversale](research-review.md) relie les priorités benchmark, contexte et comparaison.

## Conclusion de la revue

LANCE possède déjà un protocole de comparaison bien plus rigoureux qu'une simple démonstration « l'agent a trouvé une faille ». Il manque surtout la validation de la référence, l'indépendance des cas d'évaluation, la traçabilité de certaines conditions réelles et les résultats. Ajouter plusieurs modèles sans résoudre ces conditions ne répondrait pas à la question de l'utilité du LLM.

La question principale devrait rester : **dans quels cas l'ajout du modèle au socle déterministe donne-t-il un meilleur audit, à quelles conditions et à quel coût ?** « Montrer l'intérêt » signifie ici rechercher un effet falsifiable, y compris absent ou négatif. Une absence de gain dans le périmètre courant ne démontre ni que tous les LLM sont inutiles, ni qu'un gain de rédaction remplace le gain technique manquant.

Les quatre mécanismes à séparer sont l'interprétation d'observations, la planification initiale, la révision à partir des retours et la restitution. Ils correspondent déjà aux hypothèses H1–H6 ([research/2026-09-27-agent-vs-automation/protocol.md:82](../../research/2026-09-27-agent-vs-automation/protocol.md)). Il faut maintenant relier chaque affirmation à une expérience réalisable, un seuil fixé avant test et une décision de produit.

## Faits vérifiés dans le dépôt

| Fait logiciel ou documentaire | Preuve dans le dépôt | Conséquence scientifique |
| --- | --- | --- |
| La comparaison disponible porte sur les phases 3 et 4, profil `full`, un worker, inventaire public commun. | [src/agent/audit_experiment.py:97](../../src/agent/audit_experiment.py), [src/agent/pipeline.py:122](../../src/agent/pipeline.py), [src/agent/pipeline.py:579](../../src/agent/pipeline.py) | Elle n'évalue pas encore la reconnaissance autonome, l'intrusion complète, ni la rédaction. |
| Le scanner déterministe s'exécute d'abord pour les deux bras. D1 termine son analyse avant les micro-agents ; A1 poursuit avec eux. | [src/agent/phases/analysis/run.py:702](../../src/agent/phases/analysis/run.py), `:733`, `:1024`, `:1035` | A1 est un ajout à un socle commun. Un succès du système ne prouve pas que le modèle l'a causé. |
| Le socle partagé connaît déjà des chemins, identités et topologies des simulateurs. | [src/agent/scanner.py:174](../../src/agent/scanner.py) (API tenant et jeton de test), `:219` (enrôlement), `:267` (URL SSRF comprenant une adresse fixe) ; [src/agent/phases/analysis/run.py:770](../../src/agent/phases/analysis/run.py), `:838`, `:957` | Valable pour un corpus de développement, mais risque de plafond : beaucoup de succès peuvent venir des règles. Un renommage cassant ces règles n'établit pas une généralisation. |
| D1 phase 4 utilise le plan existant, peut répéter une sonde en erreur transitoire et remplacer certaines lectures HTTP par une lecture structurée de la même URL. | [src/agent/phases/verification/rules.py:87](../../src/agent/phases/verification/rules.py), `:114`, `:131` | Référence conditionnelle réelle mais bornée. Elle ne constitue pas toute l'automatisation classique, ni un planificateur général. |
| Le journal D1 utilise le même synthétiseur de preuves que le reste du pipeline. | [src/agent/phases/verification/rules.py:111](../../src/agent/phases/verification/rules.py), `:176` | Bonne symétrie interne ; une erreur sémantique commune nécessite une validation indépendante. |
| L'appariement refuse les divergences de configuration hors politique/fournisseur/modèle ; exige les artefacts, le cache CVE figé, la mémoire désactivée, les traces et la comptabilité complètes. | [src/benchmark/compare_policies.py:18](../../src/benchmark/compare_policies.py), `:49`, `:54`, `:97` | Bon contrôle de comparabilité déclarative. Cela ne prouve pas l'égalité effective de l'environnement. |
| Le bilan conserve les essais prévus, les coûts connus des échecs et les données manquantes ; les deltas techniques ne concernent que les paires admissibles. | [src/benchmark/policy_campaign.py:203](../../src/benchmark/policy_campaign.py), `:216`, `:230`, `:258` | Il évite de faire disparaître les échecs du bilan, mais la moyenne technique reste conditionnelle aux survivants. |
| Le pilote n'effectue pas d'inférence statistique et moyenne actuellement chaque delta disponible au sein du `family_id`. | [src/benchmark/policy_campaign.py:244](../../src/benchmark/policy_campaign.py), `:259` | Il ne réalise pas encore la moyenne hiérarchique répétition → variante → famille du protocole et ne garantit pas l'indépendance des groupes. |
| Le modèle de pilote est une configuration vide, avec répertoires de runs et précontrôles non renseignés. | [benchmarks/experiments/policy-comparison/pilot.example.json:4](../../benchmarks/experiments/policy-comparison/pilot.example.json), `:17`, `:19` | Le manifeste est une préparation ; il n'est ni une campagne réalisée ni un protocole gelé. |
| La validation d'inventaire limite les clés mais laisse `role` et `public_context` comme chaînes ; ce contexte est injecté au modèle. | [src/agent/audit_experiment.py:61](../../src/agent/audit_experiment.py), `:76` ; [src/agent/phases/analysis/run.py:1099](../../src/agent/phases/analysis/run.py) | Un schéma valide peut encore contenir une solution ou un indice. Revue du contenu public indispensable. |
| Le périmètre d'inventaire refuse `benchmark_split` et `execution_context`, paramètres utilisés par le chemin scellé. | [src/agent/pipeline.py:111](../../src/agent/pipeline.py) ; [src/agent/audit_experiment.py:111](../../src/agent/audit_experiment.py) | La comparaison D1/A1 ne bénéficie pas automatiquement d'`eval-sealed`. Son isolation doit être conçue et validée pour un test réservé. |
| Le hash couvre les fichiers source/ressources de `src/agent` et `src/benchmark`, pas l'OS, les binaires, le laboratoire ou la base fournisseur. | [src/agent/audit_experiment.py:121](../../src/agent/audit_experiment.py) | Il faut des empreintes supplémentaires pour reproduire le système complet. |
| Les métadonnées de comparabilité ne comprennent pas endpoint/version effectivement résolus du modèle ; le fournisseur peut être reconfiguré par SQLite. | [src/benchmark/comparability.py:14](../../src/benchmark/comparability.py), `:32` ; [src/agent/provider.py:237](../../src/agent/provider.py), `:278` | Même nom de fournisseur/modèle et même code ne suffisent pas à garantir un backend identique. Aucune dérive n'a été observée ici. |
| Les requêtes ordinaires fixent modèle et plafond de sortie, et éventuellement l'effort, mais pas température ou graine. | [src/agent/provider.py:645](../../src/agent/provider.py) | Archiver les paramètres effectifs et les valeurs par défaut connues/inconnues ; une température nulle ne dispense de toute façon pas des répétitions. |

## Ce qui pourrait fausser la conclusion

### 1. Mauvaise attribution des résultats au modèle

Une bonne performance absolue de A1 peut être entièrement produite par le scanner partagé. À l'inverse, un plafond de détection déjà atteint par D1 empêche A1 de montrer un gain technique sur ce corpus, sans que le test permette de conclure sur des tâches plus ouvertes.

Construire une matrice de connaissances : pour chaque contrôle, origine de l'endpoint, de l'identité, de la propriété attendue, de l'ordre des actions, de l'outil et du validateur ; préciser « fourni publiquement », « observé », « codé dans le scanner », « prompt », « modèle », « oracle privé ». Ne pas interdire à D1 les informations opérationnelles publiques accordées au modèle. Ne pas laisser les réponses privées dans les rôles, noms ou descriptions.

Pour chaque vrai positif confirmé, relier les preuves à la première action qui l'a rendu vérifiable : socle partagé, décision additionnelle de A1, vérification conditionnelle D1, ou reprise. Publier les VP communs, propres à chaque bras et les confirmations perdues lors de la fusion/filtration. Une provenance de journal décrit le parcours ; elle n'est pas, à elle seule, une preuve causale du raisonnement. L'ablation contrôlée tranche l'attribution.

### 2. Une référence sans LLM insuffisamment forte

D1 dispose de reprises, donc ce n'est plus un simple script linéaire. Mais sa phase 4 s'arrête lorsque le plan ne convient pas ; une victoire sur une lacune connue et réparable ne prouve pas la nécessité du LLM. Avant le gel, revue indépendante de D1 sur développement : extraction de paramètres observables, branchements usuels, transfert d'identités découvertes, contrôles négatifs, priorités et arrêts. Consigner les heures de développement des deux politiques.

Ne pas rendre D1 artificiellement omniscient en lui ajoutant les réponses du test. Une référence classique plus forte doit se construire avec les mêmes données de développement et les mêmes informations publiques. Un contrôleur à graphe d'états ou de dépendances serait une extension pertinente si l'affirmation visée est plus large que « mieux que le D1 borné actuel ». Un comparateur externe (p. ex. Nuclei) mesure l'utilité du système complet et doit être limité à une couverture technique documentée.

### 3. Mesurer les survivants au lieu du service rendu

Le F1 sur les paires admissibles reste nécessaire pour le contrat technique, mais ne suffit pas. Si A1 échoue plus souvent ou dépense son budget avant la finalisation, les seuls runs achevés peuvent le faire paraître meilleur. Le bilan sait conserver ces issues ; il faut maintenant une règle d'analyse préenregistrée.

Conserver les valeurs officielles manquantes. Ajouter séparément un succès opérationnel binaire défini avant test, par exemple « livrable évaluable et seuil de qualité fixé atteint avant le plafond ». Sur les environnements valides avant l'essai, une erreur de l'agent ou un budget dépassé est un échec opérationnel ; un précontrôle invalide est une défaillance de préparation publiée séparément. Publier aussi une sensibilité des conclusions aux scores techniques manquants. Ne pas convertir silencieusement tous les `null` en F1 nul.

### 4. Confondre répétitions, variantes et généralisation

Trois répétitions réduisent l'incertitude sur la stabilité d'un système donné ; elles ne fabriquent pas trois environnements indépendants. Les labels `flat-network`, `mixed-hardening` et `api` du pilote ne prouvent pas des familles indépendantes. Plusieurs scénarios peuvent partager les mêmes services, réponses et règles.

Il faut définir les familles par origine technique/composition et réutilisation des mécanismes, les variantes par transformations réellement déployées, puis le niveau de généralité revendiqué : mêmes familles, nouvelles compositions, autres familles ou dispositifs réels. Les scénarios publics S20–S29 sont utiles à la régression ; leur simple étiquette test ne suffit pas à garantir un test vierge.

## Expériences prioritaires proposées, non exécutées

| Étape | Comparaison et contrôles | Ce qu'elle tranche | Conditions avant exécution |
| --- | --- | --- | --- |
| P0 — Validité de mesure | Auditer les connaissances, la couverture D1, la preuve et la reproductibilité. | Le contraste a-t-il un sens ? | Réviser le tableau de capacités, l'entrée publique et le manifeste ; préparer les contrôles sains réels. |
| P1 — Interprétation hors ligne | Règles / interpréteur LLM sur dossiers d'observations identiques et gelés, outils désactivés ; mélange vulnérable/sain. | Le LLM classe-t-il mieux les observations et conserve-t-il les preuves nécessaires ? | Dossiers sans vérité terrain visible, découpage par famille, métrique et coûts fixés. N'établit pas l'exploration autonome. |
| P2 — Pilote opérationnel existant | D1/A1 sur S1, S14, S15 et contrôle sain, 3 répétitions, soit 24 runs planifiés. | Traces, réinitialisations, coûts, lacunes D1, variance ; premiers deltas descriptifs. | Autorisation laboratoire distincte ; configuration renseignée ; chaque contrôle réellement présent ; ordre contrebalancé, même état par paire. |
| P3 — Test principal réservé | D1/A1, budgets communs prévus, cas routiniers et recompositions réservées, équilibrage des cas sains. | Gain technique incrémental utile dans le périmètre de distribution déclaré. | Contrôleurs et seuils gelés avant révélation ; environnement/réseau/fichiers isolés ; taille issue du pilote ; aucun réglage après test. |
| P4 — Adaptation | A0 plan initial figé avec branches autorisées / A1, mêmes outils, même préfixe ; obstacle externe reproductible. | Bénéfice de nouvelles décisions modèle après observation. | A0 à implémenter ; reprise technique équitable ; pas de replay statique de la trace A1 pour simuler les actions divergentes. |
| P5 — Restitution et travail humain | D1 rapport structuré / D1-R mêmes preuves avec rédaction LLM ; étude d'auditeurs aveugle et contrebalancée. | Temps de compréhension/correction, qualité décisionnelle et fidélité du rapport. | Aucun changement des scores techniques autorisé ; grille, cas, auditeurs et temps actifs définis avant étude. |

P1 peut donner un signal utile avant la campagne complète, mais doit employer des observations autorisées déjà disponibles ou des fixtures déclarées. Des fixtures synthétiques ne démontrent pas une robustesse réelle du laboratoire. Ne pas retarder toute recherche jusqu'à la création d'un corpus immense, et ne pas présenter P2 comme une preuve générale.

Pour distinguer adaptation et robustesse de parseur, faire deux strates : variation du format brut, puis mêmes informations dans une représentation structurée commune. Un gain qui disparaît après normalisation indique un avantage d'interprétation de surface ; il ne démontre pas une meilleure planification. La recomposition doit changer les dépendances entre actions et les informations à acquérir, avec possibilités de vérification préservées et contrôle sain correspondant, sans seulement paraphraser les descriptions.

Pour relier contexte et utilité du modèle, prévoir un petit test diagnostique à dossiers constants : observation critique ancienne, bruit sans information utile supplémentaire, contradiction ultérieure et changement de cible. Comparer le contexte actuel et une représentation structurée avec références de preuves, même modèle et budget, en mesurant liens corrects, contradictions résolues, appels redondants et preuves manquantes. Cette expérience est distincte du contraste D1/A1 ; elle ne doit pas changer simultanément architecture, outils, modèle et budget. Les mesures de contexte expliquent un défaut ; elles ne remplacent pas les confirmations techniques.

## Unités, statistiques et seuils à geler

L'analyse proposée du protocole est à conserver : calculer les deltas D1/A1 appariés par instance/répétition, moyenner les répétitions par variante, les variantes par famille, puis donner le même poids aux familles. Publier aussi les valeurs par famille et les tailles. Si le poids économique réel des familles est connu, déclarer une deuxième analyse pondérée séparée avant test.

L'intervalle à 95 % par rééchantillonnage apparié des familles est une méthode proposée, pas une fonction présente dans le code. Garder ensemble les deux bras et toutes leurs observations internes. Avec seulement quelques familles, le bootstrap ne crée pas de diversité : rester descriptif et afficher l'incertitude. Pour dimensionner la campagne, utiliser la variance entre familles et dans les répétitions du développement, une marge utile fixée, puis une simulation de puissance/coût ; augmenter d'abord la diversité si c'est elle qui limite la conclusion.

Ne pas traiter tous les findings ou tours modèle comme des échantillons indépendants. Pour une réussite binaire, un test apparié doit respecter les grappes/familles ; un McNemar appliqué directement à des centaines de répétitions dépendantes serait trompeur. Garder un contraste confirmatoire principal ; déclarer les mécanismes secondaires et toute correction de multiplicité avant lecture du test final.

Valeurs à inscrire au manifeste avant test, actuellement non fixées :

- `delta_min` : gain minimal utile du F1 final sur scénarios positifs, ou autre critère principal choisi et justifié avant données finales ; ne pas multiplier les critères au gré des résultats.
- `margin_fp` : dégradation maximale acceptable du taux de fausses alertes sur contrôles sains ; publier aussi les nombres bruts et la prévalence.
- `margin_reliability` : dégradation maximale du succès opérationnel défini, sans exclure les échecs imputables au système.
- `budget_wall_time`, charge réseau (requêtes/plages/cibles/débits), limites par outil et coût total acceptable ; nombre d'appels n'est pas charge réseau.
- Niveau d'incertitude, règle sur les données manquantes et pannes, taille fixe, reprises, critères d'arrêt opérationnels et analyses secondaires.
- Règle de choix des traces illustratives comprenant victoire A1, victoire D1 et échec commun, lorsque ces catégories existent.

Ces paramètres sont des engagements expérimentaux à calibrer avec besoins opérationnels et pilote, pas des valeurs numériques à inventer dans ce rapport. Une recherche peu puissante peut conclure « indéterminé ». L'absence de significativité ne prouve pas l'équivalence. Pour conclure que D1 est suffisant, utiliser une marge de non-infériorité/équivalence décidée à l'avance et la précision suffisante, en plus du coût et de la fiabilité.

## Budgets et reproductibilité à compléter

L'étude d'attribution conserve outils, observations initiales, sécurité, validateurs et plafonds communs. Les quantités réellement consommées peuvent différer ; forcer D1 à brûler autant d'actions que A1 n'est pas une comparaison utile. Un plafond de tokens ne constitue pas un budget commun à une politique sans modèle.

Archiver par exécution : consommation API réelle ou estimée et source de prix, tokens d'entrée/sortie/cache/raisonnement lorsqu'ils existent, demandes échouées et inconnues, latence décisionnelle, temps outil, durée murale, requêtes réseau, coût de calcul, temps humain de préparation/intervention/correction/nettoyage. Séparer coût marginal d'exploitation et développement/maintenance amortis sur un volume déclaré. Le code actuel mesure une partie de cela, pas le coût total ([src/benchmark/compare_policies.py:113](../../src/benchmark/compare_policies.py), [src/benchmark/policy_campaign.py:261](../../src/benchmark/policy_campaign.py)).

Figer/archiver : version de modèle accessible et alias résolu si disponible, endpoint sans secret ou son empreinte, options effectives, politique de retry, SDK, container/OS/binaires/outils, prompts/règles actuels et diff local, inventaire autorisé, artefacts du précontrôle, état serveur rétabli entre bras et événements de perturbation. La base SQLite du fournisseur, les variables d'environnement pertinentes et les defaults distants ne sont pas entièrement couverts par le hash des sources. Documenter explicitement les informations non disponibles.

Les paramètres du test privé doivent être hors montage du contrôleur, les entrées publiques neutres et la vérité terrain préparée indépendamment. La contamination de préentraînement ne peut pas être prouvée absente par une graine ou une date : distinguer contenu public connu, règles spécifiques apprises au développement et compositions privées inédites. Publier les conditions de chaque niveau de revendication sans promettre une pure mesure de raisonnement.

## Décisions si le gain est absent ou défavorable

| Résultat, selon règles fixées avant test | Interprétation défendable | Suite proposée |
| --- | --- | --- |
| A1 apporte un gain supérieur à la marge utile, sans dépassement des marges FP/fiabilité/coût. | Valeur technique démontrée dans la distribution et le budget testés. | Conserver le modèle sur ce périmètre ; vérifier le mécanisme ensuite. |
| D1 atteint déjà un plafond, A1 n'apporte pas de VP supplémentaire. | Pas de gain de détection démontré sur les tâches routinières. | D1 pour cette strate ; étudier explicitement de nouvelles compositions si le besoin produit le justifie. |
| A1 progresse hors ligne mais pas en interaction. | Interprétation prometteuse ; collecte, gestion d'état, budget ou contexte peuvent annuler le bénéfice. | Examiner les traces et corriger sur développement ; retester sur un nouveau jeu réservé. |
| Gain présent uniquement avec plus de temps/actions/coût. | Effet de ressources possible ; pas de gain établi au budget principal. | Publier la courbe de compromis aux plafonds déjà prévus ; tester une politique d'escalade dans une nouvelle expérience. |
| Gain localisé aux cas ambigus, surcoût partout ailleurs. | Utilité conditionnelle possible. | Règles d'abord, appel LLM sur déclencheurs définis sur développement ; évaluer le routeur et ses faux refus sur test privé. |
| D1 techniquement non inférieur selon marge préfixée, moins coûteux et plus fiable. | LLM non nécessaire pour la décision dans ce périmètre. | Utiliser D1 ; évaluer D1-R séparément si la restitution répond à un besoin mesurable. |
| A1 dégrade faux positifs ou fiabilité au-delà des marges. | Coût opérationnel non acceptable même avec quelques succès intéressants. | Restreindre ou désactiver le chemin adaptatif ; corriger puis nouvelle version/évaluation. |
| Intervalle trop large ou trop peu de familles. | Résultat indéterminé. | Ajouter de la diversité ou réduire la portée ; ne pas choisir un score secondaire favorable comme conclusion principale. |

Une piste pertinente si le coût est surtout l'encodage manuel de nouvelles règles : comparer séparément l'adaptation d'un workflow par humain seul et humain aidé d'un LLM, puis exécuter le workflow déterministe. Mesurer temps de développement et défauts sur nouvelles familles. Ce serait un apport du LLM à la construction/maintenance de l'outil, distinct de son utilité comme décideur à chaque audit.

## Sources primaires consultées le 29 septembre 2026

Revue ciblée, non systématique. Recherche par titres et mots-clés relatifs à agents cyber, baseline sans LLM, coûts et reproductibilité. Aucun résultat reproduit. Les chiffres des articles ne sont pas comparables directement au F1 de LANCE. Les implications ci-dessus sont des propositions propres à LANCE, pas des fonctionnalités déjà prouvées par ces sources.

1. **Kapoor et al., _AI Agents That Matter_**, arXiv v1 du 1 juillet 2024. Lecture HTML des sections 2 (références simples et coûts), 5 (généralité/holdout) et 6 (reproductibilité), plus passages d'annexe. Leur réévaluation montre l'importance de contrôles simples et du compromis coût/qualité ; la version lue traite notamment programmation et navigation, pas notre audit IoT. Une version TMLR de mai 2025 a été repérée mais son PDF OpenReview était bloqué par une vérification navigateur ; ne pas la présenter comme lue. [Version effectivement lue](https://arxiv.org/html/2407.01502v1).

2. **Gioacchini et al., _AutoPenBench: A Vulnerability Testing Benchmark for Generative Agents_**, EMNLP Industry, 4–9 novembre 2025. Lecture PDF §§2–5 et limitations. 33 tâches ; 21 % de réussite autonome contre 64 % assistée dans cette configuration. Les auteurs précisent que l'assistance suppose un humain connaissant les vulnérabilités ; les jalons intermédiaires sont jugés par LLM. Bon rappel de mesurer aide et progression ; ces chiffres ne démontrent ni un gain contre D1 ni une économie d'heures humaines en situation ouverte. [Article](https://aclanthology.org/2025.emnlp-industry.114.pdf).

3. **Yang et al., _IoTBec: An Accurate and Efficient Recurring Vulnerability Detection Framework for Black Box IoT devices_**, NDSS 2026, PDF publié. Lecture §§IV–V, tables II–V et résumé. Comparaison à boofuzz/Snipuzz avec signatures et fuzzing LLM ; test sur 21 produits après construction sur 6, mêmes séries de produits, vérification en émulation QEMU. Le rappel utilise l'union des failles découvertes, pas un dénominateur exhaustif indépendant. Préparation humaine et transfert inter-fabricants limité sont reconnus. Intéressant pour un système hybride ; l'avantage ne s'attribue pas automatiquement au seul LLM. [Article](https://www.ndss-symposium.org/wp-content/uploads/2026-f634-paper.pdf).

4. **Lin et al., _Comparing AI Agents to Cybersecurity Professionals in Real-World Penetration Testing_**, prépublication arXiv v2 du 3 mars 2026 ; v1 du 10 décembre 2025. Lecture résumé, §§3.1–3.3, 5.4, 6 et limitations de v1 ; vérification des passages méthode/coûts en v2 ; les limites discutées ici ont été lues dans v1. Comparaison de dix professionnels à plusieurs agents sur un réseau universitaire ; coûts API suivis, faux positifs et dépendance aux interfaces relevés. Petit échantillon, défenses averties et assistance de surveillance limitent l'extrapolation. Référence d'utilité pratique et de mesure humaine ; aucun contraste D1/A1 directement transposable. [Version v2](https://arxiv.org/html/2512.09882v2).

5. **Zhang et al., _Cybench_**, ICLR 2025. Notice officielle et résumé consultés dans cette revue, pas nouveau dépouillement complet du PDF. 40 défis CTF et sous-tâches ; distinction guidance/autonomie et progression pertinente. Aucun transfert automatique des taux CTF à l'audit avec contrôles sains. [Actes officiels](https://proceedings.iclr.cc/paper_files/paper/2025/hash/3e9412a9c1d93810ef3ef7825115016b-Abstract-Conference.html).

6. **Zhu et al., _CVE-Bench_**, ICML/PMLR 267, 13–19 juillet 2025. Notice et résumé officiels consultés, pas article complet dans cette revue. Évaluation d'exploitation de vulnérabilités web critiques dans des environnements isolés ; exemple de validation par état de cible. Le périmètre web vulnérable ne couvre pas les contrôles sains ni toute la sémantique IoT. [Notice primaire](https://proceedings.mlr.press/v267/zhu25i.html).

7. **ProjectDiscovery, _Template Workflows Overview_**, documentation vivante sans version/date de publication explicite, consultée le 29 septembre 2026. Sections workflows conditionnels et contexte partagé lues : branchements et échanges de valeurs/cookies sont disponibles sans LLM. Justifie une baseline conditionnelle sérieuse, sans prétendre à une couverture IoT universelle. [Documentation officielle](https://docs.projectdiscovery.io/templates/workflows/overview).

8. **Dror et al., _The Hitchhiker's Guide to Testing Statistical Significance in Natural Language Processing_**, ACL 2018. Notice et PDF §§3.2–3.3 lus. Discussion des tests appariés, hypothèses de distribution et limites du bootstrap sur petits ensembles. Référence générale ; elle ne valide pas directement notre schéma de grappes ni ne fournit la puissance du pilote LANCE. [Article](https://aclanthology.org/P18-1128.pdf).

## Questions concrètes à soumettre à Muse

- Notre D1 est-il assez fort pour la portée revendiquée, ou la construction du plan donne-t-elle mécaniquement l'avantage à A1 sur les variantes ? Quels contre-exemples du code l'établissent ?
- Quelles connaissances de fixtures dépassent l'information publique autorisée d'un test indépendant ? Les rôles et le contexte suffiraient-ils à reconstituer des réponses sans observer le service ?
- Le contraste peut-il isoler un gain marginal du LLM quand le scanner est déjà presque un solveur des scénarios ? Quelle expérience minimale réfuterait cette hypothèse ?
- L'analyse des paires admissibles peut-elle inverser la conclusion lorsque la fiabilité diffère ? Quelle analyse préfixée resterait fidèle aux `null` officiels ?
- Les règles de décision prévues accepteraient-elles effectivement de supprimer le LLM en cas d'absence de gain, ou permettent-elles de déplacer a posteriori l'objectif vers un récit favorable ?
- Les lacunes de gel endpoint/options/isolation sont-elles réelles dans les chemins d'exécution actuels, et quelles conditions minimales suffiraient à rendre le premier test recevable ?
