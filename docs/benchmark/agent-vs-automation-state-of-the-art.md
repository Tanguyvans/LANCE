# Agents LLM et automatisation classique : état de l'art ciblé pour LANCE

**Recherche effectuée le 28 septembre 2026.** Cette revue exploratoire prépare
l'évaluation de LANCE. Elle ne constitue ni une revue systématique exhaustive,
ni une campagne expérimentale, ni une preuve d'avantage de notre agent.

Elle complète le [protocole scientifique](agent-vs-automation.md), le
[plan d'implémentation](agent-vs-automation-implementation.md) et le
[guide CLI D1/A1](agent-vs-automation-cli.md). Les recommandations ci-dessous
sont proposées ; elles ne décrivent pas des fonctions déjà toutes disponibles.

## 1. La question à étudier

**À outils, observations initiales et contraintes comparables, quel bénéfice
mesurable apporte une politique LLM à un audit IoT déjà automatisé ?**

Dans LANCE, la phase d'analyse commence par un scanner déterministe partagé.
La politique `rules` conserve ses résultats ; la politique `llm` poursuit avec
les agents d'analyse et leurs vérifications supplémentaires. La comparaison
actuelle mesure donc l'ajout du modèle à un socle existant. La présenter comme
le remplacement intégral des scripts par une IA serait inexact.

Il faut distinguer quatre bénéfices possibles : mieux interpréter une observation,
mieux choisir la prochaine vérification, mieux réagir à un résultat imprévu,
et mieux restituer les preuves. Un gain de rédaction ne démontre pas un gain
de détection. Des connaissances préentraînées différentes empêchent aussi
d'interpréter l'écart comme une mesure du raisonnement seul.

## 2. Périmètre de la recherche

Recherche ciblée sur les agents de pentest, leurs benchmarks, la planification
sans LLM et l'analyse de vulnérabilités IoT. Requêtes notamment :

- `LLM penetration testing benchmark rule based baseline` ;
- `IoT LLM penetration testing benchmark comparison` ;
- `automated penetration testing POMDP planning` ;
- recherches par titre pour vérifier publication, protocole et comparateurs.

Sources retenues : articles d'origine, actes de conférences, notices éditeur,
prépublications identifiées et documentation officielle. Les classements
commerciaux, billets promotionnels et discussions de forums ne servent pas
de preuve. Les dates de conférence et les PDF priment sur les dates d'indexation.

Le corpus ci-dessous comprend onze références. La lecture des sections
expérimentales a été approfondie pour PentestAgent, AutoPenBench, IoTBec et
VEXAIoT. Pour LIVA, seule la notice et son résumé éditeur ont été exploités :
les détails de son protocole restent à vérifier. Aucun résultat n'a été reproduit.
Les performances de ces articles ne forment pas un classement commun : corpus,
outils, budgets, assistance et définitions de réussite diffèrent.

## 3. Travaux retenus et implications

| Référence et statut | Ce qui est étudié | Conséquence pour notre comparaison |
| --- | --- | --- |
| [Nuclei, documentation des workflows](https://docs.projectdiscovery.io/templates/workflows/overview) — outil | Exécutions conditionnelles et partage de données entre templates. | Une référence sans LLM peut déjà réagir aux observations. D1 doit intégrer des branchements utiles, pas seulement une liste fixe. |
| [Sarraute, Buffet et Hoffmann, AAAI 2012](https://ojs.aaai.org/index.php/AAAI/article/view/8363/8222) — article | Planification de pentest sous incertitude avec POMDP, combinant scans et actions. | L'adaptation n'est pas exclusive aux LLM. Une victoire sur D1 ne prouverait pas une supériorité sur tous les planificateurs classiques. |
| [IoTFuzzer, NDSS 2018](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_01A-1_Chen_paper.pdf) — article | Fuzzing de dispositifs IoT à partir des applications mobiles, sans obtenir le firmware ; évaluation sur 17 appareils. | L'automatisation spécialisée sans LLM est une famille de références sérieuse. Son périmètre mémoire/protocole diffère toutefois de notre audit réseau. |
| [PentestGPT, USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/deng) — article | Organisation du contexte et assistance au pentest ; comparaison notamment avec des LLM moins structurés. | Référence fondatrice pour l'architecture et les pertes de contexte, mais ses gains ne répondent pas directement à la question « meilleur que des règles bien conçues ? ». |
| [PentestAgent, AsiaCCS 2025](https://shensecurity.com/assets/pdf/PentestAgent_AsiaCCS_camera_ready.pdf) — article, version publiée | Agents spécialisés, recherche documentaire et exécution ; 67 cibles, plus 11 défis HackTheBox. La comparaison à PentestGPT utilise GPT-3.5 des deux côtés, avec participation humaine dans PentestGPT. | Mesurer les étapes, les coûts et l'assistance. La comparaison de systèmes complets ne permet pas d'attribuer tout l'écart au seul modèle. |
| [Cybench, ICLR 2025](https://openreview.net/pdf?id=tc90LV0yRL) — article | 40 défis CTF, avec évaluation de tâches et sous-tâches, configurations guidées ou non. | Reprendre l'idée de progression observable. Séparer l'aide fournie et l'autonomie ; réussir un défi n'est pas mesurer les faux positifs d'un audit ouvert. |
| [AutoPenBench, EMNLP Industry 2025](https://aclanthology.org/2025.emnlp-industry.114.pdf) — article | 33 tâches, jalons et comparaison autonome/assistée. Les expériences GPT-4o rapportent 21 % et 64 % de réussite respectivement. | L'aide compte fortement : l'article précise que l'assistance suppose un humain connaissant les vulnérabilités. Les jalons sont utiles, mais leur jugement par LLM ne remplacerait pas notre validation technique des preuves. |
| [CVE-Bench, ICML 2025](https://proceedings.mlr.press/v267/zhu25i.html) — article ; [dépôt des auteurs](https://github.com/uiuc-kang-lab/cve-bench) | Exploitation de vulnérabilités réelles d'applications web dans un environnement isolé ; corpus annoncé de 40 CVE critiques. | Référence pour des résultats vérifiables dans l'environnement. Des applications web vulnérables ne représentent pas à elles seules des réseaux IoT avec contrôles sains. |
| [IoTBec, NDSS 2026](https://www.ndss-symposium.org/wp-content/uploads/2026-f634-paper.pdf) — article | Signatures d'interfaces et fuzzing assisté par LLM ; comparaison à boofuzz et Snipuzz. Le rappel est calculé sur l'union des vulnérabilités découvertes par les outils. | Comparaison IoT particulièrement pertinente. Les connaissances, signatures et méthodes changent ensemble : distinguer le gain du système hybride de l'apport isolé du LLM. |
| [LIVA, IEEE TDSC 2026](https://ieeexplore.ieee.org/document/11397462/) — article, résumé éditeur consulté | Analyse statique binaire de propagation de données avec LLM ; comparaison annoncée à SaTC et Karonte sur 64 appareils. | Piste pour l'interprétation spécialisée ; accès aux binaires et objectif différents de notre audit réseau. Pas de comparaison numérique directe avec LANCE. |
| [VEXAIoT, juillet 2026](https://arxiv.org/html/2607.09653v1) — prépublication arXiv v1 | Agents de détection et d'exécution sur IoTGoat et Metasploitable2 ; 260 exécutions d'attaques, 95 % de réussite globale rapportée. | Travail proche de notre application. La section expérimentale consultée ne fournit pas de comparaison appariée à un contrôleur sans LLM ; ces résultats n'établissent donc pas ce bénéfice marginal. |

Deux précautions ressortent de la lecture détaillée. Dans IoTBec, le jeu de test
reste constitué de produits des mêmes séries que la base de signatures ; les
auteurs signalent une limite de transfert entre fabricants. Dans LANCE, il faut
séparer robustesse au sein d'une famille et généralisation à de nouvelles familles.
[IoTBec, sections IV–V](https://www.ndss-symposium.org/wp-content/uploads/2026-f634-paper.pdf).

VEXAIoT indique mesurer temps et tokens des attaques réussies. Pour notre étude,
les dépenses des tentatives échouées doivent aussi entrer dans le bilan : une
moyenne limitée aux succès peut masquer le coût des échecs.
[VEXAIoT, section IV-B](https://arxiv.org/html/2607.09653v1).

**Lecture proposée de ce corpus :** il existe des résultats encourageants pour
des systèmes utilisant des LLM, y compris en IoT. Ils ne démontrent pas un
avantage universel sur l'automatisation classique. La contribution défendable de
LANCE serait une comparaison contrôlée, avec preuves, cas sains, coûts et variantes
indépendantes. Cette revue ne permet pas de revendiquer une première mondiale.

## 4. Une comparaison lisible sans multiplier les systèmes

Conserver les identifiants du protocole existant, avec un ordre de priorité clair.

| Priorité | Comparaison | Question isolée |
| --- | --- | --- |
| Principale | D1 : règles conditionnelles / A1 : socle partagé + agent adaptatif | Le modèle apporte-t-il des résultats techniques utiles dans le budget ? |
| Diagnostic | A0 : plan LLM figé / A1 : décisions révisées pendant l'exécution | Quel apport vient du retour des outils après le plan initial ? |
| Restitution | D1 / D1-R : mêmes artefacts, rapport rédigé par LLM | Le rapport aide-t-il davantage un auditeur, à résultats techniques identiques ? |
| Secondaire | D0 : procédure fixe / D1 | Quel gain vient déjà de règles conditionnelles ? |
| Externe, ensuite | LANCE / un outil spécialisé approprié | Quelle utilité pratique du système complet, avec des couvertures documentées ? |

D1 et A1 suffisent pour le premier pilote logiciel et expérimental. Ajouter tous
les modèles et toutes les variantes dès le départ rendrait la lecture plus
coûteuse sans résoudre les questions de preuve et d'équité.

Pour une analyse de l'interprétation seule, on peut aussi présenter exactement
le même dossier d'observations à des règles et au modèle, sans aucun nouvel
appel d'outil. Ce résultat porterait uniquement sur l'interprétation hors ligne.

Une comparaison externe à Nuclei peut être utile pour les interfaces couvertes
par ses templates. Elle doit utiliser une configuration pertinente, documenter
les protocoles absents et évaluer aussi un sous-ensemble de couverture commune.
L'absence de support d'un protocole ne doit pas être présentée comme un échec de
raisonnement. Une comparaison externe ne remplace pas D1/A1 pour l'attribution.

## 5. Situations IoT à montrer

Les situations suivantes sont des propositions à valider dans le laboratoire,
avec une version vulnérable et un cas proche mais sécurisé lorsque cela convient.

| Situation | Exemple de propriété mesurée | Interprétation possible |
| --- | --- | --- |
| Contrôle routinier | Un service expose une ressource sans autorisation ; le même service correctement protégé la refuse. | Les règles peuvent suffire et être moins coûteuses. |
| Autorisation contextuelle | Un compte accède ou non à une ressource d'un autre tenant. | La preuve doit relier identité, ressource et règle d'accès. |
| Information répartie | Deux observations publiques doivent être rapprochées pour choisir une vérification. | Tester l'exploitation du contexte, avec les mêmes informations accessibles. |
| Imprévu reproductible | Une première voie échoue ; une autre reste observable et autorisée. | Tester les reprises et la révision, face à un D1 disposant lui aussi de reprises. |
| Variante indépendante | Nouvelle composition de composants après gel des règles et prompts. | Tester le transfert, sans réécrire la référence après avoir vu le test. |

S1, S14 et S15 du corpus de développement constituent des points de départ
possibles, avec un contrôle sain validé. Les identifiants ne garantissent ni
l'état déployé ni l'indépendance du test. Un port renommé seul ne démontre pas
une généralisation ; un format devenu illisible pour un seul parseur mesure
d'abord la robustesse de ce parseur.

## 6. Mesures et restitution

Réutiliser le contrat d'évaluation actuel. Définir le succès avant de regarder
les résultats et produire trois vues complémentaires :

1. **Tableau par famille** : vrais positifs confirmés, faux positifs, faux négatifs,
   précision/rappel/F1, contrôles sains, runs prévus et évaluables, durée et coûts.
2. **Courbes selon le budget** : résultats confirmés en fonction du temps et de
   la charge de sondage, puis compromis qualité/coût. Compter les échecs ; séparer
   prix du modèle, calcul et travail humain. Un appel d'outil n'est pas forcément
   une seule requête réseau.
3. **Traces expliquées** : même situation initiale, observations reçues, actions
   sélectionnées et preuves obtenues. Choisir selon une règle préalable des cas
   où A1 gagne, où D1 gagne et où aucun ne réussit.

Pour rendre l'écart concret, publier également les vrais positifs confirmés
communs, propres à A1 et propres à D1, avec une identité commune de vulnérabilité.
Une différence de nombre de findings ne suffit pas : doublons, simples soupçons
et preuves rejetées restent séparés.

Les essais sont appariés sur l'instance et l'état initial rétabli. Geler les
outils, ressources, modèle, paramètres, budgets et consignes ; alterner l'ordre.
La vérité terrain demeure hors des informations accessibles aux contrôleurs.
Les observations ultérieures peuvent diverger si les actions choisies diffèrent.

Répéter les essais pour mesurer la stabilité, y compris celle du laboratoire pour
D1. Trois répétitions constituent un départ de pilote, pas une justification de
puissance statistique. Dimensionner ensuite la campagne selon la variabilité et
le gain minimal utile. Les familles indépendantes sont l'unité de généralisation ;
les répétitions d'un même scénario ne sont pas de nouvelles familles.

Rapporter les écarts appariés avec leur incertitude, et conserver les runs arrêtés,
non évaluables et leurs coûts dans un bilan séparé. Le F1 parmi les seules paires
complètes ne suffit pas à conclure à une meilleure fiabilité opérationnelle.
Le [protocole existant, sections 6–8](agent-vs-automation.md) détaille ces règles.

## 7. Priorités concrètes dans le code actuel

Le premier incrément partagé et le comparateur existent déjà. Avant de lancer
une étude destinée à soutenir une conclusion scientifique :

1. **Consolider D1.** Le premier incrément de
   [verification/rules.py](../../src/agent/phases/verification/rules.py) exécutait
   une sonde par candidat. L'[extension de campagne](agent-vs-automation-campaign.md)
   ajoute une reprise bornée sur erreur transitoire et une lecture HTTP
   complémentaire ; sa couverture reste à examiner sur le pilote. Les politiques peuvent
   choisir des stratégies différentes sous un même budget ; l'égalité du nombre
   d'actions réellement utilisées n'est pas exigée.
2. **Inventorier les connaissances partagées.** Dans
   [analysis/run.py](../../src/agent/phases/analysis/run.py), les sondes et les
   compléments déterministes précèdent les agents. Recenser leurs dépendances aux
   simulateurs, chemins, identifiants et services pour préciser la portée du test.
3. **Passer de la paire à la campagne.**
   [compare_policies.py](../../src/benchmark/compare_policies.py) refuse les paires
   incompatibles et n'estime pas d'incertitude à partir d'une seule paire. Le
   [bilan ajouté](../../src/benchmark/policy_campaign.py) conserve maintenant les
   essais prévus, échecs et coûts, avec des écarts descriptifs par configuration
   et situation. Les intervalles par familles indépendantes restent à réaliser.
4. **Préparer le pilote et le test indépendant.** Les 29 scénarios publics servent
   au développement et à une évaluation dont l'indépendance reste à vérifier.
   Préparer des variantes réservées après le pilote et geler les contrôleurs avant
   leur examen. Faire relire un échantillon de preuves à l'aveugle, car producteur
   et évaluateur partagent actuellement certaines règles.

Le pilote minimal proposé ici reprend les quatre situations du protocole
(S1, S14, S15, contrôle sain) mais commence avec D1/A1 seulement :
**4 situations × 2 politiques × 3 répétitions = 24 exécutions planifiées.**
C'est une option plus petite que le pilote D0/D1/A1 de 36 essais déjà proposé,
pas une campagne lancée ni un effectif suffisant pour une conclusion générale.
Le budget reste à calibrer avant exécution.

La suite logique est de valider cette référence et la collecte, puis de mesurer
l'écart. Si D1 est aussi bon sur les contrôles routiniers, le résultat justifiera
de réserver le modèle aux cas où son apport est démontré. Si aucun gain technique
n'apparaît, l'étude de restitution pourra encore examiner une utilité différente,
sans transformer celle-ci en gain de détection.
