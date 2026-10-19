# Modes d'exécution et frontière avec l'application

## Périmètre

L'application est le plan de commande : elle valide la demande, garantit un seul
run actif par instance, diffuse les événements, expose l'arrêt et relit les
artefacts. Le code d'exécution est sélectionné par `runner_kind` et garde son
propre cycle de vie. `src/api/run_coordinator.py` porte l'état et le flux SSE ;
`src/agent/run_modes.py` sélectionne le runner. `Pipeline` conserve l'orchestration
interne des six phases, avec leurs [contextes explicites et leur graphe par
run](../../src/agent/phases/README.md#graphe-et-frontières-propres-au-run).

| Mode | Exécution | Modèle | Scénario / benchmark |
| --- | --- | --- | --- |
| `lance` | Pipeline de six phases et profils `auto`, `compact`, `full` | Requis pour un audit, sauf « déployer seulement » | Scénarios, déploiement, évaluation et rapports existants |
| `rules` | Déploiement du scénario, analyse et vérification déterministes (phases 3 et 4) | Aucun | Scénarios publics ou architecture personnalisée, résultats par équipement |
| `vanilla` | Une boucle modèle–outils bornée sur un CIDR explicite | Requis | Aucun déploiement ni score benchmark |
| `scripted` | Procédures déterministes versionnées : diagnostic hors ligne, découverte des hôtes et inventaire TCP | Aucun | Aucun déploiement ni score benchmark |

Les choix « scénario prédéfini/personnalisé/batch » restent **à l'intérieur de
LANCE**. L'audit par règles partage les choix prédéfini/personnalisé ; il ne
propose pas de batch. Ils ne sont pas des modes concurrents de `vanilla` ou `scripted`.
`full` et `compact` qualifient l'orchestration du pipeline, pas le type de
runner. Cette première extraction ne remplace pas le pipeline existant et ne
promet pas des runs concurrents : l'API conserve un seul run actif par instance.

## Catalogue et lancement guidé

Le parcours **Comparer règles / LLM**, séparé du catalogue, prépare une paire
contrôlée des phases 3–4. Voir le [guide de comparaison dans l’interface](../benchmark/agent-vs-automation-campaign.md#comparer-une-paire-depuis-linterface)
pour ses conditions de remise en état, mesures et limites. Le score de ce parcours
ne s’applique pas aux simples inventaires du catalogue.

L’onglet **Automatisations** ouvre les **Résultats des exécutions** : un tableau
filtrable par procédure et scénario ou réseau, paginé par dix exécutions. Il
affiche les observations, la disponibilité d’une évaluation, la durée mesurée,
les appels d’outils et le statut. Les diagnostics hors ligne sont masqués par
défaut et peuvent être inclus explicitement. **Consulter** ouvre les résultats et
les preuves, puis les étapes dans un panneau replié pour une exécution terminée.
Le suivi d’une exécution en cours garde les étapes ouvertes.

**Nouvelle exécution** et le bouton **Choisir une automatisation** du dashboard
ouvrent le catalogue fourni par `GET /api/procedures`. Chaque fiche
décrit son objectif, sa cible, ses étapes, les outils requis, ses effets et ses
sorties. Le catalogue serveur porte un identifiant, une version et une empreinte
de l’implémentation ; il ne charge aucun modèle. La disponibilité indique les
exécutables présents sur le contrôleur, sans certifier l’accès au laboratoire.

| Procédure | Cible et actions | Résultats |
| --- | --- | --- |
| **Découvrir les équipements** (`discovery-v1`) | Réseau IPv4 explicite, découverte Nmap `-n -sn` | Hôtes observés et traces ; services non inspectés |
| **Inventorier les services** (`service-inventory-v1`) | Découverte puis identification TCP de **16 hôtes actifs observés au maximum**, dans le même CIDR | Hôtes, ports ouverts, noms et versions observés, couverture et preuves |
| **Auditer un scénario automatiquement** (`rules-audit-v1`) | Scénario public déployable, puis analyse et vérification par règles | Constats et confirmations par équipement ; contrôles incomplets distincts |
| **Vérifier le lancement hors ligne** (`smoke-v1`, rubrique Diagnostic) | Aucune cible ni opération réseau | Vérification du lancement, des étapes et de l’enregistrement |

Choisir une fiche, renseigner le réseau ou le scénario, puis lancer. Les procédures
réseau simples ont des limites préremplies et ajustables ; l’audit de scénario par
règles n’envoie aucune limite si les champs restent vides, et le pipeline interactif
n’applique ni plafond d’appels ni délai d’analyse par équipement. Les expériences
contrôlées, elles, conservent leurs limites enregistrées. L’audit de scénario précise les actions
sur les services simulés et propose le nettoyage automatique final. Sa préparation
peut supprimer les scénarios déjà présents dans le laboratoire partagé pour les
remplacer par celui demandé, même si le nettoyage final est désactivé. Sa limite
de temps porte sur les contrôles après déploiement, hors préparation et nettoyage ;
elle ne borne pas la durée totale de l’opération. Le lancement utilise
`POST /api/pipeline/start` avec les contrats existants ; aucune commande arbitraire
ou import de fichier exécutable n’est accepté. Le dashboard avancé reste disponible.

L’inventaire des services utilise les ports TCP fixes
`21,22,23,53,80,443,445,554,1883,3306,5432,5672,6379,8000,8080,8443,8883,9000,9090,9200,27017`.
Ses limites par défaut sont **17 appels et 600 secondes**. Chaque scan vise une
adresse explicitement observée active par la découverte. Les hôtes silencieux et
les autres ports restent hors couverture. Les bornes, erreurs, arrêts et pertes
d’observations donnent des résultats incomplets explicites, jamais un audit sain.
Un hôte découvert actif puis devenu silencieux pendant l’identification des
services reste une inspection incomplète, même si Nmap termine avec un code zéro.
Les observations structurées sont extraites avant la troncature des extraits texte.
La découverte est plafonnée à 30 secondes par appel et chaque identification de
services à 300 secondes, dans la limite du temps total encore disponible. Augmenter
la durée totale ne relève pas ces plafonds par sonde.

Le suivi affiche les étapes réellement observées et leur état, y compris l’attente
du laboratoire et les fins non observées. Le bouton **Demander l’arrêt** utilise
l’arrêt coopératif existant ; un playbook en cours peut encore devoir se terminer
avant le nettoyage. Les résultats et l’historique restent consultables après
rechargement. Une exécution historique est présentée séparément de la préparation
d’un nouveau lancement.

`GET /api/procedures/runs` fournit les résumés paginés ;
`GET /api/procedures/runs/{id}` fournit les mesures d’une exécution publique.
Les observations sont calculées depuis les artefacts structurés enregistrés,
sans transformer les déclarations d’un audit en confirmations. Les mesures
absentes restent indisponibles. La durée totale vient des horodatages de début
et de fin ; une durée de secours issue des outils est signalée comme telle.
Les durées cumulées des agents ne remplacent pas le temps réellement écoulé.
Un lien `/#automation/{id}` ouvre directement les détails de l’exécution.

La colonne **Évaluation par scénario** indique actuellement **Non évaluée** :
ces procédures n’enregistrent pas de comparaison aux résultats attendus, ni de
score de détection. Un nombre de services trouvés n’est pas un taux de réussite ;
**Terminé** décrit la fin de l’exécution. Le scénario est affiché uniquement s’il
est enregistré dans les métadonnées ; un réseau CIDR seul ne permet pas de le
déduire. Les diagnostics affichent **Sans objet**. Cette vue permet donc de lire
les observations et les ressources utilisées, sans établir un classement de
qualité entre scénarios.

`GET /api/runs/{id}/procedure-results` fournit les observations structurées des
scripts et la projection de preuves commune des audits par règles. Les fichiers
`procedure_results.json` (scripts) et `procedure_progress.json` (règles) conservent
les étapes, le statut et l’identité de procédure enregistrée. Les événements SSE
`procedure_step`, `procedure_results` et `procedure_progress` actualisent le suivi.
Les anciennes exécutions sans ces fichiers restent lisibles dans le dashboard ;
leur version n’est pas déduite du catalogue courant. Les runs scellés n’exposent
pas ces résultats. Ces procédures ne constituent pas une expérience D1/A1 appariée.

Pour lancer l’inventaire depuis le contrôleur d’un réseau autorisé :

```bash
python -m src.agent.run_modes scripted \
  --script-id service-inventory-v1 --target-network CIDR_AUTORISE \
  --max-tool-calls 17 --max-duration-s 600
```

Le code de sortie CLI `4` signale un résultat partiel, en plus des états déjà
documentés ci-dessous. Les deux procédures réseau produisent un inventaire,
sans score de vulnérabilité ni appel au modèle.

## Contrat API

`POST /api/pipeline/start` accepte `runner_kind` (`lance` par défaut pour les
clients existants). Les runs réseau simples exigent `target_network` au format
CIDR IPv4 canonique (`/16` ou plus étroit). `smoke-v1` refuse une cible et ne
fait aucun accès réseau. `scenario_id`, les phases, le mode blind et les options
de déploiement sont refusés. `vanilla` exige `provider` et `model` ; `scripted`
exige un `script_id` du catalogue et refuse le modèle. Les limites optionnelles
`max_tool_calls` et `max_duration_s` s'appliquent aux runs réseau simples (au
maximum 100 appels et 3 600 secondes). Par défaut, `vanilla` reçoit 30
appels/600 secondes et `discovery-v1` 1 appel/120 secondes. `smoke-v1` n'utilise
aucun outil ni budget modèle : seul `max_duration_s` y est accepté. `full` et
`compact` ne s'appliquent pas à ces runners. `POST /api/pipeline/stop`
demande un arrêt coopératif. `GET /api/pipeline/status` et le flux SSE exposent
`runner_kind` et les événements de démarrage, activité et fin.
Le coordinateur utilise le journal SSE commun à tous les modes : chaque lecteur
possède son curseur et reçoit les événements conservés puis les événements en
direct, sans les retirer aux autres lecteurs.

Exemples de corps de requête :

```json
{"runner_kind":"vanilla","provider":"minimax","model":"MiniMax-M2","target_network":"192.0.2.0/24"}
```

```json
{"runner_kind":"scripted","script_id":"discovery-v1","target_network":"192.0.2.0/24"}
```

```json
{"runner_kind":"scripted","script_id":"smoke-v1"}
```

Le CIDR explicite est une **déclaration de périmètre**, pas une preuve
d'autorisation. L'opérateur doit avoir l'autorisation d'auditer cette cible.
Les modes simples ne déclenchent pas la création ni le nettoyage de machines de
scénario. Les procédures sont des entrées de catalogue, pas un interpréteur de
scripts arbitraires. `smoke-v1` teste le chemin app/API/runner et les artefacts,
sans réseau, modèle, Nmap ni réservation du laboratoire : ce n'est **pas** un
résultat d'audit. Les capacités réseau et les limites précises sont définies dans
`src/agent/run_modes.py` ; ajouter une procédure demande une revue de son code
et de ses tests.
`vanilla` ne voit que deux sondes Nmap structurées
(`nmap_discovery`, `nmap_scan`) avec destination contrôlée par le CIDR ;
les outils HTTP ne sont pas exposés dans cette première version car leur
usage de proxies d'environnement ne garantit pas la même frontière réseau.
Il n'a ni shell arbitraire, ni outil d'intrusion, ni
accès à la vérité terrain. `discovery-v1` appelle seulement `nmap_discovery`.
Les sorties Nmap exposées au modèle et archivées sont plafonnées ; le journal
signale la troncature et conserve le statut du processus et le nombre d'hôtes
comptés avant cette troncature. Il ne faut pas interpréter ce résumé comme une
capture exhaustive des paquets ou des services.

La CLI indépendante est `python -m src.agent.run_modes vanilla
--target-network 192.0.2.0/24 --provider minimax --model MiniMax-M2`, ou
`python -m src.agent.run_modes scripted --target-network 192.0.2.0/24
--script-id discovery-v1`. Pour vérifier le fonctionnement sans trafic réseau :
`python -m src.agent.run_modes scripted --script-id smoke-v1`. Le fournisseur
doit être configuré et la cible autorisée avant une exécution réseau. Les
runners réseau simples prennent la même réservation du laboratoire partagé que
le pipeline lorsqu'elle est configurée ; cela évite
de chevaucher un déploiement sur nato, sans faire d'un CIDR arbitraire un
scénario de benchmark. La limite de durée comprend l'attente de ce verrou et
les appels Nmap ; un arrêt terminal demande la terminaison coopérative du
sous-processus. La CLI renvoie 0 si le run est terminé, 2 si arrêté, 3 si le
budget est épuisé, 4 si les résultats sont partiels et 1 en cas d'échec.

## Artefacts et lecture

Chaque run simple écrit son dossier sous `output/agent/`. `run_meta.json`
identifie le mode et le statut, ainsi que le CIDR pour les runs réseau ;
`run_summary.md` donne une restitution lisible ; `cost_summary.json` suit la
consommation, et `tool_calls.jsonl` est
présent si un outil a été appelé. L'historique de l'application montre le mode et
ouvre ce résumé, sans fabriquer de topologie, de preuves d'exploitation ou de
score pour ces runs. Les runs antérieurs sans `runner_kind` restent lus comme
`lance` ; les modes simples sont exclus de la liste des candidats benchmark.

Un statut `completed` signifie que le runner a terminé son travail, **pas** que
la cible est couverte exhaustivement, qu'une vulnérabilité est prouvée ou
qu'un accès a été obtenu. Les résultats de ces modes ne sont donc pas
directement comparables par les métriques du benchmark.

## Tester les procédures

Dans l'app, choisir **Script → Démo hors ligne · sans scan → Lancer le script**.
Aucun CIDR ni fournisseur n'est demandé. Vérifier dans le journal les événements
de début, d'étape et de fin, puis dans l'historique `run_summary.md` et
`run_meta.json` (`script_id: smoke-v1`, `status: completed`, zéro appel d'outil).
Cela teste le lancement et la restitution, pas le réseau ni le moteur Nmap.

Pour le test réseau, choisir **Script → Découverte des hôtes**, saisir **un CIDR
IPv4 canonique dont l'audit est autorisé**, puis lancer. Cette procédure exécute
réellement `nmap -n -sn` et archive l'observation dans `tool_calls.jsonl`.
Une découverte de zéro hôte peut être un résultat valide ; un statut `completed`
ne signifie pas couverture exhaustive. En CLI, les deux commandes ci-dessus
renvoient le chemin du dossier d'artefacts ; ne pas lancer la commande de
découverte sur le CIDR d'exemple documentaire.

## Audit d'un scénario par règles

Choisir **Audit par règles**, puis **Scénario** ou **Personnalisé** pour choisir
l'architecture, la posture et les packs. **Lancer l'audit par règles** déploie
et vérifie la préparation du scénario, exécute les phases 3 et 4, puis applique
le choix de nettoyage automatique final. La préparation peut retirer les scénarios
déjà présents, indépendamment de ce choix final ; elle utilise le même laboratoire
partagé. Aucun fournisseur, modèle, catalogue de prix
ou rapport LLM n'est utilisé. Les scénarios scellés restent réservés au contrôleur.

Le moteur réutilise les scanners, l'agrégation et les décisions bornées de la
politique `rules`, avec le profil `full`, un worker de scan et une source CVE
figée. Aucune limite d'appels d'outils ni de durée des contrôles n'est appliquée
par défaut ; si l'opérateur en fixe une, l'API accepte jusqu'à 2 000 appels et
3 600 secondes. Le déploiement conserve son propre délai et la réservation commune
du laboratoire reste détenue pendant l'ensemble de l'opération.

Les sondes `ssh-audit` omettent le test de débit des connexions pour éviter de
pénaliser les contrôles suivants sur les serveurs qui limitent les connexions.
Elles n'évaluent donc pas la résistance à DHEat. Les diagnostics de connexion
restent dans les traces ; les codes 2/3 accompagnés de résultats sont des
observations de configuration, pas des erreurs d'exécution ni une preuve à eux
seuls. La vérification conserve les critères de preuve SSH communs.
Si la première connexion SSH expire et que la sonde Nmap suivante observe le
même port TCP ouvert sur le même équipement, le scanner répète `ssh-audit`
une seule fois, avec la même cible et le même port. Les deux tentatives restent
archivées et comptabilisées ; seule une nouvelle observation SSH réussie permet
de retirer ce timeout des erreurs non résolues de l'équipement.

La politique `shared-scanner-bounded-verification-v5` choisit, pour un contrôle
d'identifiants SSH, le premier couple explicitement indiqué dans le constat et
appartenant à la liste finie `ssh-weak-credentials-v1` (par exemple `ubnt:ubnt`
pour le NVR). Sans indication reconnue, elle conserve le contrôle `admin:admin`.
Le texte du constat ne devient jamais une commande ni un identifiant arbitraire.
La destination et le port restent ceux du constat ; seule une connexion observée
et attribuée à cette destination peut confirmer le résultat.

```json
{"runner_kind":"rules","scenario_id":"1","auto_teardown":true}
```

Pour une architecture personnalisée, remplacer `scenario_id` par `architecture`,
`posture` et `selected_packs`. L'API refuse les modèles, le mode aveugle, les
réseaux directs, les substitutions de phase et les budgets monétaires de ce mode.
Les paramètres expérimentaux `decision_policy`, `experiment_scope` et
`audit_inventory` restent réservés au CLI.

Le run sauvegarde `audit_topology.json`, une projection des identités, services
et liens publics, ainsi que les observations et livrables des phases 3 et 4.
`GET /api/runs/{id}/audit-results` fournit les résultats par équipement, à partir
de cette topologie enregistrée. Les confirmations sont recalculées avec les
contrôles de preuve communs depuis les traces d'outils : une étiquette CONFIRMED
dans un rapport ne suffit pas. Les erreurs et contrôles en attente restent
distincts d'une analyse effectuée sans détection. Les nœuds sans adresse IP
restent sur le graphe, avec la mention « non ciblé ».

Les diagnostics `execution_errors` de phase 4 sont aussi projetés par équipement.
Une détection sans preuve, avec une erreur d'exécution persistante, affiche
« Erreur de vérification · contrôle incomplet » ; le nœud, sa fiche et le tableau
signalent « Contrôles incomplets » et le nombre d'erreurs de vérification.
Une vérification négative sans erreur conserve « Non confirmée ». Les diagnostics
d'une tentative reprise restent archivés, mais ne rendent pas incomplet un contrôle
dont les traces prouvent finalement la confirmation. Une analyse terminée avec
vérification encore en attente ne présente pas les contrôles comme complets.

Le graphe affiche les détections et confirmations ; cliquer sur un équipement
montre ses résultats. Le journal suit le déploiement et les phases. L'historique
recharge la topologie propre au run, même après nettoyage du scénario, et expose
un résumé Markdown déterministe ainsi que les fichiers de preuve.

Cet audit applicatif est distinct de l'expérience contrôlée D1/A1 sur inventaire
public : il ne déclare pas d'identité expérimentale ou de paire comparable.
Les runs `rules` ne sont pas ajoutés aux comparaisons benchmark de l'interface.
Le scoring post-run porte le statut `not_applicable` dans les événements et
métadonnées. Le journal l'affiche comme une information (« Audit par règles —
sans scoring benchmark »), sans requalifier un audit réussi en incident technique.
Les erreurs réelles du run, du nettoyage ou d'une évaluation applicable restent
signalées. Le dashboard reconnaît aussi le motif explicite des anciens événements
`rules` qui portaient encore `skipped`.
La comparaison scientifique reste décrite dans le
[guide D1/A1](../benchmark/agent-vs-automation-cli.md).
