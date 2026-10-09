# Modes d'exécution et frontière avec l'application

## Périmètre

L'application est le plan de commande : elle valide la demande, garantit un seul
run actif par instance, diffuse les événements, expose l'arrêt et relit les
artefacts. Le code d'exécution est sélectionné par `runner_kind` et garde son
propre cycle de vie. `src/api/run_coordinator.py` porte l'état et le flux SSE ;
`src/agent/run_modes.py` sélectionne le runner. Cette séparation ne transforme
pas les six phases historiques en services indépendants : `Pipeline` conserve
leur orchestration interne.

| Mode | Exécution | Modèle | Scénario / benchmark |
| --- | --- | --- | --- |
| `lance` | Pipeline de six phases et profils `auto`, `compact`, `full` | Requis pour un audit, sauf « déployer seulement » | Scénarios, déploiement, évaluation et rapports existants |
| `vanilla` | Une boucle modèle–outils bornée sur un CIDR explicite | Requis | Aucun déploiement ni score benchmark |
| `scripted` | Procédures versionnées et déterministes `smoke-v1` (hors ligne) et `discovery-v1` (Nmap) | Aucun | Aucun déploiement ni score benchmark |

Les choix « scénario prédéfini/personnalisé/batch » restent **à l'intérieur de
LANCE**. Ils ne sont pas des modes concurrents de `vanilla` ou `scripted`.
`full` et `compact` qualifient l'orchestration du pipeline, pas le type de
runner. Cette première extraction ne remplace pas le pipeline existant et ne
promet pas des runs concurrents : l'API conserve un seul run actif par instance.

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
budget est épuisé et 1 en cas d'échec.

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
qu'un accès a été obtenu. Les résultats des trois modes ne sont donc pas
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
