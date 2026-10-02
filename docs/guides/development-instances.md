# Branches de développement sur nato

## Périmètre

Le workflow `Benchmark integrity` valide `main`, `dev/1` et `dev/2`, puis
appelle `Update LANCE instance` sur le runner **nato-master**. Les pull requests
vers ces branches exécutent les validations sans déploiement. Aucun benchmark
réel n'est lancé par ces workflows. Le homelab personnel reste hors périmètre.

| Emplacement | Branche automatique | Port | Checkout | Service |
| --- | --- | --- | --- | --- |
| Stable | `main` | 8501 | `/opt/nato-smartcity-iot` | `nato-fastapi` |
| Développement 1 | `dev/1` | 8502 | `/opt/lance-dev-1` | `lance-dev-1` |
| Développement 2 | `dev/2` | 8503 | `/opt/lance-dev-2` | `lance-dev-2` |

Les accès utilisent l'adresse Tailscale de nato-master `100.103.253.86`, par
exemple `http://100.103.253.86:8502`. Le code ne modifie pas le pare-feu : les
ports doivent être accessibles depuis le réseau autorisé. `/api/environment`
renvoie l'emplacement, la branche, le commit réellement déployé et l'activation
du verrou commun.

## Validation CI selon les fichiers modifiés

Les workflows restent déclenchés sur chaque push et pull request. Les changements
limités aux documents connus passent par un parcours léger : classification du
diff et contrôle des espaces, sans installation de dépendances, tests Python,
construction Docker ni déploiement. Les jobs restent présents dans les checks.
Ce parcours couvre les README explicitement listés et les fichiers Markdown,
LaTeX, PDF, bibliographie et images sous `docs/` et `research/`.

Tout code, configuration ou chemin inconnu conserve les tests complets de
`tests/` et `model_training/tests/`, les contrôles de scénario et Ansible, la
construction du worker et son contrôle d'absence de vérité terrain. Les prompts
Markdown sous `src/` et les scripts d'expérience sous `research/` suivent donc
le parcours complet. Une exécution manuelle lance également tous les contrôles ;
les tags de version déclenchent la construction complète de l'image applicative.

Le classement compare tout le push depuis son commit précédent déclaré par
GitHub, ou le commit de base d'une PR avec son checkout de fusion. Il conserve
les suppressions et les deux chemins d'un renommage. Un historique ou événement
indéterminé déclenche le parcours complet ; un échec du job bloque le déploiement.
Un push documentaire n'entraîne pas de redémarrage des instances.

Les anciennes validations d'une même PR peuvent être annulées par une nouvelle
version. Les pushes, tags et exécutions manuelles utilisent des groupes distincts ;
la sérialisation des déploiements sur nato reste gérée par `Update LANCE instance`.
Le worker possède un cache Docker dédié et reste chargé puis contrôlé localement.
L'image applicative conserve aussi les couches intermédiaires de compilation dans
son cache de registre. Le gain de durée dépend des couches réutilisables ; il doit
être mesuré dans les prochains runs. Les deux architectures AMD64 et ARM64 de
l'image applicative restent construites sur le parcours complet.

## Vue commune de l’activité

Les trois interfaces affichent une barre **Activité partagée** avec un accès à
Main, Dev 1 et Dev 2. L’interface courante porte la mention « Vous êtes ici ».
Chaque carte montre l’état courant, le scénario et le modèle lorsqu’un run est
actif, ainsi que la phase pendant l’exécution. Cliquer sur un autre environnement
ouvre son dashboard, qui reprend son suivi en direct. Les formulaires non
soumis ne sont pas transférés d’un environnement à l’autre.

La barre se rafraîchit toutes les cinq secondes quand l’onglet est visible.
L’attente du laboratoire, le déploiement d’un scénario, le nettoyage et l’arrêt
sont distingués. Une réponse absente, invalide ou d’une identité inattendue est
marquée **Indisponible**. Si un environnement exécute une opération ou attend le
laboratoire, les environnements sans exécution affichent **Laboratoire occupé** :
ils restent consultables, mais un lancement attendra la libération du laboratoire.
Si une instance est injoignable sans activité connue ailleurs, les instances
inactives affichent **Disponibilité du labo inconnue**. « Disponible » n’apparaît
que lorsque les trois instances déclarent n’avoir aucune opération active.
Si le serveur de l’interface
courante ne répond plus, les anciens états sont retirés au prochain échec de
rafraîchissement. Il s’agit de l’activité déclarée par les applications : cette
vue ne montre pas les opérations CLI, Proxmox ou les jobs de déploiement du code.

`GET /api/activity/local` expose un résumé sans journaux, fichiers ni secrets.
`GET /api/activity` regroupe le résumé local et ceux des deux autres services,
interrogés en parallèle sur les ports fixes 8501–8503 de `127.0.0.1`. Les appels
ne transmettent pas les identifiants du navigateur, ne suivent pas de redirection
et n’utilisent pas de proxy d’environnement. Les deux réponses sont sans cache.
Les données SQLite et les historiques restent séparés ; aucune commande ne peut
être lancée sur une autre instance par cette API.

Cette vue s’active quand `LANCE_INSTANCE` vaut `main`, `dev-1` ou `dev-2`.
En mode standalone, aucune autre instance n’est contactée et la barre est masquée.
Les liens conservent le protocole et l’hôte du navigateur et changent uniquement
le port : ils correspondent à l’accès direct actuel via Tailscale. Un déploiement
derrière des chemins de reverse proxy nécessiterait une configuration des liens.
Les trois branches doivent contenir cette fonctionnalité ; une ancienne version
sans `/api/activity/local` apparaît indisponible jusqu’à sa mise à jour.

## Première activation

1. Publier cette implémentation sur `main` avec l'autorisation de publication.
   Attendre la validation et le déploiement réussi sur `nato-master`, sans run
   ni opération de laboratoire en cours. Le premier déploiement vérifie aussi
   l'état de l'ancienne application qui ne connaissait pas encore le verrou.
2. Créer `dev/1` et `dev/2` depuis cette version de `main` et publier les branches.
3. Vérifier les jobs de déploiement puis `/api/environment` sur les trois ports.
   Le déploiement d'une instance de développement refuse de démarrer si la
   version stable n'annonce pas le verrou commun.

Les scripts ne prouvent pas, à eux seuls, que les instances sont installées :
seuls les jobs réussis et les vérifications HTTP sur nato le confirment.
Le script vérifie le nom du runner et son adresse Tailscale avant toute mutation.
Il utilise la configuration Ansible déjà présente sur nato, jamais un inventaire
local du poste de développement.

## Déploiement et isolation

Chaque emplacement possède son venv, sa base `data/lance.db`, son `.env` et ses
artefacts `output/`. À la première installation d'une instance de développement,
seuls les registres fournisseurs/modèles sont copiés depuis la base stable ;
les runs et scores ne le sont pas. Les réglages ultérieurs restent indépendants.
Le `.env` et les trois fichiers de configuration Ansible de nato sont copiés
pour permettre l'accès aux mêmes fournisseurs et au laboratoire autorisé.
Le `.env` existant est conservé ; la configuration Ansible est reprise de la
version stable à chaque déploiement.

Les instances sont réservées aux branches de collaborateurs de confiance :
comme l'instance actuelle, elles exécutent des outils d'audit avec les droits
et les secrets du serveur. Une pull request ne lance jamais le déploiement.

Le déploiement prend le verrou de laboratoire, vérifie que l'instance n'a pas
de travail actif ou en attente, puis arrête son service avant de changer le
code et les dépendances. `main` conserve la mise à jour fast-forward stricte ;
les instances de développement utilisent le commit validé en HEAD détachée.
Le service redémarre et sa réponse HTTP doit annoncer ce même commit. En cas
d'échec après l'arrêt, inspecter et réparer l'instance avant de la redémarrer :
aucun retour automatique vers une ancienne base ou d'anciennes dépendances
n'est effectué. Les fichiers de données ne sont pas supprimés.

## Attente commune pour le laboratoire

`LANCE_LAB_LOCK=/var/lib/lance/lab.lock` active une réservation interprocessus.
Elle couvre le pipeline entier, son déploiement et son nettoyage, le mode
« déployer seulement », le nettoyage manuel de l'API et les déploiements de
code. Chaque scénario d'un batch réserve séparément le laboratoire.

Une instance occupée conserve sa protection habituelle contre un second run
local. Une autre instance peut accepter un lancement, qui attend le verrou
sans utiliser le réseau de laboratoire. `/api/pipeline/status` expose
`lab_waiting`, et les événements SSE `lab_waiting` / `lab_acquired` signalent
l'attente et la reprise. Le bouton Arrêter annule un pipeline en attente.
Le nettoyage manuel attend également ; il n'a pas de bouton d'annulation.

L'attente est coopérative, sans garantie FIFO, et conservée en mémoire : elle
ne survit pas à un redémarrage du processus. Le fichier de verrou ne doit jamais
être supprimé ou remplacé. Une erreur de verrou bloque l'opération.

Les VM, réseaux et scénarios restent partagés. Un scénario conservé après un
run ou un déploiement seul n'est pas réservé indéfiniment ; le prochain run
peut nettoyer ou remplacer ces machines. Les allocations de VMID générées
partagent donc aussi `LANCE_DEPLOYMENT_ROOT`, pointant sur
`/opt/nato-smartcity-iot/output/scenario_deployments`. Les résultats et les
exports de scénarios restent propres à chaque checkout.

Le CLI doit recevoir les mêmes variables d'environnement que le service.
Un script Ansible lancé directement, un ancien checkout sans verrou, une
intervention Proxmox manuelle ou un contrôleur externe ne sont pas protégés
par cette réservation. Pour une opération de maintenance autorisée, utiliser
le même verrou, par exemple :

```bash
flock -x /var/lib/lance/lab.lock ansible-playbook ...
```

Ne pas combiner ce `flock` externe avec un CLI qui acquiert déjà ce même
verrou. Après un arrêt brutal, vérifier qu'aucun sous-processus de laboratoire
ne continue avant de reprendre les runs. Le verrou n'est pas un ordonnanceur
distribué ni une isolation de sécurité entre collaborateurs.

## Choisir une autre branche et ajouter des emplacements

Dans **Actions → Benchmark integrity → Run workflow**, choisir une branche
contenant cette implémentation et l'emplacement `dev-1` ou `dev-2`. Les tests
s'exécutent avant son déploiement. `none` ne lance que les validations sur une
branche de développement ; une exécution sur `main` reste un déploiement stable.
Un prochain push sur `dev/1` ou `dev/2` reprend l'emplacement correspondant.

Pour ajouter un emplacement, ajouter son nom, son port, son checkout et son
service à `scripts/deployment/deploy-instance.sh`, puis l'option et le routage
correspondants dans le workflow. Il faut conserver le même verrou et le même
registre d'allocations de laboratoire. Aucun environnement n'est créé à partir
d'un nom arbitraire reçu dans une requête.

## Validation

Les tests `test_lab_lock.py` utilisent des processus et threads réels sans
appeler le laboratoire. Ils couvrent l'exclusion, l'attente, l'annulation et la
libération après erreur. `test_deployment_workflow.py` vérifie les conditions
CI et les mises à jour de vrais dépôts Git temporaires. La validation logicielle
ne constitue pas un test de benchmark ni une confirmation du déploiement sur nato.
