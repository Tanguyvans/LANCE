# Contrat strict-v3.12 / evidence-v12

Corrections issues de la revue du 14 septembre. Les exigences de preuve sont
communes aux profils full et compact. Les artefacts historiques ne sont pas
réécrits ; leur ancien contrat reste identifiable.

## Restrictions réseau

La destination d'une URL est son hôte, jamais une adresse trouvée dans sa
requête, son chemin ou son fragment. Les destinations structurées exigent des
IP littérales ou des listes IP/CIDR complètes. Le champ `command` de
`ssh_login` reçoit le même contrôle que celui de `ssh_exec`.

Il s'agit de gardes applicatives, pas d'un bac à sable réseau/OS. Ces corrections
ne constituent pas une garantie de confinement de tout programme shell ou de
tout effet indirect d'une requête. Les essais restent limités au laboratoire
autorisé ; aucun pivot n'est reconstruit à partir de deux accès indépendants.

## SSH : accès et faiblesse des identifiants

Une exécution réussie doit correspondre à la cible, au port et au service
annoncés. Une commande SSH historique prévaut sur d'éventuels champs
structurés contradictoires ; les formes ambiguës ne prouvent pas une identité.

Le type canonique `default_credentials` (qui inclut historiquement
`weak_credentials`) exige une paire observée appartenant à la politique finie
`ssh-weak-credentials-v1`. Le texte du modèle n'ajoute pas une paire à cette
politique. La preuve n'affirme pas qu'il s'agit d'un réglage d'usine du
constructeur. Un accès utilisant d'autres identifiants reste une observation
d'intrusion, sans confirmer cette faille.

## Nmap et Modbus

Les sorties sont attribuées à un seul bloc hôte/port/protocole/service.
Un signe FTP ne confirme pas SSH ; un marqueur CVE quelconque ne prouve pas
une exposition de données. Les résultats ambigus sont indéterminés.

Un port Modbus ouvert, un nom de script, un SID seul ou un message d'erreur
ne confirme pas l'absence d'authentification. La preuve acceptée est une réponse
d'identification applicative (`Slave ID data` ou `Device identification` dans
le bloc SID de `modbus-discover`). Elle ne prouve ni lecture/écriture de
registres ni compromission. Les deux profils utilisent le même contrat.
Grammaire : [documentation officielle Nmap](https://nmap.org/nsedoc/scripts/modbus-discover.html).

## Exécution et validation

La phase 3 UMONS utilise un seul worker, sans changer full ni le délai par
défaut de 240 secondes. En full, une réponse du modèle sans promotion validée
du livrable de cette tentative ne compte pas comme analyse achevée. La branche
compact à mémo exige un nouveau mémo exploitable, pas une réponse vide ou une
interruption de génération ; cela ne constitue toujours pas une preuve de
faille. Le scanner reste consultable séparément ; son repli ne doit pas devenir
une réussite LLM. Une agrégation structurellement valide ne doit pas effacer
les erreurs des analyses individuelles dans le statut global.

Les validations locales et cas synthétiques ne démontrent pas la disparition
des timeouts sur UMONS. Un essai contrôlé S1 reste nécessaire après publication
et déploiement explicitement autorisés. MQTT-over-WebSocket reste sans
validateur applicatif : HTTP 101 ne confirme pas l'accès MQTT.

## Validation locale du 14 septembre

Suite complète après la dernière correction de propagation du statut :
**2 232 tests réussis, 4 ignorés, 3 avertissements de dépréciation** (211,70 s).
Les tests couvrent notamment les destinations hors périmètre, l'attribution
SSH/Nmap, les preuves positives et négatives Modbus, les transactions de
sauvegarde et la conservation du statut partiel après agrégation.
Aucun commit, push, déploiement ni essai réseau sur le mini-PC n'a été effectué
pendant cette validation.
