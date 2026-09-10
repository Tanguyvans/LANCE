# Contrat de preuve — strict-v3.10 / evidence-v8

Cette version exige une identité HTTP primaire exacte (schéma, hôte, port,
chemin et query), reconnaît les dumps SQL uniquement lorsqu'une table et une
colonne sensible connue contiennent une valeur littérale concrète (ou une
heuristique opaque bornée pour `api_keys` sans colonnes, sans certifier l’usage
réel de la clé), et réserve la preuve
Telnet à une interaction structurée ayant reçu des octets. Une connexion seule,
un timeout ou une sortie stderr ne constitue pas une confirmation.

Les artefacts produits sous les contrats antérieurs restent historiques et ne
sont ni renommés ni réévalués par cette version.

Les preuves MQTT associent une revendication de topic uniquement à l'argument
`topic` explicite de `mqtt_listen` (comparaison exacte, sensible à la casse).
Pour SSH, `/` reste un placeholder de ressource et ne déclenche pas de
contrôle de chemin HTTP uniquement pour les familles transport,
authentification et cryptographie; une ressource SSH de type exposition de
données conserve son chemin obligatoire. L'hôte, le port, la commande et la sémantique
d'authentification restent obligatoires. L'identité dédupliquée ne rapproche
`/` et vide que pour `mqtt-ws` `no_auth`, afin de conserver les routes HTTP et
les autres protocoles strictement distincts.

Le verdict Phase 4 est déterministe et dérivé des traces fraîches; le fichier
de sortie du modèle est conservé comme artefact brut mais n'influence pas le
statut. Une absence de trace ou un timeout ne constitue pas une preuve
d'absence de vulnérabilité.
