# Révocation et commandes en attente : épreuve candidate

**Cycle de vie : Proposition** — dossier ouvert le **2026-11-15**.
Dernière révision : **2026-11-15 20:05 (Europe/Brussels, UTC+01:00)**.
Statut : **situation candidate ; premier passage de la sonde hors ligne, sans
LLM.**

## Question

Quand les droits d'un opérateur sont retirés, ses commandes mises en attente par
une passerelle IoT sont-elles encore exécutées, et **est-ce une faille ou le
comportement prévu** par le produit ? L'épreuve vise une capacité précise :
décider d'une propriété de sécurité en interprétant la documentation d'un
produit inconnu (hypothèse H3 du
[registre d'hypothèses](../2026-10-21-hypotheses-benchmark/README.md)).

## La situation

Beaucoup d'appareils IoT ne sont pas joignables en permanence (batterie, veille,
liaison intermittente). Une passerelle met donc leurs commandes **en file
d'attente** et les transmet à leur réveil. Si les droits de l'émetteur sont
retirés entre-temps, la réponse dépend du produit :

| Produit | Comportement documenté | Commande exécutée après la révocation |
| --- | --- | --- |
| A | La révocation annule les commandes en attente | **faille** |
| B | Seule la soumission est contrôlée ; une commande acceptée est maintenue | **comportement prévu** |
| C | Les commandes en attente sont annulées au-delà d'un délai | **faille ou non**, selon le délai |

Les journaux peuvent être identiques d'un produit à l'autre : c'est la
documentation qui tranche.

## Ce que reçoit l'auditeur

L'automatisation et l'agent LLM reçoivent les mêmes journaux et la même
documentation du produit, en texte libre. Exemple de journaux (fictif) :

```text
16:39:12  mqtt     publisher=operator_17  topic=site/x/device/y/request  result=accepted
16:39:13  gateway  operation=queued        destination=device_y
16:42:00  iam      principal=operator_17   status=revoked
16:44:51  gateway  operation=dispatched    transport_identity=gateway_service
```

Une réponse correcte donne le **constat technique** (la commande est partie
après la révocation) et le **verdict** (faille ou comportement prévu), avec les
lignes de journal et le passage de documentation qui le fondent.

## Le filtre, sur papier

Le script le plus fort reconstruit le cycle de vie de chaque commande et repère
celles transmises après la révocation de leur émetteur : **il réussit le constat
technique**, qui sert de contrôle commun aux deux approches.

La différence se joue sur le **verdict**. Le script doit traduire une
documentation qu'il n'a jamais vue en une règle (annule, maintient, délai). Avec
des formulations variées — « livraison garantie », « reprise après
reconnexion », « les droits sont vérifiés à la soumission » — la règle n'est pas
extractible par mots-clés : il faut comprendre ce que chaque phrase implique pour
une commande déjà acceptée. C'est là que l'agent LLM peut apporter quelque chose.

**Variantes** : les trois comportements de produit avec des journaux identiques,
plusieurs styles de documentation, et d'autres transports (CoAP, OPC UA) ou
opérations (maintenance, configuration).

## Conditions de l'épreuve

- **Documentations variées** : un mélange de vraies documentations de
  constructeurs et de documentations écrites par une personne extérieure, pour
  ne pas y glisser nos propres mots.
- **Règle non ambiguë** : chaque documentation désigne un seul des trois
  comportements, pour que le corrigé soit incontestable.
- **Script réellement compétent** : écrit pour gagner, puis figé avant la mesure.

## Premier passage de la sonde (2026-11-15)

La sonde (`benchmarks/experiments/revocation_commandes_attente/sonde.py`)
applique trois scripts écrits et figés **avant** de voir les documentations
(empreinte `faaf189e…`) à 9 documentations rédigées par un autre LLM, trois par
comportement, avec un corrigé séparé (`corrige.json`).

| Script | Comportement 1 | Comportement 2 | Comportement 3 | Total |
| --- | --- | --- | --- | --- |
| Règle par défaut (« toujours faille ») | 3/3 | 0/3 | 0/3 | 3/9 |
| Mots-clés avec négations | 3/3 | 0/3 | 3/3 | 6/9 |
| Extraction de durée | 3/3 | 0/3 | 2/3 | 5/9 |

Les trois scripts échouent sur le comportement 2, décrit sans formule fixe
(« autorisation évaluée au moment de l'acceptation », « enregistrement de
livraison indépendant »). Limites de ce premier passage : un seul journal, dont
l'attente (5 min 38 s) est inférieure à tous les délais du comportement 3, qui
n'est donc pas réellement testé ; un comportement 1 que la règle par défaut
réussit sans lecture ; des scripts non encore améliorés sur ces documentations.
L'agent LLM n'a pas encore été essayé.

## Harnais sur le mini-PC

Le même dossier contient l'approche LLM (`llm.py`) et le lanceur (`live.py`),
construits sur le modèle du harnais H2. Le modèle reçoit le journal et la
documentation, sans le corrigé, et clôt par un verdict accompagné des phrases de
la documentation qu'il cite ; une citation absente de la documentation est
refusée. Le lanceur fait passer chaque documentation aux trois scripts et au
modèle, sur plusieurs répétitions, et publie seulement les verdicts, les comptes
et les coûts. Le workflow manuel `.github/workflows/revocation-commandes.yml`
le lance depuis `dev/2` sur le runner `nato-master`, sous le verrou du
laboratoire, avec `qwen3.8:27b` par défaut. Tests hors ligne :
`tests/test_revocation_sonde.py`.

## Suite

1. Essayer l'agent LLM sur les mêmes documentations.
2. Version 2 de la sonde : scripts améliorés sur ces 9 documentations, puis
   mesurés sur une nouvelle série inédite ; plusieurs journaux, dont une attente
   plus longue que les délais.
3. Si la sonde confirme, rédiger l'épreuve, puis la construire et la mesurer.

Points ouverts : qui rédige les documentations des variantes ; quelles vraies
documentations décrivent ce mécanisme ; journaux figés ou passerelle simulée sur
le laboratoire.
