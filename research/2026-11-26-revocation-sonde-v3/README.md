# Révocation et commandes en attente : sonde version 3 (préenregistrement)

**Cycle de vie : Conclu** — dossier ouvert le **2026-11-26**, conclu le
**2026-11-27**.
Dernière révision : **2026-11-27 01:05 (Europe/Brussels, UTC+01:00)**.
Statut : **le critère préenregistré est atteint. Le LLM (`qwen3.8:27b`) a
raison dans 55 des 56 cas en vote majoritaire, contre 30/56 pour le meilleur
script figé ; seuil : 48/56 et 12 cas d'avance.** Un seul modèle et un seul
lot : l'épreuve est retenue comme candidate, pas encore comme résultat
généralisable.

Travaux antérieurs : [première sonde](../2026-11-15-revocation-commandes-attente/README.md)
et [sonde version 2](../2026-11-26-revocation-sonde-v2/README.md), conclue sur
un résultat négatif. Ce dossier ne les modifie pas.

## Question

Quand la règle du produit **ne s'écrit pas en une phrase** et doit se déduire
en combinant plusieurs faits de la documentation, le LLM fait-il nettement
mieux que le meilleur script qu'on sache écrire ?

C'est la partie « prose constructeur » de l'hypothèse H3
([registre](../2026-10-21-hypotheses-benchmark/README.md)), que la version 2 n'a
pas testée : ses documentations énonçaient la règle explicitement.

## Ce qui change par rapport à la version 2, et pourquoi

| Point | Version 2 | Version 3 |
| --- | --- | --- |
| Énoncé de la règle | Une phrase explicite | Déduite d'au moins deux faits, dans des phrases non voisines |
| Vocabulaire de la consigne | Proche des motifs du script | Mots du script interdits dans les documents |
| Script le plus fort | Écrit sans connaître la consigne du lot inédit | Écrit **en connaissant la consigne v3**, mais sans les documents |
| Comportement 3 | 3 âges sur les 5 demandés | 5 âges imposés, un par document |

La raison est fixée avant la mesure : la version 2 a montré qu'une règle
explicite se lit par motifs. Les vraies documentations constructeur décrivent
plutôt des mécanismes (signature, file, contrôle à la livraison) dont il faut
tirer la conséquence. Aucun autre axe ne change : mêmes trois comportements,
mêmes quatre journaux, même harnais.

## Protocole

1. **Préenregistrement** (ce document) : consigne, seuils, règle d'arrêt.
   Commit et push avant toute autre étape.
2. **Script renforcé** : le script `best` de la version 2, complété par les
   meilleures règles qu'on sache écrire pour des indices de mécanisme (jeton ou
   signature contrôlés à la livraison, instantané des droits à la soumission,
   durées de conservation). Il est mis au point sur les 24 documentations déjà
   connues (9 du premier passage, 15 de la version 2), sans nom de produit ni
   phrase recopiée, puis **figé** par une nouvelle empreinte, avec commit et
   push.
3. **Lot v3** : 15 documentations rédigées par un LLM extérieur avec la
   consigne ci-dessous, **après** le push du gel, puis commitées telles quelles
   avec leur corrigé.
4. **Contrôle du corrigé**, avant tout run : chaque documentation est relue
   avec les phrases que le corrigé désigne. Une documentation dont la réponse
   n'est pas incontestable est **exclue**, avec son motif écrit, avant la
   mesure ; aucune exclusion n'est permise après.
5. **Mesure** : les quatre scripts et le LLM, workflow manuel depuis `dev/2`,
   `qwen3.8:27b`, 3 répétitions, 15 documentations × 4 journaux.

## Critère de décision (fixé avant la mesure)

Pour chaque cas, le verdict du LLM retenu est la **majorité sur les 3
répétitions** ; un cas sans verdict majoritaire compte comme faux. Les scripts
sont déterministes.

- **L'épreuve passe** si le LLM a au moins **85 %** des cas corrects (51/60
  sans exclusion) **et** au moins **20 points** de plus que le script le plus
  fort (12 cas sur 60).
Le « script le plus fort » est, pour chaque cas, le meilleur score parmi les
scripts figés (`best` et `mechanism`) : on compare le LLM au meilleur des deux
sur l'ensemble du lot.

- **Sinon, elle casse** : la piste « révocation et commandes en attente » passe
  en `rejetée`, avec son motif, et on passe à un autre sujet. **Il n'y aura pas
  de version 4.**

Si des documentations sont exclues à l'étape 4, les seuils restent exprimés en
pourcentage du nombre de cas restants.

## Gel du script renforcé (étape 2)

Nouveau script `mechanism` dans `sonde.py`, à côté de `best` (inchangé). Il
cherche des **mécanismes** plutôt que des formules :

- contrôle de l'identité de l'émetteur **au moment de l'envoi** ou par
  l'appareil (signature, compte, jeton vérifiés « à ce moment ») → faille ;
- contrôle **à l'entrée seulement**, instantané du rôle, signature par la
  passerelle avec sa propre clé, « ne consulte plus », désactivation qui ne
  bloque que les nouvelles actions → comportement prévu ;
- fermeture d'un compte qui annule « tout ce qu'il possède », appareil qui
  refuse un jeton devenu invalide → faille ;
- durée de vie des commandes en attente (échéance, « jusqu'à … puis
  abandon ») comparée à l'attente du journal, en écartant les durées de
  sessions, jetons, certificats et battements.

Sans mécanisme net, il reprend la décision de `best`.

Mise au point :

| Jeu | `best` (v2) | `mechanism` (v3) |
| --- | --- | --- |
| Premier passage, 9 docs × 4 journaux | 36/36 | 36/36 |
| Lot inédit v2, 15 docs × 4 journaux | 60/60 | 60/60 |
| 10 mini-docs écrites à la main dans le style de la consigne v3, × 4 journaux | 26/40 | 40/40 |

Les 10 mini-docs sont dans `tests/test_revocation_sonde.py`. Elles ont servi à
écrire le script : ce 40/40 est **dans l'échantillon** et ne prédit rien sur le
lot v3.

Empreintes (vérifiées par les tests) :

- version 2, inchangée : `7cb52c29d00b865569f55afa90e0ca448017008d77f39df378fd2d4130550005` ;
- version 3 (version 2 + `mechanism`) :
  `ecdeab039ba06c79bdc12dd6ffc1ed9b705b3cd70f302eef8b3d4b73d12269a8`.

Le lot `v3` est déclaré dans la sonde, le lanceur et le workflow
(`documentations-v3/` et `corrige-v3.json`, à créer après le push du gel).

## Lot v3 et contrôle du corrigé (étapes 3 et 4)

Le lot a été rédigé par ChatGPT dans une conversation neuve, avec la consigne
ci-dessous, après le push du gel. Il est stocké tel quel dans
`documentations-v3/` (15 documents de 10 phrases) et `corrige-v3.json`, avec
les numéros des phrases que le corrigé désigne. Les cinq âges du comportement 3
sont présents (2 h, 1 jour, 36 h, 3 jours, 1 semaine).

Contrôle fait **avant tout score**, scripts et LLM compris :

- **Exclu : `05-copperfern-security-guide.md`** (corrigé : A). Au réveil, le
  broker réévalue l'identifiant de politique de la commande dans le registre
  courant, mais rien ne relie la désactivation d'un opérateur à cette
  politique : A et B se défendent. Le motif est inscrit dans le corrigé.
- **Gardés, avec réserve** : `08` Larkspur, `14` Windrow et `15` Cloudberry
  (B), ainsi que les documents C pour le rôle du compte, se déduisent de
  l'**absence** de tout contrôle de compte dans un circuit de livraison décrit
  en entier. C'est l'esprit de la consigne ; la réserve entre dans les limites.
- Les 10 autres documents ont une réponse directe dans les phrases désignées.

Il reste **14 documents × 4 journaux = 56 cas**. Seuils, en pourcentage comme
préenregistré : le LLM passe avec au moins **48/56** (85 %) **et** au moins
**12 cas** de plus que le meilleur script (20 points).

## Résultat hors ligne des scripts (après le push `6461f64`)

`python benchmarks/experiments/revocation_commandes_attente/sonde.py --lot v3`,
14 documentations × 4 journaux :

| Script | Correct |
| --- | --- |
| Règle par défaut | 20/56 |
| Mots-clés avec négations | 20/56 |
| Extraction de durée | 20/56 |
| `best` (v2) | 28/56 |
| **`mechanism` (v3)** | **30/56** |

Les scripts manquent surtout les documents B, où rien ne signale le mécanisme
(Larkspur, Windrow, Cloudberry, Birchstone), et un A dont les deux faits sont
dans deux phrases (ArdentRelay).

## Run sur le mini-PC (2026-11-26, terminé le 2026-11-27)

Conditions : workflow manuel depuis `dev/2` au commit `6461f64`, runner
`nato-master`, instance dev-2, provider `ollama-umons`, modèle `qwen3.8:27b`,
`lot = v3`, 3 répétitions, limite de temps 20 760 s. Empreintes relevées dans
le résumé publié : `frozen_sha256 = 7cb52c29…`, `frozen_v3_sha256 = ecdeab03…`,
corpus `3cf46118…`. Durée : 4 h 56, aucun échec du contrôleur. Les preuves
complètes restent sur le mini-PC dans
`/opt/lance-dev-2/output/revocation-commandes/`.

**Décision (vote majoritaire, règle préenregistrée) :**

| Approche | Comportement A | Comportement B | Comportement C | Total |
| --- | --- | --- | --- | --- |
| Règles par défaut, mots-clés, durée | 12/12 | 0/24 | 8/20 | 20/56 |
| `best` (v2) | 8/12 | 4/24 | 16/20 | 28/56 |
| `mechanism` (v3) | 8/12 | 4/24 | 18/20 | 30/56 |
| **LLM (`qwen3.8:27b`)** | **12/12** | **24/24** | **19/20** | **55/56** |

Le critère demandait au moins 48/56 et 12 cas de plus que le meilleur script
(30/56) : **55/56, soit 25 cas d'avance. L'épreuve passe.**

Détail par répétition (168 appels) :

- 154 appels terminés, **153 corrects** ; une seule erreur : Mossbank, attente
  de 60 h, échéance d'un jour, répondu « comportement prévu » à la
  répétition 1, puis juste aux deux autres.
- **14 appels interrompus** par le budget de durée d'un appel (environ 245 s),
  comptés comme faux. Compté ainsi, le LLM fait 153/168 (91 %), contre 90/168
  (54 %) pour `mechanism` : le critère tient aussi répétition par répétition.
- Le seul cas manqué au vote majoritaire, Foxglove avec 60 h d'attente, l'est
  par deux interruptions ; le seul verdict obtenu est juste.
- Durée d'un appel : médiane 80 s, moyenne 93 s, maximum 358 s.

**Contrôle a posteriori, hors décision.** Une règle constante « toujours
comportement prévu » obtient 36/56 sur ce lot (mais 18/36 et 29/60 sur les
lots précédents) ; le script `mechanism` avec ce défaut au lieu de « faille »
obtient 35/56. L'avance du LLM reste d'au moins 19 cas.

## Constats

- **Quand la règle se déduit de plusieurs faits, le meilleur script qu'on ait
  su écrire, en connaissant la consigne, tombe à 54 %, et le LLM reste à 98 %.**
  En version 2, où la règle tenait en une phrase, les deux étaient à égalité.
  Les deux résultats ensemble correspondent à la prédiction de H3 : égalité sur
  un énoncé explicite, avantage du LLM sur la prose qui décrit un mécanisme.
- L'écart vient surtout du comportement B : conclure qu'aucun contrôle de
  compte n'a lieu demande de lire tout le circuit de livraison, et non de
  repérer un mot.
- Le LLM est stable : un seul cas sur 56 change de verdict entre répétitions.

## Limites

- **Un seul modèle**, un seul lot de 14 documentations, rédigé par un seul LLM
  extérieur (ChatGPT) : la généralisation à de vraies documentations de
  constructeurs n'est pas mesurée.
- **Le script et la consigne viennent du même auteur.** Le script a été
  renforcé en connaissant la consigne pour lui donner l'avantage, mais un autre
  auteur pourrait écrire un meilleur script : le test de fermeture porte sur
  « le meilleur script que nous ayons su écrire ».
- **Corrigé déduit d'une absence** pour trois documents B et pour le rôle du
  compte dans les C ; un document ambigu (CopperFern) exclu avant tout score.
- **Latence** : 8 % des appels interrompus à environ 245 s ; ils pèsent sur un
  seul cas en vote majoritaire, mais la durée du run (près de 5 h) limite le
  nombre de répétitions et de modèles.
- Le journal présenté contient `status=revoked`, identique pour les scripts et
  le LLM.

## Conclusion

L'épreuve « révocation et commandes en attente », dans sa version 3, passe le
test de fermeture préenregistré. Elle devient une **épreuve candidate retenue**
pour H3, à confirmer avec le second modèle du panel et, si possible, de vraies
documentations de constructeurs, avant d'entrer dans le benchmark.

## Consigne de rédaction du lot v3

À donner telle quelle à un LLM extérieur, **après** le push du gel du script :

> Write 15 short, realistic product documentation excerpts (10 to 14 numbered
> sentences each) for fictional IoT gateways that hold commands for
> battery-powered devices until those devices wake up. Vary the format (user
> manual, FAQ, release notes, API reference, security guide, support article,
> datasheet, administrator reference) and the writing style. Do not reuse these
> product names: VeyraLink, Orbinet, KestrelNode, AxionMesh, Novacore, Teralink,
> Solvanta, BluePeak, Ironleaf, Asteron, Brindle, Cindervale, Dovetail,
> EmberGrid, Fallow, GarnetBridge, Hearthstone, IvoryPeak, JuniperNode,
> KairoEdge, LumenField, MorrowLink, Northstar, Oakline.
>
> Consider this situation: an operator submits a command for a sleeping device,
> the command waits at the gateway, and the operator's account is disabled
> before the device wakes up. Each excerpt describes how the product works so
> that a careful reader can work out exactly one of these outcomes:
> (A) the command never reaches the device — 5 excerpts;
> (B) the command still reaches the device, and the product treats this as
> normal — 5 excerpts;
> (C) the command reaches the device only if it waited less than a fixed time,
> stated in the excerpt as a duration, and the operator's account plays no
> role — 5 excerpts, one each with a fixed time of exactly 2 hours, 1 day,
> 36 hours, 3 days and 1 week.
>
> Hard constraints:
> - No sentence may state the outcome directly. The outcome must follow from
>   combining at least two facts given in different, non-adjacent sentences
>   (for example, what is stored with a command and what is checked when it is
>   sent).
> - No sentence may mention both a change to an account and what happens to
>   waiting commands.
> - Do not use these words or their variants: revoke, withdraw, discard, drop,
>   purge, remove, delete, undelivered, outstanding, regardless, irrespective,
>   eligible, rights, permission, authorization.
> - Use a different mechanism in every excerpt and never reuse a sentence
>   structure.
> - Add 3 to 5 unrelated durations (sessions, heartbeats, tokens, certificates,
>   retries) as distractors. In outcome C excerpts, at least one distractor must
>   be a duration that applies to something other than waiting commands.
> - Do not label the outcome, and do not hint at it in titles.
>
> Then, separately, give an answer key: file name, outcome letter, for outcome
> C the fixed time in seconds, and the numbers of the sentences that together
> establish the outcome.

Correspondance avec les comportements : A = 1 (faille), B = 2 (comportement
prévu), C = 3 (selon l'attente).

## Limites connues avant la mesure

- La consigne et le script sont écrits par la même personne : le renforcement
  du script en connaissant la consigne vise à donner l'avantage au script, pas
  au LLM.
- Les documentations restent générées par un LLM, pas tirées de vrais
  constructeurs.
- Un seul modèle pour la décision ; le second modèle du panel est hors critère.

## Documents

- Sonde, scripts et lanceur : `benchmarks/experiments/revocation_commandes_attente/`
- Workflow : `.github/workflows/revocation-commandes.yml`
- Tests hors ligne : `tests/test_revocation_sonde.py`

## Points ouverts

- Rapport LaTeX et PDF couvrant les versions 2 et 3.
- Second modèle du panel (`gemma4:26b-a4b-it-q4_K_M`) sur le même lot.
- Budget de durée d'un appel : à relever ou à expliquer avant tout nouveau run.
- Mise à jour du tableau « État vérifié » de `objectifs/ETAT-COURANT.md`
  (ligne H3), à décider avec le responsable de la ligne directrice.
