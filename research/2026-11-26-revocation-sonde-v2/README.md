# Révocation et commandes en attente : sonde version 2 (test de fermeture)

**Cycle de vie : Conclu** — dossier ouvert le **2026-11-26**, conclu le
**2026-11-26**.
Dernière révision : **2026-11-26 17:45 (Europe/Brussels, UTC+01:00)**.
Statut : **résultat négatif. Sur le lot inédit, le script figé fait au moins
aussi bien que le LLM (58/58 contre 56/58) : cette version de l'épreuve échoue
au test de fermeture.** Successeur : [sonde version 3](../2026-11-26-revocation-sonde-v3/README.md).

Travaux antérieurs : [première sonde et premier run](../2026-11-15-revocation-commandes-attente/README.md)
(2026-11-15 et 2026-11-26). Ce dossier ne les modifie pas.

## Question

Le LLM garde-t-il son avance sur la meilleure automatisation qu'on sache écrire,
lorsque les deux lisent des documentations **qu'aucun d'eux n'a vues** ? C'est le
test de fermeture : si un script compétent fait aussi bien, la situation n'est
pas une épreuve.

## Méthode

1. **Lot connu** : les 9 documentations du premier passage. Le script le plus
   fort (`best`) a été écrit en les lisant, avec des motifs de sens généraux
   (aucun nom de produit, aucune phrase recopiée) :
   - écarter les phrases parasites (sessions, jetons, sondes, journaux) et leurs
     durées ;
   - repérer un délai d'expiration des commandes en attente et le comparer à
     l'attente du journal ;
   - repérer si un retrait de droits supprime les commandes en attente
     (faille) ou les laisse partir (comportement prévu) ;
   - repérer si les droits sont contrôlés à l'entrée de la commande seulement,
     ou contrôlés à nouveau plus tard.
2. **Gel** : le script, ses motifs et les journaux sont figés par l'empreinte
   `frozen_sha256` (ci-dessous) et commités **avant** que le lot inédit existe.
3. **Lot inédit** : 15 nouvelles documentations (5 par comportement), rédigées
   par un LLM extérieur selon la consigne ci-dessous, avec leur corrigé.
4. **Mesure** : les quatre scripts et le LLM sur le lot inédit, avec le workflow
   manuel (`lot = inedit`) sur le mini-PC.

**Quatre journaux.** Ils sont identiques sauf l'attente entre la mise en file et
l'envoi : 5 min 38 s, 10 h, 60 h et 4 jours. Pour le comportement 3, la réponse
attendue est donc tantôt « faille », tantôt « comportement prévu ».

## Résultat hors ligne sur le lot connu

`python benchmarks/experiments/revocation_commandes_attente/sonde.py --lot connu`,
9 documentations × 4 journaux :

| Script | Correct |
| --- | --- |
| Règle par défaut | 18/36 |
| Mots-clés avec négations | 22/36 |
| Extraction de durée | 22/36 |
| **Script le plus fort (`best`)** | **36/36** |

Ce 36/36 est attendu et ne prouve rien : le script a été écrit sur ces textes.
Le seul chiffre qui compte sera celui du lot inédit.

Empreintes :

- version 1 (trois premiers scripts, inchangés) :
  `faaf189ee6057635ec072987e8c059c8660bc04c7ae8f83f9549595db95b257d` ;
- version 2 (tous les scripts, motifs et journaux) : valeur imprimée par
  `sonde.py`, relevée au commit du gel.

La fonction de lecture des horodatages accepte désormais les dates complètes
(attentes de plusieurs jours) ; elle n'entre pas dans l'empreinte de la
version 1, dont la logique est inchangée.

## Consigne de rédaction du lot inédit

À donner à un LLM extérieur, **après** le commit du gel :

> Write 15 short, realistic product documentation excerpts (8 to 10 numbered
> sentences each) for fictional IoT gateways that queue commands for sleeping
> devices. Vary the format (manual, FAQ, release notes, API reference, security
> guide, support article, datasheet) and the vocabulary; do not reuse the
> product names VeyraLink, Orbinet, KestrelNode, AxionMesh, Novacore, Teralink,
> Solvanta, BluePeak or Ironleaf. Each excerpt must state exactly one of these
> rules, in your own words and never with the same phrasing twice:
> (1) when the sender's rights are withdrawn, their undelivered commands are
> discarded — 5 excerpts; (2) rights are only checked when a command is
> accepted, and accepted commands are delivered even if the sender later loses
> their rights — 5 excerpts; (3) undelivered commands are discarded after a
> fixed age, whatever happens to the sender's rights — 5 excerpts, with ages of
> 2 hours, 1 day, 36 hours, 3 days and 1 week. Add unrelated durations
> (sessions, heartbeats, tokens) as distractors. Do not label the rule. Then
> give, separately, an answer key: file name, rule number and, for rule 3, the
> age in seconds.

Les âges du comportement 3 encadrent les attentes des journaux (5 min, 10 h,
60 h, 4 j), pour que chaque document ait des réponses des deux côtés.

## Chronologie du gel

- `ee03270` : script le plus fort, journaux et empreinte v2 figés
  (`frozen_sha256 = 7cb52c29d00b865569f55afa90e0ca448017008d77f39df378fd2d4130550005`).
- `887b290` : les 15 documentations inédites, rédigées par ChatGPT avec la
  consigne ci-dessus **après** ce push, stockées telles quelles avec leur
  corrigé (`corrige-inedites.json`). Empreinte du corpus :
  `dd58c71dd94364f76cd49083e336663c79f3e6600bd822158c623e857a6ae8cf`.

## Résultat hors ligne sur le lot inédit

`python benchmarks/experiments/revocation_commandes_attente/sonde.py --lot inedit`,
15 documentations × 4 journaux, sans modification des scripts :

| Script | Correct |
| --- | --- |
| Règle par défaut | 31/60 |
| Extraction de durée | 33/60 |
| Mots-clés avec négations | 37/60 |
| **Script le plus fort (`best`)** | **60/60** |

## Run sur le mini-PC (2026-11-26, run n° 4)

Conditions : workflow manuel depuis `dev/2` au commit `887b290`, runner
`nato-master`, instance dev-2, provider `ollama-umons`, modèle `qwen3.8:27b`,
`lot = inedit`, 3 répétitions demandées. Empreintes vérifiées dans le résumé
publié : `frozen_sha256 = 7cb52c29…`, corpus `dd58c71d…`. Les preuves complètes
restent sur le mini-PC dans `/opt/lance-dev-2/output/revocation-commandes/`.

**Le run a été coupé par la limite de temps** (1 h 10, code 124). Cette limite
avait été calculée pour 27 appels au modèle (premier lot, un journal) alors que
ce lot en demande 180. De plus, chaque appel a pris **70 s en moyenne**
(33 à 245 s), contre 3 à 12 s au premier run ; la cause n'est pas établie.
Seule la **répétition 1** a été faite, sur 58 des 60 cas ; les répétitions 2 et
3 n'ont pas commencé.

| Approche (répétition 1) | Correct |
| --- | --- |
| Règle par défaut | 29/58 |
| Extraction de durée | 31/58 |
| Mots-clés avec négations | 37/58 |
| **Script le plus fort (`best`), figé** | **58/58** |
| LLM (`qwen3.8:27b`) | 56/58 |

Par comportement, le LLM obtient 24/24 (comportement 1), 24/24
(comportement 2) et 8/10 (comportement 3). Ses deux cas non réussis :

- **Northstar, attente de 4 jours** : expiration documentée à 24 h, la livraison
  est donc une faille ; le LLM répond « comportement prévu ». Erreur de
  comparaison de durées.
- **Morrowlink, attente de 4 jours** : appel interrompu par la limite de temps,
  sans verdict.

## Constats

- **Le test de fermeture échoue pour cette version.** Un script écrit sur le
  lot connu et figé avant le lot inédit fait au moins aussi bien que le LLM sur
  des documentations qu'il n'avait jamais vues. Compléter les répétitions 2 et
  3 ne changerait pas cette conclusion.
- **Motif probable.** Chaque documentation inédite énonce sa règle **en une
  seule phrase explicite**, avec un vocabulaire proche de celui de la consigne
  (« undelivered », « discarded », « revoked », « regardless »), elle-même
  proche des motifs du script. Une règle ainsi énoncée se comporte comme un
  contrat structuré, cas pour lequel H3 prédit justement une égalité.
- **Le comportement 2 n'est plus un obstacle pour un script compétent**,
  contrairement au premier passage, où les scripts écrits à l'aveugle
  échouaient sur tous ses cas.

## Limites

- Une seule répétition, un seul modèle ; 2 cas sur 60 non mesurés pour le LLM.
- Une seule source de documentations (ChatGPT) et une consigne écrite par la
  même personne que le script.
- Répartition des âges du comportement 3 incomplète : la consigne demandait
  2 h, 1 jour, 36 h, 3 jours et 1 semaine ; le lot ne contient que 2 h, 24 h et
  36 h (3 documentations au lieu de 5).
- La lenteur des appels (70 s) n'est pas expliquée.

## Conclusion

Cette version ne mesure pas une compétence d'audit propre au LLM : une règle
énoncée explicitement se lit par motifs. Ce résultat ne rejette pas H3, dont
la partie « prose constructeur » reste à tester. Une version 3, unique et
préenregistrée avec sa règle d'arrêt, est ouverte dans
[son propre dossier](../2026-11-26-revocation-sonde-v3/README.md).

La limite de temps du workflow suit désormais le nombre réel de cas
(`600 + 120 × cas × répétitions` secondes).

## Documents

- Sonde et scripts : `benchmarks/experiments/revocation_commandes_attente/sonde.py`
- Lanceur : `benchmarks/experiments/revocation_commandes_attente/live.py` (`--lot`)
- Workflow : `.github/workflows/revocation-commandes.yml` (choix `lot`)
- Tests hors ligne : `tests/test_revocation_sonde.py`
- Lot inédit : `documentations-inedites/` et `corrige-inedites.json` dans le même
  dossier que la sonde.

## Points ouverts

- Rapport LaTeX et PDF : un seul rapport couvrira les versions 2 et 3, une fois
  la version 3 mesurée.
- Second modèle du panel : non mesuré sur cette version.
