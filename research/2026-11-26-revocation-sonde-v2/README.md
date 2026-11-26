# Révocation et commandes en attente : sonde version 2 (test de fermeture)

**Cycle de vie : Actif** — dossier ouvert le **2026-11-26**.
Dernière révision : **2026-11-26 15:14 (Europe/Brussels, UTC+01:00)**.
Statut : **script le plus fort écrit et figé sur le lot connu ; lot inédit à
rédiger, puis à mesurer sur le mini-PC.**

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

## Documents

- Sonde et scripts : `benchmarks/experiments/revocation_commandes_attente/sonde.py`
- Lanceur : `benchmarks/experiments/revocation_commandes_attente/live.py` (`--lot`)
- Workflow : `.github/workflows/revocation-commandes.yml` (choix `lot`)
- Tests hors ligne : `tests/test_revocation_sonde.py`
- Lot inédit (à venir) : `documentations-inedites/` et `corrige-inedites.json`
  dans le même dossier que la sonde.

## Points ouverts

- Rédiger le lot inédit après le gel et le committer tel quel.
- Mesurer le lot inédit sur le mini-PC avec `qwen3.8:27b`, puis le second modèle
  du panel.
- Rapport LaTeX et PDF à rédiger une fois le résultat du lot inédit connu.
