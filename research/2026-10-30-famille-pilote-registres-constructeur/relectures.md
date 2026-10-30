# Relectures — famille pilote `s_registres_constructeur`

**Cycle de vie : Actif — journal de relecture** — ouvert le **2026-10-30**,
dernière révision **2026-10-30 14:40 (Europe/Brussels, UTC+01:00)**.

Ce document consigne les relectures indépendantes demandées avant toute
implémentation. **Un avis d'agent n'est pas une validation** : chaque verdict
est confronté aux faits mesurés sur le dépôt, et les désaccords restent
écrits.

---

## Révision 1 du plan (`plan-conception.md`, état du 2026-10-30 ~13:40)

Deux relectures indépendantes : méthodologique et technique. Verdicts :
**à corriger** dans les deux cas.

### Relecture méthodologique — 9 risques bloquants

| # | Reproche | Suite |
| --- | --- | --- |
| R1 | Un test binaire transformé en test à abstention non déclaré : un D1+ prudent obtient `inconclusive` et n'est jamais rejeté (mécanisme même de C2). | **Accepté.** Fermé en révision 2 (§ 5) : `undetermined` sur une propriété (c) rend le test `inconclusive`, ce qui **rejette** la famille. |
| R2 | Grille asymétrique : `absorbed` ne regardait que les faux positifs de la convention ; le cas `{D1+ juste, convention juste}` n'avait pas de ligne. | **Accepté.** Grille unique en révision 2 (§ 5) : `absorbed` si la convention est ≥ D1+ sur la classe (c). |
| R3 | F0 biaisé et verdict déclenché par un seul dossier. | **Accepté en partie.** Taux de base 4/8 publié ; les dossiers `t05`/`t06` portent une ambiguïté réelle sans projection, ce qui rejette un bras qui conclut `projection` dès qu'un libellé est ambigu. |
| R4 | Le bras convention pourrait être réécrit après coup ; R4 affirme en outre que H2 l'a écrit après avoir vu le corpus. | **Partiellement contré.** Le code de H2 réfute l'affirmation : `run_attempting_rules` ne contient que des jetons du domaine (`mqtt_formats.py` l. 225-231, 348-355). Le risque réel — une réécriture pendant l'étape 5 — est traité par l'exécution liée au manifeste. |
| R5 | Une référence devinnable n'est pas une preuve liée ; la classe (b) est vide. | **Accepté.** Preuve liée en révision 2 (§ 4) : `observation_ref` attesté avec voisins et registre d'entrée ; la classe (b) sert de témoin, non de mesure. |
| R6 | P3 mesuré sur des fixtures d'étalonnage ; P4 inopérant sans outil. | **Accepté.** P3 préenregistré sur `t01`–`t08` ; P4 reformulé en longueur de journal (40, 120, 360). |
| R7 | L'échelle était comptée dans l'oracle de mesure. | **Accepté.** Retirée de l'oracle de mesure (§ 4). |
| R8 | Avec un catalogue identique aux trois bras, on mesure H3, pas H4. | **Accepté, puis arbitré par l'auteur du cahier des charges** (D5, 2026-10-30) : le contraste de H4 est **l'absence de table côté LLM** ; D1+ reçoit la table. |
| R9 | Un modèle qui dit toujours `no_projection` gagne 50 % sur huit dossiers binaires. | **Accepté et amplifié.** Décompte **par registre ambigu** (20 par dossier), arbitré par l'auteur (D4). |

### Relecture technique — 7 risques bloquants

| # | Reproche | Suite |
| --- | --- | --- |
| T1 | Le modèle d'adressage du § 4.4 n'est pas reproductible : la sonde citée ne vient pas du fil. Justification : `ModbusDeviceContext.async_getValues` renverrait `DEVICE_BUSY`. | **Résultat accepté, justification contredite.** Mesuré sur le dépôt le 2026-10-30 : `ModbusDeviceContext.async_getValues` **n'existe pas** dans la 3.15.0 installée (`hasattr` → `False`, `AttributeError` à l'appel). Le relecteur décrit un autre code que celui du dépôt. En revanche, sa conclusion est **juste** : par trames MBAP brutes, un bloc déclaré à `lo` expose `lo` — et non `lo + 1` — sur le fil ; la sonde de révision 1 lisait donc une table décalée. |
| T2 | Le test d'offset est impossible à écrire sur le témoin prévu. | **Accepté.** Révision 2 § 1 : test par trames brutes. |
| T3 | `hr` et `ir` ne cohabitent pas sous un même `unit_id`. | À vérifier en relecture 2 (lentille technique), point C. |
| T4 | La portabilité n'est pas assurée par un simple `< 4`. | **Accepté.** Épinglage exact `pymodbus==3.15.0`, version lue dans le manifeste, test qui échoue hors intervalle. |
| T5 | Le journal n'est pas « ce que le scanner aurait produit ». | **Accepté.** Le journal est une **capture enregistrée** avec provenance et hash (§ 2). |
| T6 | Le rejeu n'est pas déterministe. | **Accepté.** `replay()` spécifié avec état initial, ordre d'écriture et comparaison exacte (§ 2). |
| T7 | Le contrôle positif PC-b est infaisable tel qu'écrit. | **Accepté, arbitré par l'auteur** (D6) : contrôle **partiel assumé**, ce qu'il couvre et ne couvre pas est écrit. |

### Ce que la relecture technique se trompe de dire

Le relecteur technique corrige le plan en affirmant que l'adaptateur
`modbus_write` « existe bien » et passe `device_id=unit_id`. C'est exact au
2026-10-30 **après** le commit `f76da6d`, qui a précisément remplacé `slave=`
par `device_id=` : le plan de révision 1, écrit **avant** ce commit,
décrivait l'état antérieur. Aucun des deux documents n'avait tort sur son
propre instant ; la correction d'outil est indépendante de ce plan.

---

## Révision 2 du plan — en cours

Deux relectures indépendantes commandées le 2026-10-30 14:35. Verdicts à
consigner à réception, avec la même règle : un reproche fondé sur un
comportement non mesuré est contré, pas accepté d'office.
