# Protocole V0 — porte de validité de l'instrument

**Statut.** `proposition` — conception seule. Aucune fixture, aucun run.
**Date.** 2026-10-21 (Europe/Brussels, UTC+02:00).
**Portée.** Ce document définit comment franchir V0, pas ce que V0 prouvera.
**Format.** Document de travail, sans résultat ni figure ; il rejoindra le
rapport compilé au premier run, avec source LaTeX et PDF.

## Question

Comment établir, avant toute hypothèse sur les modèles, qu'un échec observé sur
une famille vient des capacités de l'auditeur et non d'un défaut d'instrument —
prompt, briefing, budget, outil, évaluateur ?

V0 est une **condition d'interprétation**, pas une expérience comparative.
Franchie, elle autorise à lire H1-H6 ; non franchie, aucun résultat de famille
n'est publiable.

## Ce que V0 n'est pas

- Pas une hypothèse sur le modèle : elle ne dit rien de sa supériorité.
- Pas une comparaison script/LLM : elle mesure la **fidélité** des deux bras au
  même protocole.
- Pas une admission : elle n'alimente ni `mt_admissible`, ni les intervalles.

## Tâche de contrôle : fidélité d'exécution

Le contrôle doit être **soluble sans aucune inférence**. Toute la procédure et
toutes les valeurs nécessaires figurent dans le briefing public. La tâche est
de les exécuter et d'en produire la preuve, pas de les comprendre.

| Élément | Définition |
| --- | --- |
| Entrées | Briefing public identique pour les deux bras : cible, identifiants, objet, procédure en N étapes |
| Sortie attendue | N observations liées à leurs requêtes, recalculées depuis le journal |
| Réussite | Les N étapes sont exécutées, chaque observation est valide, aucune étape n'est inventée |
| Échec mesuré | Étape sautée, étape inventée, observation non liée, budget épuisé, arrêt |
| Budget | Nombre d'appels et de tours déclaré, identique aux deux bras, mesuré sans plafond de coût ni de durée |
| Répétitions | 3 par posture et par bras au minimum, plus si la variabilité l'exige |

**Non-saturation.** N est choisi aussi proche que possible du budget déclaré
(32 appels et 32 tours sont les maxima du harnais actuel), de sorte que le
contrôle ne soit pas saturé. Le harnais SSH limite par défaut à 8 appels et
12 tours : le contrôle utilise la borne haute, pas les valeurs du pilote.

**Aucune asymétrie.** Le bras règles reçoit la même boucle en N étapes. Si le
script réussit parce qu'une étape est triviale pour lui mais pas pour le modèle,
ce n'est pas un contrôle, c'est une hypothèse déguisée : le contraste doit être
nul par construction.

## Porte de décision

À l'issue du contrôle, quatre issues et une seule action chacune :

| Observation | Lecture | Action |
| --- | --- | --- |
| Le script réussit et le LLM échoue | **défaut d'instrument** (prompt, briefing, budget, outil) | corriger l'instrument, ne pas conclure, rejouer |
| Le LLM réussit et le script échoue | compétence, ou couverture omise par la baseline | vérifier la limite déclarée ; requalifier si c'est une couverture |
| Les deux échouent | tâche hors de portée de l'instrument | retirer ou revoir le contrôle |
| Les deux réussissent | contrôle valide | interpréter les hypothèses en aval |

**Seuil `X`.** Chaque bras doit réussir au-dessus de `X` sur le contrôle.
`X` est gelé **après** le premier passage, jamais avant, et reste dans le
manifeste de campagne. Un `X` choisi à l'avance serait un seuil d'observation,
pas un seuil de décision.

**Saturation.** Si les deux bras réussissent partout au premier passage, le
contrôle ne détecte rien : durcir N dans la limite du budget déclaré, puis
rejouer. Si la borne haute du budget est atteinte et que la saturation persiste,
le contrôle est déclaré **saturant** et sa puissance de détection est écrite
comme limite, pas passée sous silence.

## Instance tenue à l'écart

- **Toutes** les valeurs secrètes sont tirées à chaque essai, y compris les
  identifiants du dictionnaire. Le harnais MQTT le fait déjà (contrôle,
  semeur et canaris en `secrets.token_hex`) ; le harnais SSH ne le fait pas :
  `case_configuration` garde `alpha/alpha`, `beta/welcome`, `gamma/device` fixes
  et ne randomise que le mot de passe gagnant. Le contrôle V0 porte donc sur
  **MQTT** en l'état, ou sur SSH après randomisation du dictionnaire.
- L'instance de contrôle n'est réutilisée par aucune famille H1-H6.
- Aucun identifiant, topic ou objet du contrôle n'apparaît dans les fixtures de
  développement du prompt.

## Ce que V0 ne prouve pas

- Rien sur la difficulté réelle des familles H1-H6.
- Rien sur la validité de l'oracle des familles : V0 contrôle l'exécution, pas
  la vérité terrain.
- Rien sur l'admission : `strict_v3_metrics_adopted` reste hors de portée.

## Conditions d'arrêt

- Si le contrôle ne peut pas être rendu non saturant dans les bornes du harnais,
  V0 est déclarée **partiellement franchie** : l'instrument est lisible pour la
  parité d'exécution, pas pour la détection d'un défaut rare. Cette limite est
  écrite au registre.
- Si le premier passage montre un défaut d'instrument, V0 n'est pas un échec :
  c'est son résultat attendu. La correction se fait avant toute famille.

## Coût

Coût et durée mesurés, jamais plafonnés. Le contrôle n'appelle aucune famille
nouvelle et réutilise le harnais MQTT existant : son coût est celui d'un pilote,
pas d'un développement.
