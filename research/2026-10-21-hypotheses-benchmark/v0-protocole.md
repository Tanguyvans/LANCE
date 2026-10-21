# Protocole V0 — porte de validité de l'instrument

**Statut.** `proposition` — contrôle implémenté et testé hors ligne, sans
fixture multi-topic ni run. Les deux bras, l'oracle et l'évaluateur existent ;
la fixture en N sujets et le lancement sur nato restent à construire.
**Date.** 2026-10-21 (Europe/Brussels, UTC+02:00). Dernière révision :
**2026-10-21 11:12 (Europe/Brussels, UTC+02:00)**.
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

## Implémentation actuelle (2026-10-21)

Contrat `v0-control-calibration-v1`, scénario `v0_fidelite_mqtt`.

- `benchmarks/experiments/v0_control.py` : validation du briefing public,
  oracle, bras règles, évaluateur, ligne de commande hors ligne.
- `benchmarks/experiments/v0_control_llm.py` : bras LLM sur le même exécuteur
  et le même enregistreur de preuves que les harnais existants ; outils
  `run_step` et `finish_control`.

Ce qui est imposé par le code :

- le briefing ne porte que la procédure — sujet littéral, identifiant optionnel,
  fenêtre d'écoute, 1 à 30 étapes ; un sujet à joker, un champ d'oracle ou une
  valeur non finie sont refusés ;
- l'oracle lie un condensat de charge utile **distinct** par étape au condensat
  du briefing ; il ne peut pas être rejoué sur une autre instance ;
- les deux bras exécutent les étapes dans l'ordre déclaré et citent une preuve
  par étape ; le bras règles n'accepte pas d'oracle ;
- la mesure est recalculée depuis le journal : étapes exécutées, sautées,
  charges utiles discordantes, références en trop. La réussite exige le statut
  terminal `completed`, toutes les étapes, aucune discordance et aucune
  référence supplémentaire ;
- un run tronqué par le budget est enregistré `budget_exceeded` des deux côtés,
  jamais lu comme un échec de compétence.

Vérification : `tests/test_v0_control.py`, 32 tests hors ligne (broker simulé,
exécuteur et enregistreur réels) ; avec les harnais voisins, 224 tests passent.
Aucun run sur nato, aucune fixture, aucun seuil `X`.

Ce qui reste avant un pilote :

1. une fixture qui publie N charges utiles distinctes sur N sujets, avec les
   identifiants tirés à chaque essai — la fixture MQTT actuelle n'a que deux
   sujets ;
2. un lanceur nato réutilisant l'infrastructure existante, dans la campagne V2
   et son manifeste ;
3. les répétitions et le gel de `X` après le premier passage.

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
