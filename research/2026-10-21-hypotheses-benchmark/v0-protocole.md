# Protocole V0 — porte de validité de l'instrument

**Statut.** `proposition` — contrôle implémenté, testé hors ligne et exécuté
sur nato en deux smokes (8 étapes, 1 répétition) ; le premier passage de
calibration et le seuil `X` restent à faire. Le contrôle porte sur la fixture
MQTT existante à deux abonnements, répétés en alternance.
**Date.** 2026-10-21 (Europe/Brussels, UTC+02:00). Dernière révision :
**2026-10-21 12:45 (Europe/Brussels, UTC+02:00)**.
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

**Réserve de tours.** La boucle du fournisseur réserve ses deux derniers tours
à l'appel terminal : à `max_turns = T`, le modèle ne peut collecter que `T - 2`
observations. Une procédure de N étapes consomme donc N appels de données et
`N + 2` tours. Le plafond des deux budgets étant 32, `N = 30` est la borne
haute : au-delà, le modèle serait forcé de conclure avant d'avoir exécuté la
procédure déclarée, et l'échec se lirait à tort comme une faiblesse du modèle.
La réserve ne donne aucune capacité de collecte supplémentaire : elle remplace
deux tours perdus, elle n'en ajoute pas.

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
- `benchmarks/experiments/v0_control_live.py` : lanceur nato sur la fixture
  MQTT existante, inchangée. Il précontrôle les deux abonnements déclarés,
  exécute les deux bras dans un ordre alterné selon la répétition, détruit la
  fixture à chaque répétition pour retirer de nouveaux secrets, et écrit
  `results.json` avec l'issue des quatre cas. Commande `cleanup` pour
  récupérer un contrôleur interrompu.
- `.github/workflows/v0-control.yml` : `workflow_dispatch` manuel sur
  `nato-master`, sous le verrou de laboratoire partagé, depuis `dev/2`.

Ce qui est imposé par le code :

- le briefing ne porte que la procédure — sujet littéral, identifiant optionnel,
  fenêtre d'écoute, 1 à 30 étapes ; un sujet à joker, un champ d'oracle ou une
  valeur non finie sont refusés ;
- l'oracle lie un condensat de charge utile par étape au condensat du
  briefing ; il ne peut pas être rejoué sur une autre instance. Deux étapes
  peuvent nommer le même abonnement, donc la même charge utile : la fraîcheur
  est celle de l'essai (les canaris sont tirés à chaque démarrage de fixture)
  et l'évaluateur exige toujours une preuve liée **distincte** par étape, si
  bien qu'une seule observation ne peut pas répondre à deux étapes ;
- les deux bras exécutent les étapes dans l'ordre déclaré et citent une preuve
  par étape ; le bras règles n'accepte pas d'oracle ; `finish_control` refuse
  une liste incomplète (une référence par étape déclarée), sans quoi le bras
  LLM pouvait clore un contrôle tronqué qui se lisait comme un échec de modèle ;
- la commande `summary` projette le résultat dans le journal du run — issue,
  nombres d'étapes, discordances et dépense — sans charge utile, canari ni
  identifiant ;
- la mesure est recalculée depuis le journal : étapes exécutées, sautées,
  charges utiles discordantes, références en trop. La réussite exige le statut
  terminal `completed`, toutes les étapes, aucune discordance et aucune
  référence supplémentaire ;
- un run tronqué par le budget est enregistré `budget_exceeded` des deux côtés,
  jamais lu comme un échec de compétence.

Vérification : `tests/test_v0_control.py`, 40 tests hors ligne (broker et
fournisseur simulés, exécuteur et enregistreur réels) ; le précontrôle, les
deux bras, le refus d'une clôture incomplète, la projection du journal, la
lecture des quatre issues et la reprise sur dossier interrompu sont couverts.

**Smokes du 2026-10-21 (8 étapes, 1 répétition, `qwen3.8:27b`).** Le premier a
tourné de bout en bout sur `nato-master` et rendu `instrument_defect` : le bras
règles a réussi 8/8 étapes en 40 s et 8 appels (0 $) ; le bras LLM s'est arrêté
après 6 étapes sur 8, en 53 s, 6 appels et 0,022 $, sans discordance ni
référence en trop. Le harnais réservait ses deux derniers tours à la clôture et
la terminait sans vérifier la complétude : défaut d'instrument, pas une mesure
de compétence. Deux corrections en découlent — `finish_control` refuse une
liste incomplète, et `N` est ramené à 30 pour laisser deux tours de clôture
dans le plafond de 32. Le second smoke, sur la version corrigée, rend
`valid_control` : les deux bras réussissent 8/8 sans discordance ni référence
en trop, le bras règles en 40 s et 8 appels (0 $), le bras LLM en 64,6 s,
8 appels et 0,029 $. Un smoke n'est pas le premier passage : `X` reste non
gelé.

Ce qui reste avant un premier passage :

1. le premier passage réglé sur 30 étapes et 3 répétitions ;
2. le gel de `X` dans le manifeste, après ce passage seulement, et la
   déclaration de saturation si les deux bras réussissent partout.

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
