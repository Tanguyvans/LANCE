# Protocole V0 — porte de validité de l'instrument

**Statut.** `partiellement franchie` — contrôle implémenté, testé hors ligne et
exécuté sur nato : deux smokes de 8 étapes, un passage de 30 étapes qui a rendu
`instrument_defect` et fait corriger le budget de tours, puis le passage de
calibration à 24 étapes × 3 répétitions, `valid_control`, `X = 0,9` gelé et
saturation déclarée. Le contrôle porte sur la fixture MQTT existante à deux
abonnements, répétés en alternance.
**Date.** 2026-10-21 (Europe/Brussels, UTC+02:00). Dernière révision :
**2026-10-21 14:34 (Europe/Brussels, UTC+02:00)**.
**Portée.** Ce document définit comment franchir V0, ce que V0 a rendu, et ce
qu'elle ne prouve pas.
**Format.** Document de travail, sans figure ; il rejoindra le rapport compilé
avec source LaTeX et PDF.

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
12 tours : le contrôle utilise la borne haute, pas les valeurs du pilote. Les
deux exigences se contredisent en partie — monter N sature moins mais laisse
moins de tours de routage — et la borne retenue est celle qui garde la marge :
`N = 24`.

**Réserve de tours.** La boucle du fournisseur réserve ses deux derniers tours
à l'appel terminal : à `max_turns = T`, le modèle ne peut collecter que `T - 2`
observations. Une procédure de N étapes consomme donc N appels de données et au
moins `N + 2` tours. La réserve ne donne aucune capacité de collecte
supplémentaire : elle remplace deux tours perdus, elle n'en ajoute pas.

**Marge de routage.** Un tour peut aussi ne produire aucun appel de données :
réponse en texte seul, appel répété refusé, arguments malformés. Ces tours ne
consomment pas le plafond d'appels, seulement le plafond de tours. Le premier
passage de 30 étapes en a dépensé quatre sur les 32 tours et s'est clos sans
décision terminale : la porte a lu `instrument_defect`, qui est bien un défaut
d'instrument et non une faiblesse du modèle. Le budget distingue donc deux
plafonds — `N` appels de données, `N + 2 + 6` tours — et `N = 24` est la borne
haute qui garde six tours de routage sous le maximum de 32 du harnais. Le
contrôle refuse désormais un budget dont le plafond de tours ne couvre pas la
réserve et la marge.

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
pas un seuil de décision. Il est gelé à `0,9`
(`benchmarks/experiments/v0-control-manifest.json`) : à trois répétitions,
trois succès passent, un échec échoue.

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
- Rien sur un défaut rare : le contrôle est saturant au premier passage, donc
  il détecte un défaut répété (un échec sur trois suffit à passer sous `X`),
  pas un défaut intermittent qu'aucune des trois répétitions n'aurait capté.

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
  récupérer un contrôleur interrompu ; commande `summary` pour le journal.
- `benchmarks/experiments/v0-control-manifest.json` : le seuil `X` gelé, la
  déclaration de saturation et la provenance de la mesure (run, commit, modèle,
  succès par bras). Absent, le contrôle enregistre `X` non gelé.
- `.github/workflows/v0-control.yml` : `workflow_dispatch` manuel sur
  `nato-master`, sous le verrou de laboratoire partagé, depuis `dev/2`.

Ce qui est imposé par le code :

- le briefing ne porte que la procédure — sujet littéral, identifiant optionnel,
  fenêtre d'écoute, 1 à 24 étapes ; un sujet à joker, un champ d'oracle ou une
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
  nombres d'étapes, discordances, dépense et, pour le bras LLM, le routage des
  tours en nombres (appels refusés, arguments malformés, cause d'arrêt) — sans
  charge utile, canari ni identifiant ;
- le contrôle refuse un budget dont le plafond de tours ne couvre pas la
  procédure, la réserve de clôture et la marge de routage ;
- `X` est lu dans un manifeste de campagne, jamais dans le code : manifeste
  absent signifie `X` non gelé, et un seuil calibré sur un autre nombre d'étapes
  ne s'applique pas ;
- la mesure est recalculée depuis le journal : étapes exécutées, sautées,
  charges utiles discordantes, références en trop. La réussite exige le statut
  terminal `completed`, toutes les étapes, aucune discordance et aucune
  référence supplémentaire ;
- un run tronqué par le budget est enregistré `budget_exceeded` des deux côtés,
  jamais lu comme un échec de compétence.

Vérification : `tests/test_v0_control.py`, 55 tests hors ligne (broker et
fournisseur simulés, exécuteur et enregistreur réels) ; le précontrôle, les
deux bras, le refus d'une clôture incomplète, la projection du journal, le
routage des tours, le refus d'un budget sans marge, la lecture du manifeste, la
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

**Premier passage du 2026-10-21 (30 étapes, 3 répétitions, `qwen3.8:27b`,
run 39592971744, `dev/2` à `ae32dd7`).** Le bras règles réussit 3/3, à 30 appels
et 150 s par répétition. Le bras LLM réussit 2/3 : la troisième répétition
exécute 28 appels de données dans les 32 tours, puis se clôt sans décision
terminale (`outcome: unknown`, 320 s, 0,418 $). Quatre tours ont donc produit
autre chose qu'un appel de données, et le plafond de tours, égal aux 32 du
harnais, n'en laissait aucun. La porte rend `instrument_defect` : c'est le
résultat attendu d'un contrôle, pas une mesure de compétence. La correction
donne au bras LLM six tours de routage en plus de la réserve de clôture et
ramène `N` à 24 (commit `375141b`).

Ce passage n'est pas le premier passage de calibration : il a servi à corriger
l'instrument.

**Passage de calibration du 2026-10-21 (24 étapes, 3 répétitions,
`qwen3.8:27b`, run 39597630837, `dev/2` à `375141b`).** Les deux bras
réussissent partout : `valid_control`, 24/24 étapes sur chacune des trois
répétitions, aucune discordance de charge utile, aucune référence en trop. Le
bras règles dépense 24 appels et 120 s par répétition (0 $) ; le bras LLM
dépense 24 appels de données et un appel de clôture, entre 160 et 182 s, pour
0,026 $, 0,163 $ et 0,194 $ selon la répétition. Le routage des tours est
enregistré : les trois répétitions atteignent la clôture acceptée
(`cause=accepted_save`) sans aucun tour perdu, en 2, 25 et 25 tours utiles.

**Saturation déclarée.** Les deux bras réussissent partout au premier passage,
et `N = 24` est la borne haute compatible avec la marge de routage : durcir `N`
dans les bornes du harnais reviendrait à retirer cette marge et à reproduire le
défaut du passage précédent. Le contrôle ne détecte donc pas un défaut de taux
inférieur à un échec sur trois ; il détecte un défaut répété. Cette limite est
au registre, elle n'est pas passée sous silence.

**Seuil `X` gelé.** `X = 0,9`, dans
`benchmarks/experiments/v0-control-manifest.json`, avec le run et le commit de
la mesure. Un bras doit réussir **strictement au-dessus** de `X` : à trois
répétitions, trois succès passent et un seul échec échoue. Le seuil n'est pas
un taux observé recopié, c'est le plancher qui aurait refusé le passage
précédent (2/3) et accepté celui-ci (3/3). Le manifeste porte aussi `saturating`
et la lecture de la saturation ; le contrôle relit ce fichier, refuse un seuil
qui ne serait pas gelé et refuse qu'un seuil calibré sur un autre nombre
d'étapes s'applique.

**V0 est déclarée partiellement franchie**, au sens de la première condition
d'arrêt : l'instrument est lisible pour la parité d'exécution et pour un défaut
répété, pas pour un défaut rare.

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
