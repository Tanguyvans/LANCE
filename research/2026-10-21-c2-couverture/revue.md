# Relecture adverse du plan C2 : résultat

**Date : 2026-10-21 (Europe/Brussels, UTC+02:00).**
Deux relectures indépendantes, en lecture seule, sur le plan (retiré au commit `4ffadcd`) :
une lentille « honnêteté de la baseline et test de clôture », une lentille
« mesurabilité et faisabilité ». Toutes deux concluent à l'arrêt de C2 tel que
spécifié.

## Verdict

**Les deux candidats sont morts, pour des raisons différentes et convergentes.**
La construction est falsifiable dans sa forme — portes, hash, critère
d'abandon — mais elle ne peut pas produire la revendication visée.

## Ce qui est démontré, et non supposé

Les faits de code suivants ont été vérifiés directement avant d'écrire ceci :

| Fait | Emplacement |
| --- | --- |
| Le harnais vivant passe `families=1` en dur | `benchmarks/experiments/api_reference_live.py:476` |
| Tout `scenario_id` autre que `s_api_organisations` est rejeté | `benchmarks/experiments/api_reference.py:82` |
| `family_id` vaut `scenario_id` : deux scénarios API comptent 2 familles | `benchmarks/experiments/v2_campaign.py:71`, `:308` |
| `bootstrap_mean_ci` refuse moins de deux familles par un simple message, sans test d'indépendance | `src/benchmark/inference.py:25` |

Conséquence : « deux familles » est un **compteur**, pas une mesure
d'indépendance. Le registre le dit déjà pour toutes les variantes API
(`statistical_independence: not_established`, `mechanism_family_independence:
"Not established; shared simulators/templates remain clustered."`).

## Candidat A — `s_api_jetons` : mort par construction

Le plan se contredit en deux lignes. Il attribue à D1+ la règle « demande un
jeton pour chaque service de l'inventaire » (plan § Candidat A), puis
suppose pour la survie que « l'ensemble des services n'est pas public ». Les
deux ne peuvent pas être vraies ensemble. Trilemme exhaustif :

1. services publics ou dérivables de l'inventaire → D1+ énumère et réussit ;
2. services non publics mais le refus nomme le service → D1+ parse le refus ;
3. services non publics et refus muet → il faut deviner un nom de service,
   exactement l'anti-patron « mesurer la devinette de chemins »
   ([PISTES](../../objectifs/PISTES.md)).

Aucune branche ne respecte la barre. Le garder « pour le démontrer » est
circulaire : la démonstration est déjà faite sur papier.

## Candidat B — `s_api_etats` : mort, et mal rattaché

Même dilemme, avec une issue de plus :

1. la transition est documentée → la boucle générique de D1+ la trouve ;
2. elle ne l'est pas → devinette de chemin, angle mort artificiel ;
3. l'espace d'états est énumérable mais D1+ échoue par budget → contredit la
   clause du plan lui-même (« un échec par budget n'est jamais une mesure de
   compétence »).

Le plan n'établit à aucun endroit que l'espace d'états est **non énumérable**.
Par ailleurs, B n'est pas C06 : C06 exige de fournir la politique aux deux bras,
or B repose sur un prérequis non publié. Le mécanisme correspond à
`X40-C09-D05` (`s_prerequis_conjoints`, C09/G10), avec un volet C10. La
recommandation « chaîne de prérequis » a déjà été rejetée le 2026-10-20 pour
« oracle contradictoire » ; ce motif n'est traité nulle part dans le plan.

## Candidat B2 — la seule variante qui survit techniquement

Politique entièrement publique, toutes les opérations documentées, mais l'ordre
utile n'est trouvé que par recherche : D1+ échoue par explosion combinatoire,
pas par information manquante.

Ce qu'elle coûte, et pourquoi elle n'est pas le plan écrit :

- elle mesure une **efficacité de recherche sous budget**, pas la clôture
  informationnelle ;
- elle exige d'assouplir explicitement le critère « échec survivant à un budget
  non contraignant », puisque c'est le budget qui discrimine ;
- elle appartient à C09/C10, pas à C06 ;
- il faut prouver la borne inférieure de taille d'état, et `X40` n'a aucune
  mesure (`feasible_witness_path: null`, `observed_candidates: null`) ;
- il faudrait une famille supplémentaire pour que `family_inference` ait plus
  de deux unités, et aucune revendication à 95 % n'est possible à n = 2 : le
  bootstrap sur des moyennes de famille donne `[min, max]` comme pseudo-IC.

## Ce que les deux lentilles ont trouvé en commun

- **La famille 1 ne compte pas.** `s_api_organisations` est elle-même une
  omission de couverture : le contrat public énonce la règle par membre, donc
  D1+ la referme. La compter comme l'une des deux familles revient à
  revendiquer une supériorité sur un scénario dont on sait qu'il mesure une
  limite déclarée.
- **Le test de clôture n'a pas de plancher de compétence.** Il est hashé sur la
  prose, pas sur l'exécutable, sans contrôle positif, et jugé par la même
  équipe. Un D1+ volontairement faible échoue partout et valide C2 à vide.
- **Le budget est un plafond déguisé.** `request_budget=16` en dur, déjà
  consommé à 10–11 par le pilote de référence ; A et B le dépasseraient.
- **Le harnais n'est pas paramétrable.** `_route` ne reconnaît pas de nouvelles
  routes, `evaluate_trial` ne compte aucune divulgation hors objet/collection,
  l'oracle est verrouillé sur `s_api_organisations`.
- **Le repli C3 ne libère pas le chemin critique** : `independent_families`
  reste requis, et sans deuxième famille aucun intervalle n'est calculable.

## Décision proposée

1. **Arrêter C2 tel que spécifié.** Ne pas construire A, ne pas construire B
   sous C06.
2. **Consigner le résultat** : ce dossier devient le mémo de falsification —
   pourquoi le test de clôture élimine les mécanismes d'autorisation API. C'est
   une contribution de méthode honnête et publiable comme limite.
3. **Basculer sur C3** avec `s_api_organisations` comme étude de cas de
   couverture, explicitement étiquetée comme telle.
4. **Si une famille C2 reste voulue**, la seule voie conforme est B2 sous
   C10/C09, avec politique publique, borne inférieure prouvée, amendement
   écrit du critère de budget et une famille supplémentaire. Ce n'est pas
   poursuivi dans la campagne en cours : c'est un choix de thèse, pas un ajout
   de scénario.

## Point le plus grave

Le plan hérite d'une famille dont il sait qu'elle échoue au test de clôture, et
il compte dessus pour atteindre « deux familles ». Corriger ce point vide le
plan de son objet. C'est pour cela que la recommandation est l'arrêt, pas une
réécriture cosmétique.
