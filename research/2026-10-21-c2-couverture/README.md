# C2 : un scénario où la baseline déclarée échoue

**Question.** Peut-on construire, sans retirer de règle ni créer d'angle mort,
un scénario où une automatisation paramétrique préenregistrée et déclarée
compétente échoue, là où un modèle réussit ?

**Statut.** `rejetée` — les deux mécanismes sont instruits et écartés. Aucune
fixture, aucun run. La construction proposée est conservée comme trace, avec
son verdict.

**Dates.** Étude ouverte et classée le 2026-10-21 (Europe/Brussels, UTC+02:00).
Dernière révision : **2026-10-21 10:38 (Europe/Brussels, UTC+02:00)**.

**Format.** Mémo de falsification, sans résultat ni figure : ni source LaTeX ni
PDF. Le dossier passera au format scientifique classique si un run est un jour
produit.

## Synthèse

Deux relectures adverses indépendantes — honnêteté du test de clôture,
mesurabilité et faisabilité — concluent à l'arrêt. Les deux candidats sont
morts **sur papier**, avant toute ligne de code :

- **A (`s_api_jetons`)** se contredit : son D1+ suppose un inventaire des
  services, sa survie suppose que cet inventaire n'existe pas. Le trilemme
  n'a aucune branche conforme.
- **B (`s_api_etats`)** n'a que trois issues : transition documentée (D1+ la
  trouve), non documentée (devinette de chemin), ou hors budget (contredit le
  critère « l'échec survit à un budget non contraignant »). Il est de plus mal
  rattaché : c'est C09/C10, pas C06.

Deux constats de fond dépassent les candidats :

1. **La famille 1 ne compte pas.** `s_api_organisations` est elle-même une
   omission de couverture — le contrat public énonce la règle par membre, donc
   D1+ la referme. La compter pour atteindre « deux familles » revient à
   revendiquer une supériorité sur une limite déclarée.
2. **« Deux familles » est un compteur, pas une mesure d'indépendance.**
   `family_id` vaut `scenario_id`, et le registre marque toutes les variantes
   API `statistical_independence: not_established`.

Décision : **C2 s'arrête.** Le papier revient à C3 (coût à résultat non
inférieur), avec `s_api_organisations` comme étude de cas de couverture
explicitement étiquetée comme telle. La seule variante C2 qui survivrait
techniquement (B2, coût de recherche d'état sous C09/C10) exige un amendement
du critère de budget, une borne inférieure prouvée et une famille
supplémentaire : elle n'est pas poursuivie dans la campagne en cours et
relèverait d'une autre thèse.

## Documents

- [revue.md](revue.md) — le verdict des deux relectures, les faits de code
  vérifiés, les trilemmes, la variante B2 et la décision.
- [plan.md](plan.md) — la construction proposée, conservée comme trace. Son
  en-tête porte le statut de rejet.

## Points encore ouverts

- **C3** : `independent_families` reste requis pour un intervalle, et le
  repli C3 ne dispense donc pas de construire une deuxième famille
  indépendante. Ce point n'est pas résolu par l'arrêt de C2, mais ce n'est plus
  le conducteur du travail : c'est la condition d'une revendication
  statistique.
- **Si B2 est poursuivi** : prouver la borne inférieure de taille d'état,
  écrire l'amendement du critère de budget, et le rattacher à C09/C10.
- **Le test de clôture lui-même** n'a toujours ni contrôle positif ni
  exécutable hashé. Tant que ce n'est pas le cas, aucun futur C2 ne sera
  falsifiable — c'est un livrable de méthode, indépendant du choix C2/C3.
- **Le harnais n'est pas paramétrable** : `families=1` en dur, oracle et
  évaluateur verrouillés sur `s_api_organisations`. À corriger avant toute
  deuxième famille, quelle qu'elle soit.

## Voir aussi

- [Pistes de la plateforme](../../objectifs/PISTES.md)
- [État courant](../../objectifs/ETAT-COURANT.md)
- [Plan V2 et avancement consolidé](../2026-10-12-recentrage-corpus/README.md)
- [Comparaison script/LLM `s_api_organisations`](../../benchmarks/experiments/api-reference/README.md)
