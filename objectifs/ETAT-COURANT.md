# État courant

**Dernière mise à jour : 2026-10-23 14:33 (Europe/Brussels, UTC+02:00).**

Point de reprise : ce qui est vrai, ce qui bloque, ce qui vient ensuite. Le
détail des études reste dans `research/` ; l'historique des runs reste dans git.

## But

Un auditeur de réseaux IoT/IIoT autonome et prouvable : il explore, trouve,
vérifie et rapporte, avec des preuves recalculables.

Question mesurée : **quand un agent LLM apporte-t-il quelque chose qu'une
automatisation à règles ne peut pas apporter, à outils, preuves et budgets
identiques ?**

## Priorités

1. **Le benchmark** — instrument comparatif, structuré par le
   [registre d'hypothèses](../research/2026-10-21-hypotheses-benchmark/README.md)
   (V0 et H1-H6), pas par une liste de scénarios.
2. **La plateforme** — déployer, lancer, suivre, récupérer, isoler, nettoyer.

L'entraînement des modèles est hors priorité. Aucune étape n'est datée : une
étape commence quand la précédente est vérifiée.

## État vérifié

| Élément | État | Preuve |
| --- | --- | --- |
| V0, contrôle MQTT | `valid_control`, `X = 0,9`, contrôle **saturant**, 24 étapes × 3 répétitions | `benchmarks/experiments/v0-control-manifest.json` |
| V0, SSH | non couverte : dictionnaire d'identifiants fixe | `v0-protocole.md` |
| H2, `s_mqtt_formats` | mesurée le 2026-10-22, 3 répétitions, 72 bras ; prédiction tenue mais **gain absorbé par un bras par convention** (0,5 contre 0,0 pour les parseurs déclarés, 1,0 pour le bras convention ; 1 dossier sur 2) | `research/2026-10-21-hypotheses-benchmark/h2-protocole.md` |
| Pilotes SSH et MQTT | 6/6 pour les deux bras, 3 répétitions, `qwen3.8:27b` et `gemma4:26b-a4b-it` ; MoE ≈ 2× le coût et 1,3–1,7× la durée | runs `39465619725`, `39467657683`, `39480713050`, `39482737529` |
| `s_api_organisations` | étude de cas de couverture, **non admise** (une famille, une répétition) | `benchmarks/experiments/api-reference/` |
| Admission de campagne | `mt_admissible = false` ; `strict_v3_metrics_adopted` n'est jamais satisfait | `src/benchmark/v2_campaign.py` |
| Inférence | aucun intervalle calculable ; à n = 2 familles, pseudo-intervalle seulement | `src/benchmark/inference.py`, `configuration_uniformity` |
| Familles H1, H3, H4, H5 | non ouvertes ; `s_chaines_identites` et `s_registres_constructeur` n'existent pas | registre d'hypothèses |
| Corpus | 29 scénarios, 288 entrées de vérité terrain. **243/288 (84,4 %)** à signature selon la lecture interprétative de l'audit ; l'index dérivé, binaire, donne **282/288** et 6 entrées logiques (S15, S22, S28) | `benchmarks/ground_truth/`, `benchmarks/labels/derived_index.json`, [audit de couverture](asiaccs-2027/audit-couverture.md) |
| Branche `dev/2` | 16 commits derrière `main` | `git log origin/dev/2..main` |

## Blocages

1. **La mesure.** `inference.py` calcule une p-value bilatérale autour de 0 :
   le signe est perdu, `delta_threshold` n'entre dans aucune décision, et à
   n = 2 familles la p-value ne peut valoir que 0, 0,5 ou 1. L'outil produit
   l'apparence d'une inférence qu'il ne fournit pas.
2. **La condition d'ouverture.** D1+ (« D1 + toutes les règles dérivables des
   entrées publiques ») n'existe qu'en doctrine. H1, H3, H4 et H5 en dépendent :
   sans lui, aucune ne peut être ouverte de façon défendable.
3. **Le corpus.** Il a été construit autour de ce que les règles trouvent
   (84,4 % à signature). Le contrôle sain officiel (`S1h`) n'est pas dans le
   catalogue. Un écart nul y est attendu par construction.
4. **Les critères de décision.** La branche « soumettre » exige un critère
   inatteignable, « repositionné » exige une puissance non définie, et
   « ne pas soumettre » rejette tout effet mono-famille — ce que sont tous les
   designs actuels. Ils ne peuvent pas dire non.
5. **Le livrable.** L'artefact anonymisé exigé par l'appendice Open Science
   n'existe pas, et les harnais vivants ne tournent que sur nato.

## Prochaines étapes

Dans l'ordre des dépendances, sans dates.

1. **Trancher la métrique** : crédit gradué de strict-v3 écrasé en TP binaire
   par le funnel ; réparer ou retirer `inference.py`.
2. **Décider D1+** : l'implémenter, ou abandonner H1/H3/H4/H5 pour cette
   campagne et l'écrire comme limite.
3. **Extraire le harnais paramétrable** : `scenario_id`, `families=1`, oracle
   et évaluateur sont verrouillés par module ; les harnais sont dupliqués à
   73–80 %.
4. **Ouvrir une famille** (H3 ou H4) et étendre H2 (autres schémas, second
   modèle).
5. **Produire l'artefact anonymisé** : fixtures H2, oracle, évaluateur et
   contrôle V0, exécutables hors laboratoire.
6. **La plateforme** : déploiement et lancement reproductibles.

Sérialisation du laboratoire : deux runs ne se parallélisent pas (verrou
`lance-lab-dev2`), et un déploiement doit précéder tout run.

## Démarrer une session

```bash
python3.12 -m venv .venv && source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q tests model_training/tests
```

Cible d'exécution : nato / `pve-nato` via le runner `nato-master` uniquement.
Le homelab personnel est hors périmètre.

## Limites à ne pas oublier

- Trois répétitions donnent une variabilité descriptive, pas un intervalle
  confirmatoire.
- Un run vert ne vaut pas une mesure exploitable : le premier passage SSH était
  vert alors que les six bras LLM avaient échoué.
- Les coûts sont des estimations tarifaires, pas des factures ; le coût
  matériel n'est pas mesuré.
- Le corpus couvre deux protocoles et des services en partie simulés : ni
  firmware, ni radio, ni impact physique.
- **Aucun avantage général du LLM n'est démontré à ce jour.**

## Voir aussi

- [Registre d'hypothèses](../research/2026-10-21-hypotheses-benchmark/README.md)
- [Objectif AsiaCCS 2027](asiaccs-2027/README.md) et
  [plan de soumission](asiaccs-2027/plan-soumission.md)
- [Plan V2 et avancement consolidé](../research/2026-10-12-recentrage-corpus/README.md)
- [Pistes de la plateforme](PISTES.md)
- [Guide CLI des harnais](../docs/benchmark/agent-vs-automation-cli.md)
