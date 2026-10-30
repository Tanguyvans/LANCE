# État courant

**Dernière mise à jour : 2026-10-30 11:50 (Europe/Brussels, UTC+01:00).**

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
| Inférence | unilatérale, corrigée le 2026-10-30 ; exige 5 familles pour décider, 3 pour produire un chiffre | `src/benchmark/inference.py`, `tests/test_inference.py` |
| Familles H1, H3, H4, H5 | non ouvertes ; `s_chaines_identites` et `s_registres_constructeur` n'existent pas | registre d'hypothèses |
| Corpus | 29 scénarios, 288 entrées de vérité terrain. **243/288 (84,4 %)** à signature selon la lecture interprétative de l'audit ; l'index dérivé, binaire, donne **282/288** et 6 entrées logiques (S15, S22, S28) | `benchmarks/ground_truth/`, `benchmarks/labels/derived_index.json`, [audit de couverture](asiaccs-2027/audit-couverture.md) |
| Noyau de harnais | quatre harnais délèguent à `build_run` ; un run incomplet est refusé à la construction | `benchmarks/experiments/harness/run.py`, `tests/test_harness_core.py` |
| Bac à sable | bras déterministes hors laboratoire sous garde-fou d'audit ; `guard_clean`, angles morts déclarés, `claims_isolation = false` | `benchmarks/experiments/sandbox.py`, `tests/test_sandbox.py`, CI `benchmark-integrity.yml` |
| Circuit de livraison | trois instances, déploiement automatique validé sur `main` et `dev/1` ; identité Tailscale déduite de l'interface | `scripts/deployment/deploy-instance.sh`, [rapport du 30 octobre](../research/2026-10-30-architecture-protocoles-avancement/README.md) |
| **Bras LLM comparable** | **absent** : `vanilla` prend un CIDR et ne produit pas de score ; `rules` produit un score sans modèle | `src/agent/run_modes.py`, `docs/architecture/run-modes.md` |
| Branche `dev/2` | 16 commits derrière `main` | `git log origin/dev/2..main` |

## Blocages

0. **Les familles sont fabriquées.** `policy_pair_runner.py:225` écrit
   `family_id: "ui-public-scenario"` en dur, et chaque scénario du catalogue
   porte son propre identifiant comme famille. Le corpus ne contient au mieux
   que trois familles défendables, alors que l'inférence en exige cinq pour
   décider. Tant que ce point n'est pas résolu, aucun test statistique ne peut
   être présenté comme une conclusion. C'est l'objet de la famille pilote.
1. **La mesure — corrigée le 2026-10-30.** Le module calcule désormais une
   p-value unilatérale : test du signe exact jusqu'à sept familles, bootstrap
   au-delà, refus explicite sous trois familles. Une décision exige cinq
   familles au moins, faute de quoi même cinq familles concordantes ne peuvent
   atteindre le seuil. Le blocage restant n'est plus le calcul mais **l'absence
   de familles indépendantes** : aucune donnée existante ne permet de conclure.
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

1. **Construire une famille réellement indépendante.** Une seule, menée de bout
   en bout : D1+ exécutable, test de clôture hashé, simulateur propre, huit
   fixtures, trois bras. C'est le gabarit des suivantes et la condition de toute
   conclusion défendable. Cahier des charges :
   [famille pilote `s_registres_constructeur`](../research/2026-10-30-famille-pilote-registres-constructeur/README.md).
2. **Comparer les trois politiques sur un même scénario.** C'est l'objectif de
   fond : sur un scénario donné, savoir ce que trouvent les automatisations
   (`scripted`), les règles déclarées (`rules`) et le modèle seul
   (`llm_on_evidence`), avec les mêmes observations et le même cadre
   d'évaluation. Voir la section « Comparer les trois politiques » ci-dessous,
   qui expose ce que cela exige et ce qui manque aujourd'hui.
3. **Trancher la métrique** : crédit gradué de strict-v3 écrasé en TP binaire
   par le funnel ; réparer ou retirer `inference.py`, qui produit une p-value
   identique sur quatre séries de comportements différents.
4. **Décider D1+** : l'implémenter, ou abandonner H1/H3/H4/H5 pour cette
   campagne et l'écrire comme limite.
5. **Étendre aux autres familles** et H2 (autres schémas, second
   modèle).
6. **Produire l'artefact anonymisé** : fixtures H2, oracle, évaluateur et
   contrôle V0, exécutables hors laboratoire.
7. **La plateforme** : déploiement et lancement reproductibles.

## Comparer les trois politiques sur un scénario

**But.** Sur un même scénario déployé, lancer trois politiques et comparer ce
qu'elles trouvent, à observations et cadre d'évaluation identiques :

| Politique | Ce qu'elle apporte | Existe aujourd'hui |
| --- | --- | --- |
| `scripted` | Procédures déterministes : découvrir, inventorier, auditer | Oui, sans score de benchmark |
| `rules` | Baseline déclarée : scanner puis règles d'interprétation | Oui, avec score strict-v3 |
| `llm_on_evidence` | **Le modèle interprète les observations produites par le scanner** | **Non** |

**Pourquoi ce troisième bras.** Les deux premiers ne répondent pas à la
question du programme : savoir si un modèle fait mieux qu'une automatisation
lorsqu'il reçoit la même information. Le mode `vanilla` réalise une exploration
libre sur une plage d'adresses et ne produit pas de score comparable ; le mode
`lance` conduit le pipeline complet sur six phases et ne se prête pas au même
contraste. Il manque donc le bras où seule **l'interprétation** change.

**Ce que ce bras mesurerait.** Le modèle reçoit, par appareil, les observations
brutes collectées par le scanner et doit produire des constats étayés par une
référence d'observation. Il ne reçoit ni les constats des règles, ni la vérité
terrain, ni le nombre attendu de failles. L'écart entre `rules` et
`llm_on_evidence` mesure alors la seule qualité d'interprétation.

**Ce qui empêche aujourd'hui une comparaison honnête.** Quatre mécanismes du
code avantagent `rules`, et chacun rendrait l'écart ininterprétable :

1. La phase 4 de `rules` émet de **nouvelles sondes** pour confirmer chaque
   candidat ; l'étage `confirmed` du funnel exige cette provenance. Un bras qui
   ne peut pas sonder n'atteindrait jamais cet étage.
2. `supplemental.py` **réécrit** les fichiers `03_scans` en y ajoutant des
   sondes dérivées (familles S16 à S18). L'observation n'est donc pas figée au
   sortir du scanner.
3. L'agrégation **ajoute les constats des règles** aux constats du modèle
   (`add_scanner_candidates`), ce qui gonflerait mécaniquement le score du bras
   modèle.
4. Le score de benchmark n'est calculé que pour les runs du mode `lance` ;
   l'attestation de pré-vol n'est écrite que par un déploiement de scénario.

**Décisions à prendre avant toute implémentation.** Elles portent sur ce qu'on
prétendra avoir mesuré, pas sur la faisabilité :

- **L'étage de comparaison** : constats candidats (interprétation seule) ou
  constats confirmés (interprétation et vérification confondues). Le second
  n'est comparable que si les deux bras peuvent sonder avec le même budget.
- **L'ouverture du calcul de score** aux modes autres que `lance`, et
  l'attestation de pré-vol associée.
- **Le rendu identique des observations** aux deux interpréteurs, vérifié plutôt
  qu'affirmé : une empreinte des fichiers lus avant et après chaque bras.
- **Le traitement des désaccords** entre les constats des règles et ceux du
  modèle : les constats des règles ne sont pas la référence, seule la vérité
  terrain l'est.

**État de la conception.** Une conception a été soumise à deux relectures : l'une
méthodologique, l'autre technique. La faisabilité est établie — environ quatre
jours de travail sans modifier le scanner ni l'évaluateur — mais la comparaison
n'est pas valide en l'état, pour les quatre raisons ci-dessus. Aucun code n'a
été écrit. Les principes restent valables ; les décisions doivent être prises
avant l'implémentation.

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
