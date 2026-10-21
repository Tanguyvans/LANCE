# État courant : point de reprise

**Dernière mise à jour : 2026-10-21 10:38 (Europe/Brussels, UTC+02:00).**
Cette page sert de point d'entrée pour reprendre le travail rapidement dans une
nouvelle session. Elle ne remplace pas les documents de référence : elle dit
**où on en est**, **ce qui est prêt**, et **ce qui peut être fait en parallèle ou
non**. Voir [l'objectif AsiaCCS 2027](asiaccs-2027/README.md) et
[l'étude de recentrage V2](../research/2026-10-12-recentrage-corpus/README.md).

## Objectif et priorités (révisé le 2026-10-21)

**But global.** Un auditeur de réseaux IoT/IIoT autonome et prouvable : il
explore, trouve, vérifie et rapporte, avec des preuves recalculables.

**Priorités actuelles, dans cet ordre :**

1. **Le benchmark** — un instrument d'évaluation comparative des modèles, à
   couverture maximale, contre d'autres LLM et contre des scripts déclarés.
   Il est structuré par un
   [registre d'hypothèses](../research/2026-10-21-hypotheses-benchmark/README.md)
   (V0 et H1-H6), pas par une liste de scénarios.
2. **La plateforme** — déploiement et lancement : installer, lancer un audit,
   suivre, récupérer, isoler, nettoyer.

**Hors priorité :** l'entraînement des modèles. **Conséquence :** le papier
AsiaCCS est le compte rendu de ce que le benchmark mesure ; il ne pilote pas
l'ordre des travaux.

**Règle de planification.** Aucune étape interne n'est datée. Une étape commence
quand la précédente est vérifiée. La seule contrainte externe est la date de
soumission, documentée dans le
[plan de soumission](asiaccs-2027/plan-soumission.md) ; elle ne justifie ni un
périmètre réduit non validé, ni un résultat non mesuré.

**C2 est clos pour la campagne en cours.** Les deux mécanismes ont été rejetés
sur papier le 2026-10-21 ; le
[verdict](../research/2026-10-21-c2-couverture/revue.md) explique pourquoi. La
variante B2 (coût de recherche d'état) n'est pas poursuivie : elle changerait la
thèse et relèverait d'une autre campagne.

## Où en est le dépôt

`main` et `dev/2` sont alignés (vérifié le 2026-10-21 ; le SHA n'est pas figé
ici). Tout nouveau commit sur `main` doit être reporté sur `dev/2` avant un
nouveau pilote.
Le pilote de référence de
`s_api_organisations` (contrat v2) est exécuté ; les deux pilotes V2 (SSH et
MQTT, 3 répétitions, `qwen3.8:27b`) restent exploitables.

Derniers travaux livrés :

| Commit | Contenu | Vérification |
| --- | --- | --- |
| `006356c` | Politique LLM bornée pour `s_api_organisations` : même outil, budget de requêtes, preuves observées obligatoires | 4223 tests passés ; un test de temporisation instable sous `-n 4`, vert seul |
| `f7956ce` | Incrément hors ligne `s_api_organisations` : contrat, fixture paramétrique, baseline déclarée, évaluateur | 4223 tests passés ; comparaison script contre exploration, hors ligne |
| `ca1279f` | Résultats du panneau MoE consignés | CI verte |
| `9a283f8` | Job `v2-summary` : agrégation en lecture seule des deux racines sur nato | CI verte, 4209 tests |
| `74c218a` | Correction : les bras LLM V2 démarrent sans plafond de durée | 4208 tests, pilotes SSH et MQTT rejoués |
| `4e82f6f` | Tests CI : 297 s → 149 s séquentiel, 85 s avec `-n 4` | CI verte, 4204 tests |
| `70d9031` | Cette page de reprise | CI verte |
| `29a3f6b` | Coût et durée des harnais V2 **mesurés, plus plafonnés** | 4204 tests verts, CI + déploiement nato |
| `c0c0568` | Tri des collections multi-principaux dans les preuves de portée | CI verte |
| `0dec6cf` | Validateur `broken_access_control` (contrat `evidence-v16`) | Run S15 : FN 0, rappel 1,0, F1 0,545 |
| `b232059` | Suppression des plafonds par défaut des runs interactifs | CI verte |

Le parcours interactif et les harnais V2 mesurent désormais le coût et la durée
sans les tronquer (`29a3f6b`). Les bornes d'action (8 appels SSH, 12 tours)
restent : elles définissent l'instrument borné, pas un budget économique.

## Résultats des pilotes (2026-10-20)

Deux pilotes réels, 3 répétitions × 2 postures, `qwen3.8:27b` via
`ollama-umons`. Toutes les paires sont admissibles, aucun échec de contrôleur,
aucun échec Proxmox.

| Famille | Modèle | Run | Bras | Succès | Appels | Plage de durée | Requêtes | Jetons | Plage de coût |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SSH | — | `39465619725-1` | règles | 6/6 | 3–4 | 0,2–0,4 s | 0 | 0 | 0 $ |
| SSH | `qwen3.8:27b` | `39465619725-1` | LLM | 6/6 | 4 | 14,0–73,7 s | 2–3 | 3 461–5 126 | 0,006–0,008 $ |
| SSH | `gemma4:26b-a4b-it` | `39480713050-1` | LLM | 6/6 | 4 | 19,5–69,8 s | 5–6 | 7 528–10 176 | 0,012–0,017 $ |
| MQTT | — | `39467657683-1` | règles | 6/6 | 3 | 15,0 s | 0 | 0 | 0 $ |
| MQTT | `qwen3.8:27b` | `39467657683-1` | LLM | 6/6 | 3 | 23,7–37,3 s | 2–3 | 3 051–6 408 | 0,004–0,010 $ |
| MQTT | `gemma4:26b-a4b-it` | `39482737529-1` | LLM | 6/6 | 3 | 33,9–44,4 s | 4 | 6 808–8 244 | 0,012–0,016 $ |

Le modèle MoE coûte environ le double du dense et prend 1,3 à 1,7 fois plus de
temps, avec deux fois plus de requêtes fournisseur, pour le même résultat. Le
panneau est désormais couvert sur les deux familles.

Variabilité inter-répétitions du bras LLM (n = 3 par posture) :

| Famille / posture | Durée CV | Coût CV | Jetons CV |
| --- | --- | --- | --- |
| SSH F0 | 92,3 % | 7,0 % | 5,9 % |
| SSH F1 | 6,4 % | 17,9 % | 21,8 % |
| MQTT F0 | 27,8 % | 46,1 % | 25,6 % |
| MQTT F1 | 10,2 % | 34,7 % | 35,6 % |

Le CV de durée SSH F0 (92 %) vient d'une **première répétition à 73,7 s**
contre 16,6 et 16,7 s ensuite : c'est un chargement de modèle à froid, pas une
variabilité de politique. Les autres séries restent entre 6 % et 46 %.

Rappel de portée : ces six paires par famille établissent que **les deux
instruments mesurent**, pas qu'un bras surpasse l'autre. `mt_admissible` reste
`false` et les verdicts ne satisfont toujours pas `strict_v3_metrics_adopted`.

### Résumé hors ligne des deux familles (run `39479954747`)

12 paires planifiées, observées et incluses ; aucune exclue, incomplète ou
dupliquée. Taux de succès 1,0 pour les deux bras dans les deux postures, aucun
faux positif, contrôles prouvés 3/3.

**Aucun intervalle n'est calculé**, et c'est structurel : `configuration_uniformity`
reste non satisfaite parce que SSH et MQTT sont deux configurations distinctes —
une configuration inclut le commit, les empreintes d'implémentation du harnais
et les budgets, pas seulement le modèle. Chaque groupe ne contient donc qu'une
famille, alors que `family_inference` en exige deux indépendantes.

### Comparaison script / LLM (`s_api_organisations`)

Le bras script est la **matrice rôle/objet/organisation déclarée**, exécutée
telle quelle : politique et inventaire publics, un jeton, une lecture par
objet. Sa limite est déclarée d'avance — il s'arrête à la frontière objet
et ne lit aucune collection — donc ce n'est pas une règle retirée.
Le bras LLM reçoit les mêmes entrées et le même outil `http_request`.

Hors ligne, le script réussit en posture protégée et s'arrête en posture
vulnérable ; l'exploration franchit la frontière `collection_cross` en F1
sans faux positif en F0. L'évaluateur recalcule la divulgation depuis le
journal d'outils, jamais depuis la décision.

Le **pilote de référence sur nato** (run 39491860391, `qwen3.8:27b`,
contrat v2) donne le cas d'usage cherché : le script déclaré échoue en F1
(`required_assessment_not_proven`) ; le modèle lit la politique publiée,
suit la collection, prouve la divulgation inter-organisation
(`collection_cross`) et ne produit aucun faux positif en F0. Coût estimé
0,032 $ (F0) et 0,036 $ (F1), 10–11 appels. Les deux premiers lancements
n'ont produit que du 404/401 : le briefing ne documentait aucune route, et
la comparaison mesurait la devinette de chemins. Le contrat v2 documente la
surface publiée, identique à `GET /v1/policy`. Le pilote reste **non
admis** (une famille, une répétition, strict-v3 non adoptées).

## Ce qui manque pour avancer

Le panneau de modèles est couvert : les deux modèles réussissent partout, le
MoE coûtant environ le double. La variabilité inter-répétitions est mesurée
pour les deux. Mais ces résultats sont **descriptifs** : ils montrent que
l'instrument mesure, pas quand un LLM est utile.

Ce qui manque, dans l'ordre :

1. **Un harnais paramétrable** : aujourd'hui un scénario est un module
   verrouillé (`scenario_id` imposé, `families=1`, oracle et évaluateur figés).
   Tant que ce n'est pas réglé, ajouter une famille revient à dupliquer du code.
2. **Les familles du [registre d'hypothèses](../research/2026-10-21-hypotheses-benchmark/README.md)**
   H1-H6, avec leur oracle, leur baseline déclarée et leur mesure propre. C'est
   la contribution du benchmark : une matrice d'hypothèses, pas un nombre de
   scénarios.
3. **La couverture déclarée** : publier ce qui est couvert et ce qui ne l'est
   pas. Un benchmark qui assume ses trous est plus solide qu'un benchmark qui
   prétend tout couvrir.
4. **Une deuxième famille indépendante par harnais**, si l'on veut des
   intervalles. Ce n'est plus le conducteur du travail, mais la condition d'une
   revendication statistique.
5. **La plateforme** : déploiement reproductible, lancement, suivi,
   récupération des résultats, isolation. Elle ne se mesure pas en précision —
   c'est le rôle du benchmark.

La précision du cœur d'audit (les 5 faux positifs S15) reste un objectif, mais
elle appartient au benchmark qui la mesure, pas à la plateforme.

## Conditions de démarrage d'une session

- **Interpréteur** : Python **3.12**. Le Python 3.11 global du poste est cassé
  (conflit `eth_typing`/`web3`) et ne sait pas lire les f-string du projet.
  ```bash
  python3.12 -m venv .venv && source .venv/bin/activate
  python -m pip install -r requirements.txt
  python -m pytest -q tests model_training/tests
  ```
- **Cible d'exécution** : nato / `pve-nato` via le runner `nato-master`
  uniquement. Le homelab personnel est hors périmètre.
- **Blocage levé le 2026-10-20** : `dev/2` suivait alors `main`, CI verte et
  `dev-2` redéployé. Un futur commit sur `main` doit à nouveau être reporté sur
  `dev/2` avant tout nouveau pilote.

## Plan de travail

Les étapes ci-dessous décrivent la séquence V2 historique. Elles restent
valides pour ce qu'elles couvrent, mais elles ne sont plus le conducteur :
l'ordre courant est le registre d'hypothèses, puis le harnais paramétrable,
puis la plateforme. Le pilote MoE reste une mesure utile, pas un préalable.

### Séquence V2

Ces étapes dépendent les unes des autres ; les paralléliser invaliderait les
mesures.

1. ~~**Avancer `dev/2` sur `main`**~~ — **fait le 2026-10-20** : CI verte et
   `dev-2` redéployé ; réaligné depuis.
2. ~~**Pilote SSH**~~ — **fait le 2026-10-20** : run `39465619725`, 6 paires
   admissibles, un premier passage invalidé par un `TypeError` corrigé en
   `74c218a`.
3. ~~**Pilote MQTT**~~ — **fait le 2026-10-20** : run `39467657683`, 6 paires
   admissibles.
4. ~~**Pilote SSH + MQTT avec le modèle MoE**~~ — **fait** : runs
   `39480713050` (SSH) et `39482737529` (MQTT), 3 répétitions chacun. Le
   panneau est verrouillé à ces deux modèles ; l'inférence reste séparée par
   configuration, jamais regroupée. Les commandes ci-dessous restent la
   procédure de reproduction.
   ```bash
   gh workflow run benchmark-integrity.yml --ref dev/2 -f slot=dev-2 \
     -f ssh_reference=true -f ssh_provider=ollama-umons \
     -f ssh_model=gemma4:26b-a4b-it-q4_K_M -f ssh_repetitions=3
   gh workflow run mqtt-reference.yml --ref dev/2 \
     -f provider=ollama-umons -f model=gemma4:26b-a4b-it-q4_K_M -f repetitions=3
   ```
5. **Résumé hors ligne** des deux racines scellées, depuis GitHub Actions
   (les racines restent sur nato) :
   ```bash
   gh workflow run benchmark-integrity.yml --ref dev/2 \
     -f v2_ssh_experiment=39465619725-1 -f v2_mqtt_experiment=39467657683-1
   ```
   Le job `v2-summary` est en lecture seule et publie `v2-summary.json` en
   artefact.
6. **Lire la variabilité** inter-répétitions et en déduire l'effectif
   confirmatoire. Les chiffres de `qwen3.8:27b` sont déjà dans la section
   « Résultats des pilotes » ci-dessus.

### Travail parallèle

Ces tâches n'utilisent pas le laboratoire et peuvent avancer pendant qu'un
pilote tourne, ou avant lui.

| Tâche | Pourquoi c'est parallélisable | Où |
| --- | --- | --- |
| **`s_api_organisations`, pilote v2** | Contrat v2, fixture, baseline, évaluateur, politique LLM, harnais vivant et premier pilote réel faits ; restent les répétitions et l'attestation de posture. C'est une **étude de cas de couverture**, pas une famille de revendication. | `benchmarks/experiments/api-reference/` |
| **Précision S15** | Les 5 faux positifs confirmés (SSH routeur, `/docs`) se traitent en lisant `04_exploitation.json` du run `2026-10-19_205307` sur nato. | nato, API |
| **Artefact anonymisé AsiaCCS** | Exigé par l'appendice Open Science. Bloquant en cas d'absence et long à préparer. | [plan](asiaccs-2027/plan-soumission.md) §6 |
| **Squelette du papier** | Structure, contributions, bibliographie. | [plan](asiaccs-2027/plan-soumission.md) |

`s_api_organisations` peut se développer **pendant** un pilote, mais son
exécution réelle repasse par le laboratoire : elle ne double pas un pilote en
cours.

### Ce qui ne peut pas être parallélisé

- **Deux runs laboratoire** : le verrou `lance-lab-dev2` est partagé et
  `cancel-in-progress: false`. SSH et MQTT se sérialisent.
- **Déploiement et run** : `ssh-reference` dépend de `deploy-development`.
  Lancer avant la fin du déploiement échoue le contrôle `EXPECTED_SHA`.
- **Un déploiement sur `dev/2` et un run** : même verrou `deploy-nato-master`.
- **Le gel et le pilote** : geler les marges ou `delta_min` avant d'avoir la
  variabilité reviendrait à figer à l'aveugle. Le pilote d'abord.

## Étapes et conditions de démarrage

Aucune étape interne n'est datée. Une étape commence quand la précédente est
vérifiée.

| Étape | Condition de démarrage | État |
| --- | --- | --- |
| Avancer `dev/2` sur `main` | — | **Fait** le 2026-10-20 |
| Pilotes SSH et MQTT, `qwen3.8:27b` | — | **Faits** le 2026-10-20 |
| Pilotes SSH et MQTT, modèle MoE | — | **Faits** : runs `39480713050` et `39482737529` |
| [Registre d'hypothèses](../research/2026-10-21-hypotheses-benchmark/README.md) V0 et H1-H6 | — | **Rédigé** le 2026-10-21 |
| Porte de validité V0 sur SSH/MQTT, instance tenue à l'écart | registre validé | À faire |
| Harnais paramétrable (un scénario = un module) | V0 franchie | À faire |
| Familles H2, H3, H4 : oracle, baseline, évaluateur | harnais paramétrable | À faire |
| Deuxième famille indépendante par harnais | une famille H2 ou H3 opérationnelle | À faire ; condition d'un intervalle, pas du travail courant |
| Marges, `delta_min`, unité d'indépendance | données de plusieurs familles | Volontairement reporté |
| Plateforme : déploiement et lancement reproductibles | benchmark exécutable de bout en bout | À faire |
| Décision de soumission | manuscrit relisible et artefact prêt | Contrainte externe : **2026-12-11 (AoE)** |

La date de soumission est la seule contrainte externe. Elle n'ordonne pas les
étapes : si une condition n'est pas remplie, l'étape suivante ne commence pas,
quelle que soit la date.

## Limites à ne pas oublier

- Trois répétitions par posture produisent une variabilité descriptive, pas un
  intervalle de confiance confirmatoire.
- Le pilote a montré que « run vert » ne vaut pas « mesure exploitable » : le
  premier passage SSH était vert alors que les six bras LLM avaient échoué.
- Les verdicts de calibration ne satisfont jamais `strict_v3_metrics_adopted` :
  une campagne reste non admise même quand toutes les autres conditions le sont.
- Le coût facturé UMONS et le coût matériel ne sont pas mesurés ; les
  estimations tarifaires ne sont pas une mesure monétaire.
- Aucun avantage général du LLM n'est démontré à ce jour.

## Voir aussi

- [Pistes de la plateforme](PISTES.md) : idées au-delà du scénario courant, avec leur barre d'honnêteté
- [Objectif AsiaCCS 2027](asiaccs-2027/README.md) et [plan de soumission](asiaccs-2027/plan-soumission.md)
- [Plan V2 et avancement consolidé](../research/2026-10-12-recentrage-corpus/README.md#avancement-consolidé)
- [Guide CLI et qualification des harnais](../docs/benchmark/agent-vs-automation-cli.md)
- [Comparaison script/LLM `s_api_organisations`](../benchmarks/experiments/api-reference/README.md)
