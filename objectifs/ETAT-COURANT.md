# État courant : point de reprise

**Dernière mise à jour : 2026-10-20 19:50 (Europe/Brussels, UTC+02:00).**
Cette page sert de point d'entrée pour reprendre le travail rapidement dans une
nouvelle session. Elle ne remplace pas les documents de référence : elle dit
**où on en est**, **ce qui est prêt**, et **ce qui peut être fait en parallèle ou
non**. Voir [l'objectif AsiaCCS 2027](asiaccs-2027/README.md) et
[l'étude de recentrage V2](../research/2026-10-12-recentrage-corpus/README.md).

## Où en est le dépôt

`main` est à `9a283f8`, **CI verte et déployée sur nato**. `dev/2` suit `main`
au même commit. Les deux pilotes V2 (SSH et MQTT, 3 répétitions, `qwen3.8:27b`)
ont été exécutés et sont exploitables.

Derniers travaux livrés :

| Commit | Contenu | Vérification |
| --- | --- | --- |
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

## Ce qui manque pour avancer

Le panneau de modèles est couvert : les deux modèles réussissent partout, le
MoE coûtant environ le double. La variabilité inter-répétitions est mesurée
pour les deux.

Deux décisions de fond restent, dans cet ordre :

1. **Trancher la cible** : le succès est saturé (les deux bras réussissent les
   douze paires), donc la mesure primaire du plan de soumission — l'écart en
   vrais positifs confirmés strict-v3, testé en supériorité — n'est pas
   atteignable avec ces fixtures. Soit on défend le **coût à résultat non
   inférieur** (C3), soit on construit des scénarios où les règles échouent (C2).
2. **Deux scénarios par harnais** : aucune campagne ne produira d'intervalle
   tant qu'un harnais ne couvre pas au moins deux scénarios. Ajouter des modèles
   ou des répétitions n'y change rien.

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
- **Blocage levé le 2026-10-20** : `dev/2` suit `main` (`9a283f8`), CI verte et
  `dev-2` redéployé. Un futur commit sur `main` doit à nouveau être reporté sur
  `dev/2` avant tout nouveau pilote.

## Plan de travail

### Séquence obligatoire

Ces étapes dépendent les unes des autres ; les paralléliser invaliderait les
mesures.

1. ~~**Avancer `dev/2` sur `main`**~~ — **fait le 2026-10-20** : `dev/2` est à
   `4e82f6f`, CI verte et `dev-2` redéployé.
2. ~~**Pilote SSH**~~ — **fait le 2026-10-20** : run `39465619725`, 6 paires
   admissibles, un premier passage invalidé par un `TypeError` corrigé en
   `74c218a`.
3. ~~**Pilote MQTT**~~ — **fait le 2026-10-20** : run `39467657683`, 6 paires
   admissibles.
4. **Pilote SSH + MQTT avec le modèle MoE** (`gemma4:26b-a4b-it-q4_K_M`), le
   seul reste à exécuter. Le panneau est verrouillé à ces deux modèles ;
   l'inférence reste séparée par configuration, jamais regroupée.
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
| **`s_api_organisations`** | Prochaine réalisation V2 prévue. Contrat défini, harnais à construire. Aucun accès labo requis pour la conception et les tests. | `coverage-plan.json`, plan V2 |
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

## Décisions en attente

| Décision | Échéance | État |
| --- | --- | --- |
| Avancer `dev/2` sur `main` | ~~immédiat~~ | **Fait** le 2026-10-20 |
| Pilotes SSH et MQTT, `qwen3.8:27b` | ~~immédiat~~ | **Faits** le 2026-10-20 |
| Pilotes SSH et MQTT, modèle MoE | immédiat | Prêt |
| Deuxième scénario par harnais (condition d'un intervalle) | **avant** marges et `delta_min` | Nouveau, à trancher |
| Marges, `delta_min`, unité d'indépendance | **après** le pilote | Volontairement reporté |
| Soumission AsiaCCS ou repli | **2026-11-16** | Critères dans le plan |
| Soumission | **2026-12-11 (AoE)** | — |

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

- [Objectif AsiaCCS 2027](asiaccs-2027/README.md) et [plan de soumission](asiaccs-2027/plan-soumission.md)
- [Plan V2 et avancement consolidé](../research/2026-10-12-recentrage-corpus/README.md#avancement-consolidé)
- [Guide CLI et qualification des harnais](../docs/benchmark/agent-vs-automation-cli.md)
