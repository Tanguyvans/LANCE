# État courant : point de reprise

**Dernière mise à jour : 2026-10-20 12:10 (Europe/Brussels, UTC+02:00).**
Cette page sert de point d'entrée pour reprendre le travail rapidement dans une
nouvelle session. Elle ne remplace pas les documents de référence : elle dit
**où on en est**, **ce qui est prêt**, et **ce qui peut être fait en parallèle ou
non**. Voir [l'objectif AsiaCCS 2027](asiaccs-2027/README.md) et
[l'étude de recentrage V2](../research/2026-10-12-recentrage-corpus/README.md).

## Où en est le dépôt

`main` est à `29a3f6b`, **CI verte et déployée sur nato**. Rien n'est en cours
côté code.

Derniers travaux livrés :

| Commit | Contenu | Vérification |
| --- | --- | --- |
| `29a3f6b` | Coût et durée des harnais V2 **mesurés, plus plafonnés** | 4204 tests verts, CI + déploiement nato |
| `c0c0568` | Tri des collections multi-principaux dans les preuves de portée | CI verte |
| `0dec6cf` | Validateur `broken_access_control` (contrat `evidence-v16`) | Run S15 : FN 0, rappel 1,0, F1 0,545 |
| `b232059` | Suppression des plafonds par défaut des runs interactifs | CI verte |

Le parcours interactif et les harnais V2 mesurent désormais le coût et la durée
sans les tronquer (`29a3f6b`). Les bornes d'action (8 appels SSH, 12 tours)
restent : elles définissent l'instrument borné, pas un budget économique.

## Ce qui manque pour avancer

Deux qualifications réelles existent (SSH le 15 octobre, MQTT le 19 octobre),
mais chacune ne compte **qu'une répétition par posture**. Elles qualifient
l'instrument sans admettre de campagne : `mt_admissible` reste `false` et les
verdicts de calibration ne satisfont pas `strict_v3_metrics_adopted`.

Le pilote V2 (3 répétitions × 2 postures × SSH + MQTT × 2 modèles) produira la
variabilité inter-répétitions. C'est **le chiffre qui manque** avant toute
décision sur les marges, les effectifs ou le gel.

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
- **Blocage connu** : les workflows SSH et MQTT exigent la branche `dev/2` et un
  commit exact. `origin/dev/2` est encore à `6dda69e`, soit **huit commits en
  retard** sur `main` (il ignore notamment `29a3f6b`, `c0c0568`, `0dec6cf`,
  `b232059`). Un fast-forward est possible. **Rien ne peut être lancé avant
  cette mise à jour.**

## Plan de travail

### Séquence obligatoire

Ces étapes dépendent les unes des autres ; les paralléliser invaliderait les
mesures.

1. **Avancer `dev/2` sur `main`** (`29a3f6b`). Fast-forward possible.
   Sans cela, aucun pilote ne peut démarrer.
2. **Pilote SSH** — 3 répétitions, `qwen3.8:27b` :
   ```bash
   gh workflow run benchmark-integrity.yml --ref dev/2 -f slot=dev-2 \
     -f ssh_reference=true -f ssh_provider=ollama-umons \
     -f ssh_model=qwen3.8:27b -f ssh_repetitions=3
   ```
3. **Pilote MQTT** — workflow séparé, même verrou laboratoire :
   ```bash
   gh workflow run mqtt-reference.yml --ref dev/2 \
     -f provider=ollama-umons -f model=qwen3.8:27b -f repetitions=3
   ```
   Il partage le verrou `lance-lab-dev2` avec SSH : **jamais en parallèle**.
4. **Pilote SSH + MQTT avec le modèle MoE** (`gemma4:26b-a4b-it-q4_K_M`),
   après les deux précédents. Le panneau est verrouillé à ces deux modèles ;
   l'inférence reste séparée par configuration, jamais regroupée.
5. **Résumé hors ligne** des racines d'expérience :
   ```bash
   python -m benchmarks.experiments.v2_campaign \
     --root output/ssh-reference/RUN_SSH --root output/mqtt-reference/RUN_MQTT \
     --output output/v2-summary.json --minimum-families 2 --minimum-repetitions 3
   ```
6. **Lire la variabilité** inter-répétitions et en déduire l'effectif
   confirmatoire.

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
| Avancer `dev/2` sur `main` | immédiat | Confirmation utilisateur requise (branche partagée) |
| Lancer le pilote SSH 3 répétitions | après l'étape 1 | Prêt |
| Marges, `delta_min`, unité d'indépendance | **après** le pilote | Volontairement reporté |
| Soumission AsiaCCS ou repli | **2026-11-16** | Critères dans le plan |
| Soumission | **2026-12-11 (AoE)** | — |

## Limites à ne pas oublier

- Une répétition par posture ne produit ni intervalle de confiance ni conclusion
  sur un avantage du LLM.
- Les verdicts de calibration ne satisfont jamais `strict_v3_metrics_adopted` :
  une campagne reste non admise même quand toutes les autres conditions le sont.
- Le coût facturé UMONS et le coût matériel ne sont pas mesurés ; les
  estimations tarifaires ne sont pas une mesure monétaire.
- Aucun avantage général du LLM n'est démontré à ce jour.

## Voir aussi

- [Objectif AsiaCCS 2027](asiaccs-2027/README.md) et [plan de soumission](asiaccs-2027/plan-soumission.md)
- [Plan V2 et avancement consolidé](../research/2026-10-12-recentrage-corpus/README.md#avancement-consolidé)
- [Guide CLI et qualification des harnais](../docs/benchmark/agent-vs-automation-cli.md)
