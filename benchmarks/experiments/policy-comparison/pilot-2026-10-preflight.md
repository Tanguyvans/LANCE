# Précontrôle du pilote `lance-policy-pilot-2026-10`

Relevé le 2026-10-13. Manifeste :
[pilot-2026-10.json](pilot-2026-10.json). Aucun run lancé à ce stade.

## Vérifié

| Point | Résultat |
| --- | --- |
| Identité de la cible | `nato-master` (100.103.253.86, Tailscale, direct) ; `pve-nato` distinct listé séparément. Aucun repli sur une autre machine. |
| Pipeline libre | `GET /api/pipeline/status` : `running=false`, aucun déploiement en cours. |
| Modèle | `qwen3.8:27b` présent côté Ollama UMONS ; digest SHA-256 `22130167c4c20e20c7b71454612966ca8e8171e9b3cc8ab6ce8aa6cbfec79643` (27.3B, Q4_K_M), relevé via `/api/tags` le 2026-10-13, consigné dans le bloc `decision` du manifeste. |
| Configuration du manifeste | Complète : les 8 champs attendus sont fixés, dont `rules_version=shared-scanner-bounded-verification-v5` et `resource_manifest_sha256=64dd04f2…` calculée sur le code local (`926058f`). Manifeste revalidé par `load_manifest()`. |
| Set dans la grille | S1 signature ×12, S14 signature ×4, S15 logique ×3 (chaînages 1-3), S1h zéro faille (index dérivé). |

## Bloquant avant le premier run

| Point | État | Action requise |
| --- | --- | --- |
| Code déployé sur nato | **Vérifié le 2026-10-13** : le workflow Benchmark integrity du push `926058f` (run GitHub Actions 38379700523) inclut le job `deploy-master / update` en succès ; ce workflow déploie le commit exact validé sur le runner `nato-master`. Le commit déployé est donc `926058f`, cohérent avec l'empreinte du manifeste. Le commit `7a17f21` relevé initialement était celui du dernier run du 2026-10-10, sans rapport avec le déploiement courant (erreur corrigée). | Revérifier à chaque nouveau push de code touchant `src/` : job `deploy-master` en succès avant de lancer un bras. |
| Entrées publiques par paire | Non préparées — **non fabricables depuis le poste de développement** : les topologies des vérités terrain ne portent pas les ports déployés, et l'inventaire public doit être *validé par l'opérateur* sur l'état réellement déployé (mêmes appareils, services et ports pour les deux bras). Le deviner (ports usuels par rôle) violerait le protocole. | Sur nato, après déploiement de chaque instance : relever l'inventaire déployé, le valider, calculer `environment_sha256` sur le manifeste d'état initial, écrire une entrée par instance (même fichier pour les 3 répétitions, seul `trial_id` change). |
| État initial par bras | Non attesté | Contrôle et rétablissement de l'état avant chaque bras, `preflight.status` + `evidence_ref` daté versé au manifeste. Exécution des bras elle-même : CLI sur l'environnement laboratoire (leases de déploiement), pas depuis le poste de développement. |

Tant que ces trois points ne sont pas clos, aucun bras ne doit être
lancé : un échec serait attribué au laboratoire a posteriori, ce que le
protocole interdit.

## Accès d'exécution (inventaire du 2026-10-13)

- SSH depuis le poste de développement vers `nato-master`
  (100.103.253.86) : clé d'hôte vérifiée (présente dans `known_hosts`),
  mais authentification refusée pour tous les utilisateurs et clés
  locales essayés (`Permission denied (publickey,password)`). Aucun
  compte `nato-master` dans `~/.ssh/config`. Aucun accès forcé.
- Voie d'exécution établie par l'usage du dépôt : le runner
  `nato-master` lui-même (le workflow temporaire « S1 SSH diagnostic »
  du 2026-10-12 y a exécuté des diagnostics SSH vers les équipements
  avec un identifiant local au runner). Les bras du pilote doivent donc
  être lancés depuis une session sur `nato-master` (ou un workflow
  temporaire équivalent, supprimé après usage), pas depuis le poste de
  développement.

## Paire fumée S1 r1 — essais du 2026-10-13 (tous conservés, aucun interprété)

- Run `38435392572` : échec `./deploy.sh: Permission denied` (avant déploiement).
- Run `38435541026` : échec vault interactif EOF (avant déploiement).
- Run `38435795041` : annulé à 120 min. Déploiement OK (1m50), inventaire OK,
  puis bras `rules` sans sortie pendant ~117 min (run_dir créé vide, log 0 octet,
  python bufferisé). Diagnostic borné (run `38452868852`, reprise de l'inventaire
  fumée sur labo encore déployé) : le bras `rules` termine en <120 s mais avec
  **0 service scanné par hôte** — l'inventaire fumée nommait les services
  `tcp-<port>`, absents de `SERVICE_ALIASES` : le scanner déterministe ne
  reconnaît aucune règle. Défaut de mécanique du workflow fumée (noms canoniques
  nmap `-sV` requis), pas du manifeste. Artefacts du run annulé non téléversés :
  chemins relatifs au workspace alors que le job travaille dans
  `/opt/nato-smartcity-iot` (corrigé en chemins absolus).
- Corrections mécanique uniquement (set, modèle, critère inchangés) :
  noms de services canoniques `-sV`, `PYTHONUNBUFFERED=1`, `timeout 1500` par
  bras, sélection des `run_dir` par marqueurs temporels, teardown
  `--extra-vars scenario_id=1`, artefacts en chemins absolus.

## Paire fumée S1 r1 — run `38453703944` (job success, paire incomparable)

- Job terminé en succès, comparaison produite : `comparable: false`,
  motifs explicites des deux bras : `run_meta.json` absent des `run_dir`
  `2026-10-13_212054` (rules) et `2026-10-13_214706` (llm). Chaque bras a
  été tué par son `timeout 1500` sans aucun log, run_dir créé vide.
- Cause racine : double verrou. Le workflow exporte
  `LANCE_LAB_LOCK=/var/lib/lance/lab.lock` et tient `flock -x` sur ce
  fichier ; le pipeline (`src/benchmark/lab_lock.py:reserve_lab`, via
  `@serialized_lab`) tente d'acquérir le même verrou sans deadline et
  attend indéfiniment. Le diagnostic borné qui « réussissait » en <120 s
  tournait sans cette variable d'environnement — d'où l'écart.
- Correction mécanique uniquement : `env -u LANCE_LAB_LOCK` sur les deux
  invocations d'agent (le `flock` du workflow reste l'unique sérialisation).
  Set, modèle, critère inchangés. Essai conservé, non interprété.

## Paire fumée S1 r1 — runs des 2026-10-14 (branche dev/1, instance dev-1)

Les workflows temporaires vivent désormais sur `dev/1` (branche tirée
par le mini-PC ; instance `/opt/lance-dev-1`), commit `ad11f18`, pour
être visibles dans l'historique Actions sans toucher `main`.

- Run fumée `38531094317` (branche codex/pilot-2026-10, code main
  `7514254`) : job success, `comparable: false`. rules : pipeline
  terminé, 4/4 appareils, score 60,9 %, mais rejeté « incomplete
  analysis » — le comparateur exigeait `phase3_status == "completed"`
  alors que l'artefact porte `completed_with_device_errors` (erreurs
  scanner conservées comme information, 0 appareil en échec). llm :
  `budget_exceeded` à 600 s en phase 4, 3/4 appareils (échec `s1-web`).
- Run fumée `38534240392` (dev/1, déclenché par `ad11f18`) : job
  success, `comparable: false`, mêmes motifs. Réserve : le job a
  attrapé le runner avant le déploiement dev-1, les deux bras portent
  `git_commit: 37d287d54` (ancien checkout) — essai conservé, non
  interprété comme mesure du nouveau code.
- Correction de l'instrument (commit `96b8a0a`, déployé dev-1 par le
  run `38536910949`) : la complétude phase 3 du comparateur suit la
  sémantique du verdict d'exécution (`run_verdict` dans
  `src/agent/phases/analysis/context.py`) — complète si statut
  `completed`/`completed_with_device_errors`, tous appareils analysés,
  aucun en échec. Test : `tests/test_compare_policies.py`. La logique
  plus stricte de l'évaluateur pour les contrôles zéro-GT (spécificité)
  est inchangée.
- Run fumée `38538127991` (dev/1, checkout mesuré prouvé
  `96b8a0a756ceb39cb7f7503398d3d06dfbc26193` via `checkout_head.txt`
  et les deux `run_meta.json`) : job success. rules : **plus aucun
  motif d'incomparabilité**, score 60,9 %. llm : seul bloquant restant,
  `budget_exceeded` — 94 appels outil (< 200), 0,49 USD (< 2), mais
  600,0 s de mur : la phase 3 série (workers=1, ~24 requêtes modèle de
  20-45 s, échec `s1-web` à ~8 min) consomme presque tout le budget
  avant la phase 4. `comparable: false` pour le seul bras llm
  (3/4 appareils, artefacts d'exploitation absents).

Conclusion de fumée : l'instrument de comparaison est réparé ; le
budget durée du manifeste (600 s) est structurellement insuffisant
pour le bras llm dès S1. Décision à prendre avant toute mesure des
12 paires : relever le budget durée du manifeste (calibration pilote,
à documenter) ou traiter le dépassement comme résultat mesuré — le
comparateur actuel écarte la paire au lieu de la scorer. Aucune
extension aux autres paires tant que ce point n'est pas tranché.

## Calibration budgets (2026-10-14, après fumées S1)

Constat mesuré : à 600 s de budget total et 240 s par appareil, le
bras llm ne peut pas terminer S1 (phase 3 série : 4 appareils,
requêtes modèle de 20-65 s ; `s1-web` tué par la deadline appareil,
puis budget global épuisé en phase 4, artefact `04_exploitation.json`
jamais produit, paire écartée). Calibration du pilote, décidée avant
toute mesure des 12 paires et appliquée à l'identique aux deux bras :
`max_duration_s` 600 -> 1800 et nouveau champ manifeste
`phase3_device_timeout_s` = 600 (env `LANCE_PHASE3_DEVICE_TIMEOUT_S`,
défaut code 240 inchangé hors pilote). Les plafonds appels (200) et
coût (2 USD) ne mordaient pas (94 appels, 0,49 USD observés) et sont
inchangés, de même que le modèle, le set et le critère δ.

## Paire fumée S1 r1 — run `38549458127` (budgets calibrés, comparable)

Premier essai comparable. Checkout mesuré `a91415d` (correctifs
comparateur + alias services inclus), `max_duration_s=1800`,
`device_timeout_s=600` enregistrés à l'identique dans les deux
`run_meta.json` (`2026-10-14_122830` rules, `2026-10-14_123242` llm).
`comparable: true`, aucun motif d'incomparabilité. Phase 3
`completed` des deux côtés (4/4, 0 échec — la normalisation des noms
nmap a aussi supprimé les faux « incidents techniques »). Scores
(strict-v3) : rules 66,7 %, llm 72,0 %. Deltas llm-règles : TP
confirmés +1, F1 confirmé +0,053, FP candidats +6 ; llm : 1394 s de
mur (sur 1800), 1,34 USD (sur 2), 1 189 300 tokens, 67 tours.
Marge restante faible sur les deux plafonds temps/coût : à surveiller
sur S14/S15, plus gros que S1. Essai de fumée : il prouve que
l'instrument mesure ; il ne préjuge pas du verdict des 12 paires.

## Gel de configuration campagne (2026-10-14, avant les 12 paires)

Les essais `s1-r1` (dev-1, runs `2026-10-14_134728`/`135140`,
comparaison récupérée `comparable: true`) et `s1-r2` (main, run
campagne `38563382320`, `comparable: true`, rules 66,7 / llm 66,7)
ont été exécutés sous le hash ressources `f96066bb…`. Un défaut du
bilan (le champ manifeste `phase3_device_timeout_s`, appliqué par
environnement, était comparé au `run_meta` où il n'existe pas) a été
corrigé dans `policy_campaign.py` — ce qui change le hash
(`b636f0a5…`). Pour que les 12 paires partagent une seule identité
de configuration, le manifeste déclare désormais `b636f0a5…` et les
deux essais ci-dessus sont conservés comme essais d'instrument,
non comptés dans les 12 paires. Aucun changement de set, modèle,
budgets ou critère. À partir d'ici, aucun changement dans `src/`
pendant la campagne.


## Récupération des artefacts Actions — 2026-10-16

Après enregistrement des domaines réseau dans les paramètres du cloud, les
artefacts des 15 runs du workflow ont été téléchargés sous
`output/policy-comparison/actions/<github_run_id>/` (stockage local ignoré).
L'inventaire des jobs, y compris échecs et annulation, est conservé dans
`output/policy-comparison/actions-inventory.json`.

Lecture des comparaisons publiées pour les sept essais identifiés :

| Essai | Run Actions | Verdict du comparateur publié | État LLM |
| --- | --- | --- | --- |
| s1-r1 | 38570488357 | comparable | completed |
| s1-r2 | 38575803864 | comparable | completed |
| s1-r3 | 38581153999 | comparable | completed |
| s14-r1 | 38611677976 | incomparable | budget_exceeded, 200 appels, 792,5 s |
| s14-r2 | 38616086219 | incomparable | budget_exceeded, 200 appels, 1 192,1 s |
| s14-r3 | 38621265302 | incomparable | budget_exceeded, 200 appels, 1 179,4 s |
| s15-r1 | 38626380879 | incomparable | budget_exceeded, 200 appels, 567,0 s |

Pour chaque comparaison ci-dessus, l'identité des deux bras porte l'empreinte
courante `b636f0a5…`. Les quatre dernières paires manquent d'artefacts de
vérification évaluables du bras LLM ; leur phase d'analyse est déclarée achevée.
Les coûts/temps viennent des `cost_summary.json` de ces bras. Le plafond de
200 appels est atteint avant 1 800 secondes ; augmenter uniquement la durée
ne répondrait donc pas au plafond observé. Le diagnostic S15 mentionne
explicitement `Tool-call budget exhausted (200 calls)`.

Ce relevé décrit les artefacts publiés, sans nouvelle exécution ni revue
indépendante des preuves. Les anciens artefacts peuvent contenir des
comparaisons cumulatives et des essais sous une ancienne empreinte : ne pas
compter chaque fichier comme une nouvelle paire, ni effacer une tentative
incomplète parce qu'une copie antérieure est comparable.

Pour les quatre artefacts récents avec `evidence-manifest.json`, les six fichiers
de métadonnées de runs téléchargés par paire correspondent aux SHA-256 du
manifeste. Les archives complètes (92 à 131 fichiers annoncés par paire) restent
sur nato ; leur contenu complet n'a pas été récupéré ni revérifié ici.
Les métadonnées partielles ne suffisent donc pas à reconstruire le bilan complet
avec `policy_campaign` ni à attester les précontrôles. Le manifeste actif reste
inchangé pour éviter de fabriquer ces références.

Suite : récupérer les archives complètes et réconcilier toutes les tentatives ;
conserver les dépassements dans le bilan opérationnel. Toute calibration du
plafond d'appels exige un nouveau gel explicite et des essais distincts, sans
remplacer les résultats déjà obtenus. Aucun avantage scientifique n'est conclu
à partir de ce relevé opérationnel.


## Diagnostic hors ligne sur nato — 2026-10-16

Le [workflow 38905591684](https://github.com/Tanguyvans/LANCE/actions/runs/38905591684)
a exécuté le lecteur d'archives `scripts/benchmark/pilot_archive_review.py`
(commit `b143f67`) sur le runner `nato-master`, identifié par son nom et son IP.
Aucun audit, appel de modèle ni déploiement n'a été exécuté. Les archives et
traces brutes restent sur nato ; seul le
[relevé agrégé](offline-review-2026-10-16.json) est conservé dans le dépôt.

Les cinq archives présentes sous `output/pilot-evidence` ont été vérifiées :
483 fichiers au total, avec contrôle du SHA-256 de chaque archive, de la liste
exacte des fichiers, des tailles et empreintes individuelles. Une archive de
huit fichiers correspond à l'échec de préparation S14 r1 `38610509723-1`, sans
bras exécuté. Les quatre autres sont S14 r1–r3 et S15 r1, déjà identifiées.
Les huit précontrôles de ces quatre paires déclarent `valid` et leurs fichiers
sont intègres ; leur contenu déclaratif ne constitue pas une validation humaine
de la remise à zéro ni de l'état réel des cibles.

| Essai, bras LLM | Appels phase 3 | Appels phase 4 | Total journalisé | Appels curl_headers, toutes phases |
| --- | ---: | ---: | ---: | ---: |
| S14 r1 | 182 | 18 | 200 | 94 |
| S14 r2 | 175 | 25 | 200 | 97 |
| S14 r3 | 182 | 18 | 200 | 96 |
| S15 r1 | 199 | 1 | 200 | 161 |

Le journal concorde avec les 200 appels comptabilisés de chaque bras. Pour
S15, le bras règles consomme déjà 177 appels en analyse et 15 en vérification,
soit 192 au total ; il compte lui aussi 161 appels `curl_headers`. Le LLM
atteint donc la vérification avec une seule unité de budget, après ajout des
recherches et opérations de livrables. Ce constat explique le manque de marge ;
il ne démontre ni que les sondes HTTP sont inutiles, ni qu'un plafond supérieur
suffirait à terminer, ni un avantage de l'une des politiques.

### Décision de reprise

- Conserver les quatre dépassements dans le bilan du gel historique. Ne pas
  remplacer les essais, ne pas relever rétroactivement leurs limites.
- Les trois S1 comparables sont encore attribuées aux comparaisons Actions :
  aucune archive S1 n'est présente dans le magasin `pilot-evidence` inspecté.
  Leur preuve complète reste donc à localiser parmi les anciens dossiers.
- Le code `main` a évolué depuis le gel (fusion `7911b7b`) ; ne pas reprendre
  `pilot-campaign.yml` sur ce code en remplaçant l'empreinte du vieux manifeste.
- Avant un nouveau pilote : définir explicitement s'il s'agit de mesurer la
  performance sous 200 appels, ou de calibrer un budget permettant la
  vérification. Dans ce dernier cas, prévoir un plan distinct, la même limite
  pour les deux bras et un budget suffisant pour le scanner commun, puis
  qualifier un essai S15 et son contrôle sain avant une série complète.

Le nouveau lecteur est validé par 26 tests avec le support du pilote :
agrégation sans export des arguments/réponses, refus d'archive altérée et de
fichier dont l'empreinte ne correspond pas, ainsi que les tests existants du
workflow. Les résultats sont opérationnels ; aucune nouvelle étude de
performance ni revue humaine de preuves n'est revendiquée.
