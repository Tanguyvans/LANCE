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
