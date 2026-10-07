# Accès labo nato-master depuis la machine dev (Tailscale)

Plateforme LANCE : `http://100.103.253.86:8501/` (nœud `nato-master`,
réseau Tailscale `100.64/10`). Procédure vérifiée le **7 octobre 2026**.

## 1. Prérequis

- Tailscale **connecté sur la machine dev** (l'icône « Connected » ne
  suffit pas : `tailscale status` doit lister `nato-master` en vert).
- Sans Tailscale actif, `100.103.253.86` est injoignable (pas de route).

## 2. Accès direct (recommandé)

Contourner tout proxy HTTP : la cible est une IP de tailnet, le proxy
ne fait que renvoyer des réponses vides.

```bash
curl --noproxy '*' --max-time 25 http://100.103.253.86:8501/api/pipeline/status
```

## 3. Cas particulier : shell sandboxé de l'agent

Le sandbox bloque le trafic direct vers l'interface `utun` (échec en
~2 ms même avec Tailscale connecté et routé). Lancer les commandes
`curl` avec une escalade sandbox approuvée + `--noproxy '*'`. Sans
escalade, seul le proxy d'approbation répond, de façon intermittente
(ordre de grandeur : 1 réponse sur 10) — inutilisable pour suivre un run.

## 4. Endpoints utiles

| Besoin | Requête |
| --- | --- |
| Statut pipeline | `GET /api/pipeline/status` |
| Lancer un run | `POST /api/pipeline/start` `{"model":"qwen3.8:27b","provider":"ollama-umons","scenario_id":"7","execution_profile":"auto"}` |
| Fichier d'un run | `GET /api/runs/{id}/{filename}` (`02_recon.md`, `03_phase3_status.json`, `score`, `run_meta.json`, `04_exploitation.json`) |
| Détail d'un run | `GET /api/runs/{id}` (fichiers, coût, statut, commit) |

`run_meta.json` fait foi pour le diagnostic : `results` donne l'état
par phase (`executed_with_worker_errors` sur une phase ⇒ run `partial`,
voir `src/agent/results.py`), `git_commit` le code déployé.

## 5. Avant un run de validation

1. Vérifier le commit déployé (`git_commit` dans `run_meta.json` ou
   `commit` dans `GET /api/runs/{id}`).
2. Après chaque push, le mini-PC pull automatiquement ; redémarrer
   `nato-fastapi` pour charger le nouveau code si besoin.
3. `LANCE_PHASE3_DEVICE_TIMEOUT_S=420` requis pour la campagne
   (override systemd sur `nato-fastapi`, vérifié via
   `systemctl show nato-fastapi -p Environment`).
