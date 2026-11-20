# Plan d'implémentation — profil partenaire « offline »

Contexte : les partenaires (site polonais) déploient le harness **sur leurs propres
serveurs** pour auditer leur réseau. Ils hébergent Ollama (GPU) ; notre container
LANCE pointe dessus. Objectif : une **appliance d'audit auto-suffisante** — un seul
hôte Linux GPU, un `docker compose up`, **rien ne sort de leur réseau** (ni vers
nous, ni vers le cloud). Voir [accès partenaire](partner-access.md).

Deux relectures indépendantes (architecture + sécurité) ont convergé sur **les
embeddings Voyage** comme bloquant n°1 : le container `src/agent/knowledge/embedder.py`
lève une `RuntimeError` sans `VOYAGE_API_KEY`, donc il **ne démarre même pas** hors
ligne, et à l'exécution il enverrait leurs findings d'audit (IP, ports, CVE) vers
`api.voyageai.com`.

Décisions actées : **ne pas livrer flint** (ils tournent qwen/gemma) ; **endpoint +
modèle Ollama pilotés par `.env`** ; **single-host `network_mode: host`** ; **image
livrée en tarball `docker save` épinglé par digest**.

Branche : **code sur `dev/1`**, pas sur `docs/vocab-checkpoints`.

---

## Chantier 1 — Embeddings locaux (le bloquant)

But : le container boote et tourne **sans Voyage ni Internet**. Les embeddings
passent par un seul point (`embed()`), le swap est donc localisé.

| Fichier | Changement |
| --- | --- |
| `src/agent/knowledge/embedder.py` | Backend sélectionné par env : `LANCE_EMBEDDINGS=ollama` (défaut), `LANCE_EMBED_BASE_URL` (défaut = l'Ollama du LLM), `LANCE_EMBED_MODEL=nomic-embed-text`. Implémenter `_embed_ollama()` (POST `/api/embeddings`), garder Voyage en **opt-in**. `embed()` dispatche. |
| `src/agent/knowledge/store.py` | Renommer `_VoyageEmbeddingFunction` → neutre (elle appelle déjà `embed()`, aucune logique à toucher). |
| `requirements.txt`, `.env.example` | `voyageai` optionnel ; documenter les 3 vars. Pas de dépendance lourde (embeddings via HTTP Ollama, pas de sentence-transformers). |

Fait quand : `VOYAGE_API_KEY` absent + Ollama avec `nomic-embed-text` → `ingest_skills()`
passe, la recherche marche, **zéro appel à voyageai**.

⚠️ Piège à documenter : la dimension change (nomic 768 vs voyage 1024). Un
`data/knowledge.db` construit sur un backend **n'est pas réutilisable** sur l'autre
→ déploiement neuf uniquement.

## Chantier 2 — Provider/modèle pilotés par `.env`, réconciliés au boot

But : `.env` = source unique. Supprimer l'étape `inject_*` manuelle **et** le piège
de la ligne DB qui survit dans `data/` et écrase silencieusement le `.env`
(`provider.py` lit « DB d'abord »).

| Fichier | Changement |
| --- | --- |
| `src/db/inject_moe.py` | Ajouter un flag `--model` (aujourd'hui `default_model="lance-moe"` est codé en dur → 404 si le vrai modèle Ollama diffère). |
| `docker/entrypoint.sh` | Avant `uvicorn`, **réconcilier le provider depuis l'env à chaque boot** (upsert `base_url` + `default_model` depuis `AGENT_PROVIDER` / `LANCE_MOE_BASE_URL` / `LANCE_MOE_MODEL`). |
| `.env.example` | Ajouter ces 3 vars + rendre `LANCE_ADMIN_TOKEN` **obligatoire** (vide aujourd'hui). |

Fait quand : éditer `base_url`/`model` dans `.env` → `restart` → la ligne provider
reflète le changement, sans `docker compose run` séparé.

## Chantier 3 — Compose single-host + packaging offline

But : un seul `docker compose up` sur un hôte Linux GPU, offline-proof.

| Fichier | Changement |
| --- | --- |
| `docker-compose.yml` | `network_mode: host` par défaut (+ **retirer `ports:`** dans ce mode), `healthcheck:`, Ollama en `localhost:11434`. |
| `Dockerfile` | Pré-embarquer les **templates nuclei** au build (pas de pull Internet). NVD : mode offline ou dégradé documenté (priorité moindre). |
| Livraison | Artefact = **tarball `docker save` épinglé par digest + sha256** (pas de dépendance GHCR au déploiement). Préciser **amd64** (ou publier multi-arch). |

Fait quand : hôte neuf **sans Internet** → `docker compose up` boote, ingère en
local, dashboard sur `127.0.0.1`, scan SYN OK.

## Chantier 4 — Garde-fous (avant handover)

- **Allowlist de cibles (CIDR)** imposée avant tout scan — ⚠️ **à vérifier si le
  mécanisme existe déjà** ; sinon c'est une feature à part entière (host networking
  = rayon de blast illimité sinon).
- Dashboard sur `127.0.0.1`, `LANCE_ADMIN_TOKEN` fort.
- **Ne pas livrer flint** ; enregistrer le vrai slug qwen/gemma.
- RoE signé + fiche de specs partenaire (`.env` type, matériel requis, modèles à
  `ollama pull`).

---

## Ordre et dépendances

1. **C1** (débloque tout) et **C2** sont du code quasi indépendant.
2. **C3** dépend de C1 + C2.
3. **C4** : surtout config/doc, sauf l'allowlist CIDR (à chiffrer après vérification).

Seul inconnu bloquant un chiffrage : l'existence d'un mécanisme d'allowlist CIDR
dans le harness (C4).
