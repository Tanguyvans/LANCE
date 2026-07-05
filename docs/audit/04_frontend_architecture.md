# 04 — Architecture front : 3 copies divergentes

## Réalité du service (ce qui est réellement atteignable)

`src/api/main.py` (unique app FastAPI) câble exactement **deux** fronts :

| Chemin | Route / mount | Dossier | index servi |
|---|---|---|---|
| `/` | `@app.get("/")` (`main.py:61-64`) + mount `/static` (`:40`) | `src/static/` | `src/static/index.html` |
| `/v2` | `@app.get("/v2")` (`main.py:67-70`) + mount `/static_v2` (`:41`) | `src/static_v2/` | `src/static_v2/index.html` |

**`src/static_docker/` n'est ni monté ni routé dans `main.py`** — donc inatteignable en run
`uvicorn` classique. **Mais il n'est pas mort** : `Dockerfile:80-81` l'écrase sur le primary au build :
```dockerfile
COPY src/static_docker/index.html ./src/static/index.html
COPY src/static_docker/app.js    ./src/static/app.js
```
Seuls `index.html` + `app.js` sont copiés ; `style.css` et `cytoscape.min.js` restent ceux du
primary. **Donc dans tout conteneur Docker, `/` sert le front `static_docker`** (son HTML/JS + le CSS
+ le Cytoscape local du primary). C'est l'UI de prod Docker, pas du legacy.

Chronologie (git) : `static_v2/` et `static_docker/` figés au **2026-05-25** ; `static/app.js`
continué jusqu'au **2026-06-24** (« edit models & providers from the UI »). Le primary a ~1 mois
d'avance sur les deux copies.

---

## ARCH-1 — `static_docker` : fork figé couplé silencieusement au CSS du primary (chantier)

**Constat** : `static_docker` est un fork gelé du primary (~2026-05-25), en « mode découverte »
(graphe vide, construit en parsant la sortie `nmap` : `parseNmapResult` `app.js:1371-1397`,
topologie `?empty=true`). Il partage les noms de variables CSS avec le primary (`--node-compute`,
`--sev-*`, `--sidebar-w`…) → il rend, mais **tout renommage CSS futur dans le primary casse
silencieusement l'UI Docker** (aucun signal à la compilation). Il manque aussi ~1 mois de
correctifs/fonctionnalités du primary (dont le CRUD modèles/providers du 2026-06-24).

Endpoints appelés — **tous existent** (vérifiés dans `routes/`) : `/api/models`, `/api/topology`
(`?empty=true`|`?scenario=`), `/api/pipeline/{start,stop,stream,status}`, `/api/runs`,
`/api/runs/{id}`, `/api/runs/{id}/{filename}`, `/api/runs/{id}/score`,
`/api/runs/{id}/download/zip`. Aucun appel vers un endpoint supprimé.

**Correctif recommandé (le plus fort)** : « mode découverte » (graphe vide + nmap, sans UI de
scénario) est un **mode runtime**, pas une raison de forker tout le front. **Consolider** : faire
basculer le primary `static/app.js` en mode découverte via un flag (ex. `window.DOCKER_MODE`
injecté par env, ou `?empty=true` par défaut), et **supprimer le `COPY` du Dockerfile** (`:79-81`).
Cela retire une copie divergente de 1457 lignes et le risque de dérive CSS.
**Effort** : M.

---

## ARCH-2 — `static_v2` : `provider` codé en dur → runs MiniMax mal routés (bug)

**Emplacement** : `src/static_v2/app.js:740` et `:786` — `provider: 'openrouter'` en dur.
**Problème** : ignore le provider du modèle sélectionné. L'API modèles supporte désormais un
provider `minimax` (abonnement) ; sélectionner un modèle MiniMax dans `/v2` envoie le mauvais
provider. Le primary et docker dérivent le provider de `option.dataset.provider`.
**Correctif** : dériver le provider de l'option sélectionnée (comme le primary).
**Effort** : S.

---

## ARCH-3 — `static_v2` : assets via CDN → casse en air-gap (bug)

**Emplacement** : `src/static_v2/index.html:8` (Google Fonts `fonts.googleapis.com`) et `:10`
(Cytoscape depuis `cdnjs.cloudflare.com`, v3.28.1).
**Problème** : le primary et docker chargent Cytoscape depuis un `/static/cytoscape.min.js` **local**.
En lab air-gappé / hors-ligne (contexte pentest), le graphe de `/v2` échoue silencieusement à rendre
tandis que les deux autres marchent.
**Correctif** : vendoriser Cytoscape + les fonts en local (pas de dépendance CDN).
**Effort** : S.

---

## ARCH-4 — `static_v2` : historique de runs en cul-de-sac (limitation)

**Emplacement** : `src/static_v2/app.js:814-832` (`loadRuns`/`selectRun`).
**Problème** : la liste RUNS ne fait que surligner un id — pas de vue de détail, pas de visionneuse
de fichiers, pas de rapport, pas de download, pas de compare. `/v2` peut lancer/monitorer mais **ne
peut pas inspecter** les résultats passés.
**Correctif** : dépend de ARCH-5 (décider du sort de `/v2`).

---

## ARCH-5 — Plan de consolidation (recommandation, rangée par valeur)

1. **Ne pas supprimer `static_docker`, mais cesser de le maintenir en copie séparée.** Le collapser
   dans le primary derrière un flag runtime « mode découverte » et retirer le `COPY` du Dockerfile
   (ARCH-1). Une seule source de vérité, fin du risque de dérive CSS. *Valeur maximale.*
2. **Décider du sort de `/v2` (user-facing).** Soit **(a)** promouvoir sa meilleure idée — le
   **système de calques + visualisation live des hops d'intrusion / nœuds compromis** — dans le
   primary, puis supprimer `static_v2/` + la route/mount `/v2` (`main.py:15,41,52,67-70`) ; soit
   **(b)** le garder mais corriger d'abord ARCH-2 (provider) et ARCH-3 (assets offline).
3. **Si `/v2` n'est pas promu, l'archiver/supprimer** plutôt que laisser une 2ᵉ UI à moitié finie
   (historique en cul-de-sac). Trois copies divergentes de la même logique SSE/Cytoscape sont la
   dette centrale ; l'objectif est **une** source de vérité (le primary) + un flag Docker runtime.
4. **Tant que le fork Docker survit**, ajouter un garde-fou de build (lint vérifiant que les
   variables CSS référencées par `static_docker` existent toujours dans `static/style.css`).

**Bilan** : il y a en réalité **deux** fronts alternatifs, pas un mort. `static_v2` est une UI
« Monitor » live et distincte à `/v2` (endpoints tous valides) mais avec 2 bugs de dérive
(provider en dur, Cytoscape/fonts CDN) et un historique non fonctionnel. `static_docker` **n'est pas
mort** : le Dockerfile le copie sur le primary au build → c'est l'UI Docker de prod, mais un fork
figé au 2026-05-25, en retard d'un mois et silencieusement couplé au CSS évolutif du primary. Aucun
des deux n'appelle d'endpoint supprimé. Le bon nettoyage : collapser `static_docker` dans le primary
derrière un flag runtime (supprimer l'override Dockerfile), puis promouvoir la visualisation par
calques/intrusion de `v2` dans le primary et supprimer `v2` (ou au minimum corriger provider +
assets offline) — pour ne laisser qu'un `static/` canonique.

---

## Récapitulatif

| ID | Type | Emplacement | Effort |
|---|---|---|---|
| ARCH-1 | Chantier consolidation | `Dockerfile:79-81`, `static_docker/*` | M |
| ARCH-2 | Bug | `static_v2/app.js:740,786` | S |
| ARCH-3 | Bug (offline) | `static_v2/index.html:8,10` | S |
| ARCH-4 | Limitation | `static_v2/app.js:814-832` | — (dépend d'ARCH-5) |
| ARCH-5 | Décision + plan | `main.py:15,41,52,67-70` | M–L |
