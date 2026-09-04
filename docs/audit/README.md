# Audit du frontend LANCE — plan de remédiation

> Audit réalisé le **2026-07-05** (revue statique par agents spécialisés + audit en direct
> sur instance `uvicorn` réelle : dashboard piloté au navigateur en 1440px et 375px, vues
> Dashboard / Benchmark / Modèles, console). Périmètre : `src/static/` (dashboard principal, `/`),
> `src/static_v2/` (`/v2`), `src/static_docker/`, et la couche API FastAPI (`src/api/`).
>
> **Statut : archive historique.** Ce dossier décrit l'état observé à cette date, pas nécessairement
> l'état actuel de `main`. En particulier, `src/static_docker/` a été retiré le 2026-09-04 après
> confirmation que l'image Docker servait déjà le frontend canonique.

Ce dossier documente **tout ce qui doit être fait**, découpé par domaine. Chaque finding porte
un identifiant stable (`SEC-n`, `FE-n`, `UX-n`, `ARCH-n`), une sévérité, l'emplacement exact
(`fichier:ligne`), le scénario d'échec, un correctif concret et un critère de validation.

## Fichiers

| Fichier | Domaine | Findings |
|---|---|---|
| [`01_security_api.md`](01_security_api.md) | Sécurité de l'API FastAPI | 2 BLOCKER, 1 HIGH, 5 MEDIUM, 2 LOW |
| [`02_frontend_code.md`](02_frontend_code.md) | Code JavaScript (`static/app.js`) | 2 HIGH, 9 MEDIUM, 3 LOW |
| [`03_ui_ux_accessibility.md`](03_ui_ux_accessibility.md) | UI/UX, accessibilité, responsive | 4 HIGH, 8 MEDIUM, 11 LOW |
| [`04_frontend_architecture.md`](04_frontend_architecture.md) | 3 copies de front divergentes | 1 chantier + 3 bugs de dérive |

## Verdict global

Le dashboard est **soigné et discipliné** (thème dark tokenisé, `:focus-visible`,
`prefers-reduced-motion`, focus-trap sur modales, table `sr-only` de repli pour le graphe canvas,
log capé à 300 lignes, EventSource fermé proprement, markdown renderer échappé, SQL paramétré,
pas de `shell=True`, `yaml.safe_load`). Rien ne bloque l'affichage (1 erreur console : favicon 404).

**Mais** il porte des failles de sécurité critiques côté API (aucune authentification, exfiltration
possible de la clé API réelle) et un lot de bugs frontend réels (XSS via bannière nmap, compteur de
coût toujours à $0, cycle de vie SSE fragile). Et l'accessibilité/responsive a des trous nets
(sidebar inaccessible sur mobile, tablist sans clavier, actions destructives sans confirmation).

## Ordre de traitement recommandé

Priorité décroissante. Les identifiants renvoient aux fichiers détaillés.

### P0 — Sécurité, avant toute nouvelle exposition réseau
- **SEC-1** — Ajouter une authentification (l'API est ouverte sur tout le tailnet).
- **SEC-2** — Valider `base_url` / `api_key_env` des providers (exfiltration de clé + SSRF).
- **SEC-3** — Valider `scenario_id` (injection d'extra-vars Ansible exécuté en root).

### P1 — Bugs frontend à fort impact, correctif court
- **FE-1** — Échapper les bannières nmap (XSS stocké) — 1 ligne.
- **FE-2** — Réparer le compteur de coût live (toujours $0) — quelques lignes.
- **FE-9** — Corriger l'off-by-one des phases en mode batch — 1 caractère.
- **UX-2** — Confirmation sur Teardown / Stop (actions destructives/payantes).
- **UX-1** — Rendre les erreurs visibles (toast) indépendamment de l'Event Log.

### P2 — Robustesse & cohérence
- **SEC-4 → SEC-8** (CORS/CSRF, path-guard, bornes d'entrée, course stop/start, file SSE).
- **FE-3 → FE-11** (cycle de vie SSE, courses, échappement).
- **UX-3 → UX-13** (responsive, ARIA tablist, sections repliables clavier, thème, i18n).

### P3 — Dette d'architecture & finitions
- **ARCH-1 → ARCH-5** — Consolider les 3 fronts en une source de vérité.
- **UX-14 → UX-24** — Finitions a11y, données périmées de l'UI, favicon.

## Suivi

Cocher au fur et à mesure. Convention : `[ ]` à faire · `[~]` en cours · `[x]` fait & vérifié.

- [ ] P0 — SEC-1, SEC-2, SEC-3
- [ ] P1 — FE-1, FE-2, FE-9, UX-2, UX-1
- [ ] P2 — SEC-4…8, FE-3…11, UX-3…13
- [ ] P3 — ARCH-1…5, UX-14…24
