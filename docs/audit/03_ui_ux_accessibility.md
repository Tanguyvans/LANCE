# 03 — UI/UX, accessibilité et responsive

Fichiers : `src/static/index.html` (372 l.), `src/static/style.css` (1360 l.), `src/static/app.js`
(chemins de rendu/focus/feedback). Base **déjà solide** : CSS tokenisé, `:focus-visible`,
`prefers-reduced-motion`, focus-trap + Esc + restauration de focus sur les modales, table `sr-only`
de repli pour le graphe canvas, boutons-icônes majoritairement labellisés. Les findings ci-dessous
sont là où ça manque.

---

## HIGH

### UX-1 — Erreurs invisibles : uniquement dans l'Event Log, masqué < 640px (HIGH)
**Emplacement** : `app.js:1189` (`startRun`, `fetch` sans try/catch) ; `#log-wrap { display:none }`
sous 640px (`style.css:1286`).
**Problème** : les erreurs n'atterrissent que dans `#log`, masqué en petit écran ; aucun
toast/bannière. Une action coûteuse/destructive peut échouer sans aucun signal utilisateur.
**Correctif** : envelopper tous les `fetch` en try/catch ; ajouter un composant **toast/bannière**
persistant, visible indépendamment du log (`role="status"` pour le succès, `role="alert"` pour
l'erreur) ; désactiver Start de façon optimiste puis le réactiver en cas d'échec.
**Effort** : M.

### UX-2 — Actions destructives sans confirmation (HIGH)
**Emplacement** : `app.js:1291` (`teardownScenario`, détruit les VMs), `:1244` (`stopRun`, tue un
run payant). Or **supprimer un modèle** demande `confirm(...)` (`:2539`). Incohérent et dangereux.
**Correctif** : ajouter une confirmation (dialog ou hold-to-confirm) sur `#btn-teardown` et
`#btn-stop`, cohérente avec le pattern de suppression de modèle.
**Effort** : S.

### UX-3 — Aucune stratégie responsive : sidebar inaccessible sur mobile (HIGH)
**Emplacement** : layout multi-panneaux (`#sidebar`, `#graph-wrap`, `#detail`) ; media queries
insuffisantes.
**Problème** (constaté en direct à 375px) : **toute la sidebar disparaît** — formulaire New Run
**et** historique — sans menu hamburger. Impossible de lancer un run, voir l'historique ou le
panneau de détail sur mobile/tablette. Seul le graphe reste.
**Correctif** : décider le support cible. Si mobile requis : convertir la sidebar en drawer
déclenché par un bouton hamburger sous le breakpoint, empiler les panneaux, rendre le graphe et le
détail accessibles. Si desktop-only assumé : afficher un message explicite « écran trop petit »
plutôt qu'une UI amputée silencieusement.
**Effort** : M–L.

### UX-4 — `role="tablist"` sans modèle clavier (HIGH)
**Emplacement** : `#view-nav` (`index.html:16`), `#detail-tabs` (`index.html:268`) ; JS met à jour
`aria-selected` (`app.js:1817,1986`) mais **aucune gestion ArrowLeft/ArrowRight** et pas de roving
`tabindex`. De plus les onglets de vue pointent `aria-controls` vers des panneaux sans
`role="tabpanel"`/`aria-labelledby`.
**Correctif** : soit implémenter des vrais ARIA tabs (roving tabindex, flèches/Home/End,
`tabindex="-1"` sur onglets inactifs, `role="tabpanel"`+`aria-labelledby` sur `#main` et
`#benchmark-view`), soit retirer les rôles tab et traiter en boutons (`aria-pressed`).
**Effort** : M.

### UX-5 — En-têtes de sections repliables non interactifs (HIGH)
**Emplacement** : `.sidebar-section h3` (`style.css:196-219`) — `cursor:pointer`, toggle `.collapsed`,
affordance ▼/▶, mais c'est un `<h3>` nu avec handler de clic : non focusable, sans `role="button"`,
sans `aria-expanded`. Clavier/lecteur d'écran ne peuvent pas replier « New Run »/« Historique ».
**Correctif** : mettre un vrai `<button>` dans le `<h3>` (garde la sémantique de titre) avec
`aria-expanded` reflétant l'état.
**Effort** : S.

---

## MEDIUM

### UX-6 — `.run-item` `role="button"` contenant de vrais `<button>` (MEDIUM · M1)
**Emplacement** : `app.js:1642` (`_renderRunItem`) — ligne `role="button" tabindex="0"` avec
handler Enter/Space, imbriquant deux `<button>` (« + cmp », « zip »). ARIA invalide (contrôles
interactifs dans un `role="button"`) → focus/activation ambigus.
**Correctif** : faire de la ligne un conteneur non-bouton ; un `<button>`/lien primaire « ouvrir »,
cmp/zip en frères, pas descendants d'un rôle bouton.

### UX-7 — Poignées de redimensionnement souris uniquement (MEDIUM · M2)
**Emplacement** : `.resize-handle`/`.resize-handle-h` (`index.html:184,253,337`), `app.js:68`
(`mousedown`). Pas de `role="separator"`, `tabindex`, `aria-valuenow`, ni clavier.
**Correctif** : `role="separator"` + `aria-orientation` + `tabindex="0"` + resize aux flèches, ou
accepter comme confort souris et marquer `aria-hidden`.

### UX-8 — Thème dark unique, pas de `prefers-color-scheme` (MEDIUM · M3)
**Emplacement** : tokens dark en dur (`style.css:9-66`). Pas de mode clair ni toggle.
**Correctif** : si le clair est souhaité, override `@media (prefers-color-scheme: light)` (le design
est déjà tokenisé → faible effort) ou un toggle documenté.

### UX-9 — Toggles sans `aria-pressed` ; statut par couleur seule (MEDIUM · M4)
**Emplacement** : boutons de layout, `.color-mode-btn`, `.phase-pill` utilisent `.active` sans
`aria-pressed` ; états de pill `.done`/`.failed`/`.running` distingués **par couleur seule**
(`style.css:157-158,1248`) → indistinguables pour daltoniens (les SR sont couverts via aria-label
mis à jour à `app.js:2157`).
**Correctif** : `aria-pressed` sur les toggles ; indice non-coloré sur les états de pill
(icône/coche/× ou texte).

### UX-10 — `<label>` nu comme titre de groupe radio/checkbox (MEDIUM · M5)
**Emplacement** : `<label>Mode</label>`, `Posture`, `Phases`, `Scénarios à lancer`, `Packs…`
(`index.html:93,134,148,117,141`) — non associés programmatiquement.
**Correctif** : `<fieldset><legend>` (ou `role="group"` + `aria-labelledby`).

### UX-11 — Microcopy mixte FR/EN (MEDIUM · M6)
**Emplacement** : `lang="fr"` mais « New Run » vs « Historique » (`index.html:46/174`),
« Dashboard »/« Benchmark », « Event Log » + « Effacer » (`:342-343`), « Model global », etc.
**Correctif** : choisir **une** langue d'UI (le français, vu `lang="fr"` et l'audience) et traduire
les restes ; ou baliser les fragments anglais en `lang="en"`.

### UX-12 — Styles inline éparpillés dans le markup (MEDIUM · M7)
**Emplacement** : ≥ une douzaine de `style="…"` dans `index.html` (`:103-104,118-121,109,244,308,
325-327`…). Défait le système de tokens, fragilise le theming.
**Correctif** : déplacer dans des classes CSS utilisant les tokens existants.

### UX-13 — Ordre des titres : saut h1 → h3 (MEDIUM · M8)
**Emplacement** : `#header h1` (`index.html:15`) suivi directement des `<h3>` de sidebar
(`:46/174`), sans `<h2>` ; `<h2>` n'apparaît qu'au panneau de détail (`:267`).
**Correctif** : normaliser (sections de sidebar en `<h2>`).

---

## LOW

### UX-14 — Explications de colonnes uniquement en `title` (LOW · L1)
`index.html:325-327` (« Qualité ⓘ / Sévérité ⓘ / Halluc. ⓘ ») : `title=` + `cursor:help` inaccessible
au clavier/tactile. → légende visible ou tooltip accessible (déclencheur focusable + `aria-describedby`).

### UX-15 — Aucun landmark sémantique (LOW · L2)
`#header`/`#sidebar`/`#main`/`#detail`/`#log-wrap` sont des `<div>`. → `<header>/<nav>/<main>/<aside>`
ou rôles ARIA équivalents.

### UX-16 — Pas de skip-link (LOW · L3)
Le clavier traverse toute la sidebar avant d'atteindre le graphe/détail à chaque chargement.
→ ajouter un lien « aller au contenu ».

### UX-17 — Contrastes limites + affordance disabled (LOW · L4)
Contraste globalement bon (`#848d97` sur `#0d1117` ≈ 5.6:1). Points serrés : accent-texte `#2f81f7`
sur `#0d1117` ≈ 5.05:1 (`.md-h3`, `.service-tag`, liens) ; vert low-sev `#3fb950` sur `#1e3a1e`
≈ 4.9:1 à 9px. `button:disabled { opacity:.35 }` (`style.css:318`) : le bouton Start vert reste
visible-mais-grisé pendant un run → lecture ambiguë. → éclaircir le low-sev ; masquer plutôt que
griser le Start pendant un run.

### UX-18 — Option modèle mal libellée (LOW · L5)
`index.html:80,87` : label « Claude 3.5 Sonnet » pour `value="anthropic/claude-sonnet-4"` (label
contredit le modèle). `#sel-model` (`:55`) liste « claude-sonnet-4 » brut → nommage incohérent.
→ corriger les libellés d'affichage pour matcher les IDs.

### UX-19 — Lignes de log dépliables au clic seul (LOW · L6)
`.log-line` toggle `.expanded` au clic sans `tabindex`/`role`/clavier. → rendre focusable + clavier.

### UX-20 — Badge de coût non annoncé (LOW · L7)
`#cost-badge` (`index.html:29`) change sans `aria-live`. → `aria-live="polite"`.

### UX-21 — Table benchmark sans `scope` (LOW · L8)
15 colonnes, bien contenues par `#bm-body { overflow:auto }`, mais les `<th>` manquent `scope="col"`
et aucun traitement responsive/empilé. → ajouter `scope`.

### UX-22 — Fond de modale non `inert` (LOW · L9)
Overlays `aria-modal="true"` (bien) mais le fond n'est pas `inert`/`aria-hidden` → le curseur
virtuel SR peut errer derrière. → `inert` sur le fond à l'ouverture.

### UX-23 — Filtre scénario du Benchmark périmé (LOW)
**Emplacement** : `index.html:288-300` — le `<select id="bm-filter-scenario">` ne liste que
**S1–S10**, alors que le benchmark comporte S1–S13. → compléter S11/S12/S13 (idéalement générer les
options dynamiquement depuis `/api/scenarios`).

### UX-24 — favicon manquant (LOW)
`GET /favicon.ico → 404` (seule erreur console). → ajouter un `<link rel="icon">` (data-URI SVG
suffit) ou servir un favicon.

---

## Top 3 priorités UX
1. **Boucle de feedback (UX-1 + UX-2)** : try/catch partout + toast visible indépendant du log +
   confirmation sur Teardown/Stop. Le plus gros risque : des actions coûteuses/destructives peuvent
   échouer ou se déclencher sans signal.
2. **Chrome interactif accessible au clavier (UX-4, UX-5, UX-6, UX-7)** : vrais ARIA tabs (ou
   boutons), sections repliables en boutons `aria-expanded`, lignes d'historique valides.
3. **Cohérence (UX-11, UX-12, UX-9, UX-18)** : une seule langue d'UI, styles inline → tokens,
   `aria-pressed` + indices non-colorés, libellés de modèles corrigés.

---

## Récapitulatif

| ID | Sévérité | Emplacement |
|---|---|---|
| UX-1 | HIGH | `app.js:1189`, `style.css:1286` |
| UX-2 | HIGH | `app.js:1291,1244` |
| UX-3 | HIGH | layout / media queries (constat 375px) |
| UX-4 | HIGH | `index.html:16,268` |
| UX-5 | HIGH | `style.css:196-219` |
| UX-6 | MEDIUM | `app.js:1642` |
| UX-7 | MEDIUM | `index.html:184,253,337`, `app.js:68` |
| UX-8 | MEDIUM | `style.css:9-66` |
| UX-9 | MEDIUM | `style.css:157-158,1248` |
| UX-10 | MEDIUM | `index.html:93,134,148,117,141` |
| UX-11 | MEDIUM | markup global |
| UX-12 | MEDIUM | `index.html` (styles inline) |
| UX-13 | MEDIUM | `index.html:15,46,174,267` |
| UX-14..22 | LOW | cf. sections ci-dessus |
| UX-23 | LOW | `index.html:288-300` |
| UX-24 | LOW | favicon |
