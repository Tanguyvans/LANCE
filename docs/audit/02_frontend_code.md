# 02 — Code JavaScript du dashboard (`src/static/app.js`)

Fichier principal : `src/static/app.js` (~2612 lignes). Points déjà **corrects** (vérifiés, ne rien
faire) : `renderMarkdown` échappe le HTML avant d'appliquer le markdown inline et ne parse ni liens
ni images (pas d'injection `javascript:`) ; tous les `JSON.parse` sont sous try/catch ; aucun
`eval`/`new Function`/`document.write` ; l'`EventSource` est fermé avant chaque `startSSE` ;
Cytoscape est réutilisé (instance unique) ; le log DOM est capé à `MAX_LOG=300`.

---

## FE-1 — XSS stocké via bannières nmap non échappées (HIGH)

**Emplacement** : `src/static/app.js:1068` et `:1072` (injectés en `innerHTML` à `:1084`) ;
`p` est construit dans `parseNmapResult` (`:2281`) depuis les groupes de capture regex, dont la
**version/bannière** du service (`portMatch[4]`).

```js
// app.js:1068 / 1072 — les DEUX seuls sinks du fichier sans escapeHtml
? data.services.map(s => `<span class="service-tag">${s}</span>`).join('')
? hostInfo?.ports?.map(p => `<span class="service-tag">${p}</span>`).join('')
```

**Scénario** : un device malveillant/compromis du réseau scanné annonce une bannière
`x"><img src=1 onerror=alert(document.cookie)>`. Quand l'opérateur clique sur ce nœud, le script
s'exécute dans l'origine du dashboard.

**Correctif** : envelopper les deux dans `escapeHtml` (déjà utilisé par tous les autres sinks) :
```js
? data.services.map(s => `<span class="service-tag">${escapeHtml(s)}</span>`).join('')
? hostInfo?.ports?.map(p => `<span class="service-tag">${escapeHtml(p)}</span>`).join('')
```
**Effort** : XS (1 ligne × 2). **Validation** : injecter une bannière piégée → affichée littéralement, pas exécutée.

---

## FE-2 — Compteur de coût live toujours à $0.0000 (HIGH)

**Emplacement** : `src/static/app.js:1356` — `setCost(ev.cumulative_cost_usd || 0)` dans le
handler `phase_done`.

**Problème** : le backend émet `cost_usd: 0` en dur sur `phase_done` et **n'émet jamais**
`cumulative_cost_usd` (vérifié : grep backend vide). Donc chaque `phase_done` fait `setCost(0)`,
remettant le total à zéro ; la vraie valeur n'apparaît qu'à `pipeline_done` (`total_cost_usd`).

**Scénario** : l'opérateur suit un run de 6 phases ; le widget de coût affiche `$0.0000` tout du
long, puis saute au total à la toute fin.

**Correctif** : soit accumuler côté client, soit faire émettre un vrai champ cumulatif par le
backend. Côté client (option simple) :
```js
// ne PAS faire setCost(0) sur chaque phase ; accumuler si le backend envoie un coût de phase
if (typeof ev.phase_cost_usd === 'number') { _runCost += ev.phase_cost_usd; setCost(_runCost); }
```
Idéalement : émettre `cost_usd` réel par phase côté backend (`src/agent/pipeline.py`) et cumuler.
**Effort** : S. **Validation** : le coût monte progressivement pendant un run.

---

## FE-3 — `startRun` / `startBatch` sans try/catch (MEDIUM · M1)

**Emplacement** : `app.js:1190` (`startRun`), `:1228` (`startBatch`) — `await fetch(...)` sans
try/catch (contrairement à `deployScenario`/`teardownScenario`). Ligne `:1197`
`const err = await res.json()` lève aussi sur un corps non-JSON.

**Scénario** : serveur injoignable → `fetch` rejette → rejet de promesse non géré, aucun log, aucun
retour ; le graphe ayant déjà été réinitialisé par `loadTopology`, l'UI paraît à moitié initialisée.

**Correctif** : envelopper en try/catch + `addLog({type:'error', …})` ; parser l'erreur
défensivement : `const err = await res.json().catch(() => ({}))`.
**Effort** : S.

---

## FE-4 — `onerror` SSE réactive les contrôles sur coupure transitoire (MEDIUM · M2)

**Emplacement** : `app.js:1333-1342`.

**Problème** : toute coupure transitoire déclenche `onerror`, qui réactive `btn-start`, cache
`btn-stop`, appelle `loadRuns()` et planifie une reconnexion — alors que le pipeline backend tourne
toujours. **Scénario** : un hoquet réseau d'1 s fait paraître l'UI idle → l'opérateur reclique
Start et obtient un 409 « Pipeline already running », ou croit le run mort.

**Correctif** : distinguer « run terminé » de « erreur transitoire » ; ne pas repasser les boutons
en idle sur tentative de reconnexion — seulement après confirmation via `/api/pipeline/status`.
**Effort** : M.

---

## FE-5 — Timer de reconnexion `_sseRetryTimer` jamais nettoyé (MEDIUM · M3)

**Emplacement** : `_sseRetryTimer` n'est nettoyé qu'en tête de `startSSE` (`:1323`). `stopRun`
(`:1244`), `pipeline_done` (`:1390`), `batch_done` (`:1430`) et `error` (`:1443`) ferment
l'EventSource mais laissent un timer en attente.

**Scénario** : SSE en erreur (retry planifié jusqu'à 16 s), puis l'utilisateur clique Stop ou le run
finit → le timer orphelin déclenche plus tard `startSSE()`, rouvrant un flux vers un run terminé ;
le `/stream` backend ne se termine jamais (queue non vidée post-run) → connexion pendante.

**Correctif** : dans `stopRun` et les branches `pipeline_done`/`batch_done`/`error` :
```js
if (_sseRetryTimer) { clearTimeout(_sseRetryTimer); _sseRetryTimer = null; }
```
**Effort** : S.

---

## FE-6 — Course `viewRun` / `loadTopology` sur clics rapides (MEDIUM · M4)

**Emplacement** : `app.js:1710` (`viewRun`).

**Problème** : `viewRun` pose `activeRunId` puis enchaîne plusieurs `await` (`loadTopology`,
`/score`, `/report`, `fetchVulnResults`, `loadIntrusionOverlay`) qui mutent tous les globaux `cy`,
`nodeVulns`, `nodeHosts`, sans stale-guard après les `await`.

**Scénario** : clic run A puis run B rapidement → les deux invocations s'entrelacent → la topologie
de B se retrouve colorée avec les vulns/edges d'intrusion de A.

**Correctif** : capturer `const myRun = runId` et sortir après chaque `await` si
`activeRunId !== myRun` ; idéalement sérialiser les chargements de topologie.
**Effort** : M.

---

## FE-7 — Fetch vuln phase 3 mort/inatteignable (MEDIUM · M5)

**Emplacement** : `app.js:1354` (branche `phase_done` générale) vs `:1479`
(`else if (t === 'phase_done' && ev.phase === 3)` — inatteignable car la branche générale matche
toujours d'abord).

**Correctif** : déplacer l'appel `fetchVulnResults(ev.run_dir)` dans l'unique branche `phase_done`
gardée par `if (ev.phase === 3)`, et supprimer la branche morte.
**Effort** : S.

---

## FE-8 — Résultat de teardown jamais affiché (MEDIUM · M6)

**Emplacement** : `app.js:1291` (`teardownScenario`) — POST `/api/pipeline/teardown` mais, contrairement
à `deployScenario`, **n'appelle pas** `startSSE()`. Le backend pousse `teardown_done`
(`pipeline.py:428`) sans lecteur.

**Problème** : la ligne de log « Teardown terminé » n'apparaît jamais ; pire, l'événement orphelin
est rejoué plus tard quand le flux du run suivant draine la queue.

**Correctif** : appeler `startSSE()` après un POST teardown réussi (comme `deployScenario`).
**Effort** : S.

---

## FE-9 — Off-by-one des phases en mode batch (MEDIUM · M7)

**Emplacement** : `app.js:1231` — `phases: phases.length < 5 ? phases : null`. Il y a **6** phases ;
`startRun` fait correctement `< 6` (`:1173`).

**Scénario** : sélectionner exactement 5 phases sur 6 en batch envoie `null` (= « toutes »),
lançant silencieusement la phase 6 désélectionnée.

**Correctif** : `phases.length < 6 ? phases : null`.
**Effort** : XS (1 caractère). **Validation** : batch avec 5 phases → n'exécute que ces 5.

---

## FE-10 — `pollStatus` traite les événements en double (MEDIUM · M8)

**Emplacement** : `app.js:2324-2335`.

**Problème** : au rechargement, `pollStatus` rejoue `status.recent_events` via `addLog`, puis appelle
`startSSE()`. La queue backend contient encore ces mêmes événements (aucun consommateur ne les a
drainés) → le nouveau flux les ré-émet. Résultat : lignes de log en double et effets de bord
(coloration de device…) traités deux fois.

**Correctif** : soit le backend ne double-bufferise pas (retirer de `recent_events` ce qui est déjà
en queue), soit dé-dupliquer côté client (ids d'événements rejoués vs streamés).
**Effort** : M.

---

## FE-11 — `escapeHtml` n'échappe pas l'apostrophe (MEDIUM · M9)

**Emplacement** : `app.js:37-43` — échappe `& < > "` mais **pas `'`**. Utilisé pour construire des
handlers inline à arguments en quotes simples : `_renderRunItem` `onclick="viewRun('${eid}')"`
(`:1643`), `toggleCompare`/`downloadRun` (`:1652-1653`), `viewFile('${eRunId}', '${ef}')`
(`:1785-1787`), benchmark `viewRun('${escapeHtml(r.id)}')` (`:2091`).

**Scénario** : un dossier de run ou un nom de fichier contenant `'` casse le littéral JS
(`viewFile('run','x');evil()//'`). Valeurs dérivées du serveur/disque → exploitabilité faible, mais
vrai chemin de breakout et XSS latente.

**Correctif** : ajouter `.replace(/'/g,'&#39;')` à `escapeHtml`, **ou mieux** attacher les handlers
via `addEventListener` avec des attributs `data-*` au lieu de strings inline.
**Effort** : S (patch escapeHtml) / M (refonte propre en addEventListener).

---

## FE-12 — `updateDeviceProgress` interpole `id` sans échappement (LOW · L2)

**Emplacement** : `app.js:132` — `` `<span class="sa-chip ${state}" title="${id}">${icon} ${id}</span>` ``
via `innerHTML`. `id` = `device_id` d'un YAML de scénario (contrôlé par l'opérateur), donc risque
faible mais incohérent. **Correctif** : `escapeHtml(id)`.

---

## FE-13 — Contrat lâche sur `intrusion_hop` (LOW · L3)

**Emplacement** : `app.js:1395-1398` lit `ev.from_id/to_id/method` ; l'émetteur
(`pipeline.py:2488`) envoie `from_ip`/`to_ip`/`hop_index`. Géré via fallbacks `|| ip`, donc
cosmétique (labels vides), mais contrat à aligner.

---

## FE-14 — CORS wildcard (LOW · L1)

Doublon de **SEC-4** (`api/main.py:23-29`). Traité côté sécurité API.

---

## Récapitulatif

| ID | Sévérité | Fichier:ligne | Effort |
|---|---|---|---|
| FE-1 | HIGH | `app.js:1068,1072` | XS |
| FE-2 | HIGH | `app.js:1356` (+ backend) | S |
| FE-3 | MEDIUM | `app.js:1190,1228,1197` | S |
| FE-4 | MEDIUM | `app.js:1333-1342` | M |
| FE-5 | MEDIUM | `app.js:1244,1390,1430,1443` | S |
| FE-6 | MEDIUM | `app.js:1710` | M |
| FE-7 | MEDIUM | `app.js:1354,1479` | S |
| FE-8 | MEDIUM | `app.js:1291` | S |
| FE-9 | MEDIUM | `app.js:1231` | XS |
| FE-10 | MEDIUM | `app.js:2324-2335` | M |
| FE-11 | MEDIUM | `app.js:37-43` | S/M |
| FE-12 | LOW | `app.js:132` | XS |
| FE-13 | LOW | `app.js:1395-1398` | XS |
| FE-14 | LOW | → SEC-4 | — |
