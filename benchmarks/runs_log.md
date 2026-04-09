# Benchmark Runs Log — Scenario 2

Suivi par run : changements déployés, score, vulnérabilités trouvées/manquées, FPs, diagnostic.
Objectif max : 10/10 recall, 0 FP CVE hallucinations.

---

## Grille de référence S2

| ID | Device | Sévérité | Catégorie |
|----|--------|----------|-----------|
| V1 | s2-router | CRITICAL | no_auth (LuCI WAN) |
| V2 | s2-router | MEDIUM | insecure_protocol (Telnet) |
| V3 | s2-mqtt | HIGH | no_auth (MQTT anonyme) |
| V4 | s2-iot-gw | HIGH | terrapin CVE-2023-48795 |
| V5 | s2-iot-gw | HIGH | no_auth (HTTP /admin) |
| V6 | s2-db | CRITICAL | default_credentials (MySQL root) |
| V7 | s2-jump | HIGH | default_credentials (SSH admin:admin) |
| V8 | s2-web | HIGH | directory_listing + data_exposure |
| V9 | s2-mqtt | MEDIUM | data_exposure (credentials MQTT) |
| V10 | s2-iot-gw | MEDIUM | insecure_update (OTA /update) |

Score max pondéré : 29 pts (CRITICAL=4, HIGH=3, MEDIUM=2)

---

## Run 092713 — baseline

**Modèle :** deepseek/deepseek-chat-v3-0324
**Changements déployés :** aucun (baseline)

| V1 | V2 | V3 | V4 | V5 | V6 | V7 | V8 | V9 | V10 |
|----|----|----|----|----|----|----|----|----|-----|
| ✅ | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |

**Recall : 6/10 — Score pondéré : ~17/29 (59%)**

**FPs notables :** CVE hallucinations (Mosquitto, nginx 2009)

**Problèmes identifiés :**
- s2-iot-gw : agent n'a jamais appelé save_deliverable → fallback sauvegarde du texte markdown, pas du JSON
- s2-db : fichier complètement absent → provider `_openai_loop` retournait `""` (dernier message content=None)
- Phase 2 inutile (2 tool calls) : DeepSeek écrivait "Would you like me to proceed?" → provider sortait de la boucle
- V3/V9 absents : `aggregate_device_results` crashait sur le fichier s2-mqtt (caractères de contrôle `\n` dans evidence JSON)
- V1 sévérité LOW au lieu de CRITICAL : trigger LuCI attendait un texte "LuCI" dans la réponse, 403 ne suffisait pas

---

## Run 110519 — fixes infrastructure

**Modèle :** deepseek/deepseek-chat-v3-0324
**Changements déployés :**
- `deliverable.py` : `_sanitize_control_chars()` + fix regex `_extract_json` + aggregate appelle `_extract_json`
- `pipeline.py` : fallback utilise `_extract_json` pour .json, message user plus fort, `phase_start` avant sub-agents
- `provider.py` : tracking `last_nonempty_text` pour éviter fallback vide
- `_rules.txt` + `recon.txt` : bloc "no permission asking" + "execute autonomously"
- `vuln_device.txt` : règle V1 CRITICAL (any HTTP response sur router), sévérité V9 MEDIUM, règles rejet CVE

| V1 | V2 | V3 | V4 | V5 | V6 | V7 | V8 | V9 | V10 |
|----|----|----|----|----|----|----|----|----|-----|
| ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ |

**Recall : 8/10 — Score estimé : ~73% (run dashboard)**

**FPs notables :** CVE-2026-32710/35549 (MariaDB hallucination), CVE-2009-2629 nginx (pre-2015), CVE-2021-41039/2023-28366 (Mosquitto 2.0.21 > upper bound)

**Problèmes restants :**
- V7 : agent s2-jump trouve seulement weak_cipher, pas default_credentials. Prompt dit "ssh-auth-methods" pour ssh_server mais trigger ambigu (attendait PasswordAuthentication=yes dans ssh_audit, non fiable sur Dropbear)
- V10 : /firmware/ directory listing trouvé mais pas classifié insecure_update. Aucun trigger pour /update → 200

---

## Run 120417 — fixes CVE + V7 + V10 (v1)

**Modèle :** deepseek/deepseek-chat-v3-0324
**Changements déployés :**
- `vuln_device.txt` : mandatory version check CVE (écriture explicite detected/range/yes-no), exemples de rejets, règle CVE futur (2026+), règle pre-2015 renforcée
- `vuln_device.txt` : NOTE Dropbear dans section SSH (ssh_audit non fiable pour PasswordAuthentication)
- `vuln_device.txt` : Default credentials : "publickey, password" compte, mandatory even if ssh_audit silent
- `vuln_device.txt` : trigger /update 200 → insecure_update MEDIUM, règle iot_gateway /firmware/ sans .sha256
- `vuln_device.txt` : checklist HTTP ajout insecure_update

| V1 | V2 | V3 | V4 | V5 | V6 | V7 | V8 | V9 | V10 |
|----|----|----|----|----|----|----|----|----|-----|
| ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ |

**Recall : 8/10 — Score estimé : ~82% pondéré (24/29)**

**FPs notables :** CVE-2026-32710/35549 encore présents (règles pas encore déployées au moment du run), CVE-2009-2629 sur nginx, CVE-2021-41039/2023-28366 (Mosquitto)

**Note :** meilleur run en score pondéré. CVE hallucinations réduites mais pas éliminées. V7/V10 toujours manquants.

---

## Run 133632 — fixes CVE + V7 + V10 (v2) — REGRESSION

**Modèle :** deepseek/deepseek-chat-v3-0324
**Changements déployés :** idem 120417 (run avec les fixes committés)

| V1 | V2 | V3 | V4 | V5 | V6 | V7 | V8 | V9 | V10 |
|----|----|----|----|----|----|----|----|----|-----|
| ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ |

**Recall : 7/10 — Régression**

**FPs notables :** default_credentials sur s2-iot-gw et s2-router (ssh-auth-methods lancé sur mauvais devices), CVE-2018-19630/2019-19945 uhttpd (version non confirmée)

**Régressions causées par les changements :**
- NOTE Dropbear dans section SSH → agent s2-iot-gw a focalisé sur password auth au lieu de lire ssh_audit output pour Terrapin → V4 perdu
- NOTE Dropbear → ssh-auth-methods lancé sur iot_gateway et router (pas seulement ssh_server) → FPs default_credentials
- s2-jump : fichier absent malgré 8 turns / 9 tool calls / 122k input tokens. 441 output tokens seulement → LLM n'a produit aucun texte → `last_nonempty_text` vide → fallback vide → fichier non créé

**À corriger :**
- Supprimer le NOTE Dropbear (cause régression V4 + FPs)
- Résoudre s2-jump fichier manquant (fallback ne fonctionne pas si LLM ne produit jamais de texte)
- V10 toujours absent : curl_headers teste bien /update (GET → 200 confirmé dans Ansible) mais finding non créé

---

## Run 145653 — Repeating tool detector + Reflector retry + NOTE Dropbear retiré

**Modèle :** deepseek/deepseek-chat-v3-0324
**Changements déployés :**
- `provider.py` : Repeating tool detector dans `_openai_loop` et `_anthropic_loop` (3× même tool → warning injecté)
- `pipeline.py` : Reflector retry dans `_run_single_device()` — si fichier absent ou JSON invalide → relance avec max_turns=5 + required_tool=save_deliverable
- `pipeline.py` : SSE events `device_start/done/reflector_start/done` pour le dashboard
- `vuln_device.txt` : NOTE Dropbear supprimée (cause de la régression V4 + FPs default_credentials sur mauvais devices)
- `static/` : barre de progression sub-agents (phase 3 dashboard)

| V1 | V2 | V3 | V4 | V5 | V6 | V7 | V8 | V9 | V10 |
|----|----|----|----|----|----|----|----|----|-----|
| ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

**Recall : 10/10 (100%) — F1 : 0.715 — Score pondéré : 26/29 (89.7%) — Coût : $0.23**

**FPs (8) :**
- s2-iot-gw `known_cve` : doublon V4 (Dropbear/Terrapin reporté en 2 types différents)
- s2-iot-gw `directory_listing` : /firmware/ = sous-partie de V10 reportée en finding séparé
- s2-iot-gw `default_credentials` : ssh-auth-methods lancé malgré role=iot_gateway (pas ssh_server)
- s2-router `default_credentials` : idem, ssh-auth-methods sur router
- s2-router `known_cve` ×2 : CVE uHTTPd XSS + integer signedness (version non confirmée)
- s2-web `data_exposure` ×2 : V8 splitté en 2 findings (backup/ + app.config)

**Analyse :**
- V7 et V10 enfin trouvés (fixes des sessions précédentes confirmés)
- V4 retrouvé (NOTE Dropbear supprimée = plus de distraction)
- s2-jump : fichier présent, 6 turns, pas de reflector déclenché → repeating detector a aidé
- FPs principaux = ssh-auth-methods encore lancé sur non-ssh_server + duplications

**À corriger :**
- Scoper `ssh-auth-methods` UNIQUEMENT au role `ssh_server` (retirer pour router et iot_gateway)
- Dédupliquer data_exposure web : si même device + même base path (backup/, config/) → merger en 1 finding
- Renforcer version check CVE pour OpenWrt/uHTTPd (pas de version détectable → REJECT)

---

## Run 160046 — fixes FPs (ssh-auth-methods scope + data_exposure dédup + uHTTPd)

**Modèle :** deepseek/deepseek-chat-v3-0324
**Changements déployés :**
- `vuln_device.txt` : ssh-auth-methods scopé ssh_server ONLY (pas iot_gateway/router)
- `vuln_device.txt` : data_exposure web → 1 finding par device (merge multi-path)
- `vuln_device.txt` : directory_listing /firmware/ sur iot_gateway absorbé dans insecure_update
- `vuln_device.txt` : Terrapin known_cve doublon interdit
- `vuln_device.txt` : uHTTPd sans version → REJECT CVEs

| V1 | V2 | V3 | V4 | V5 | V6 | V7 | V8 | V9 | V10 |
|----|----|----|----|----|----|----|----|----|-----|
| ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

**Recall : 9/10 — Precision : 90% — F1 : 0.900 — Score pondéré : 24.5/29 (84.5%) — Coût : $0.23**

**FPs (1) :**
- s2-db `known_cve` MariaDB 11.8.6 — range CVE ambigu ("11.5.x through 11.8") mal interprété

**Manquant :**
- V2 Telnet (port 23 sur s2-router) — nmap port 23 non appelé malgré la règle existante

**À corriger :**
- Renforcer Telnet MANDATORY dans section + pre_save_checklist
- Exemple MariaDB 11.8.6 range ambigu → REJECT dans les exemples de rejet

---

---

## Run S4-080323 — premier run S4 avec fixes OT (avant recon allégé)

**Modèle :** deepseek/deepseek-chat-v3-0324
**Changements déployés :** vuln_device.txt (modbus port 502, web_upload, camera, HMI), vuln_analysis.txt (keep ALL findings)
**Recon :** rouge (max_turns 30 épuisé sur 8 devices — non encore corrigé)

| V1 | V2 | V3 | V4 | V5 | V6 | V7 | V8 | V9 | V10 | V11 |
|----|----|----|----|----|----|----|----|----|-----|-----|
| ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

**Recall : 10/11 (91%) — F1 : 0.769 — Score pondéré : 22.2/32 (69.4%) — Coût : $0.27**

**FPs (5) :**
- s4-hmi data_exposure (hors GT)
- s4-lora-gw directory_listing + insecure_update (doublons de V11)
- s4-mqtt data_exposure (MQTT topics sans credentials dans GT)
- s4-historian insecure_update (hors GT)

**Manquant :**
- V2 code_injection (web_upload) — endpoint /upload non testé dans ce run

**À corriger :**
- Recon allégé (nmap only, max_turns 20) — déployé après ce run
- web_upload POST /upload test — dans vuln_device.txt depuis ce run
- FPs insecure_update sur mauvais devices — lié à la règle iot_gateway trop large

---

## Synthèse des patterns

| Pattern | Runs affectés | Fix tenté | Statut |
|---------|--------------|-----------|--------|
| Fichier agent absent (fallback vide) | 092713 (s2-iot-gw, s2-db), 133632 (s2-jump) | Reflector retry | **Fixé en 145653** |
| CVE hallucinations (year ≥ 2026) | 110519, 120417 | règle rejet year | **Fixé** — 0 CVE futur en 145653 |
| CVE version hors range (Mosquitto) | 110519, 120417 | mandatory version check | **Fixé** — plus présent en 145653 |
| V7 default_credentials ssh_server | tous sauf 145653 | ssh-auth-methods + prompt V7 | **Fixé en 145653** |
| V10 insecure_update iot_gateway | tous sauf 145653 | trigger /update 200 + /firmware/ | **Fixé en 145653** |
| V4 Terrapin regression | 133632 | NOTE Dropbear supprimée | **Fixé en 145653** |
| ssh-auth-methods étendu aux mauvais devices | 133632, 145653 | scope → ssh_server seulement | **Fixé en 160046** |
| CVE hallucinations OpenWrt/uHTTPd | 145653 | version check renforcé uHTTPd | **Fixé en 160046** |
| data_exposure web splitté en 2 findings | 145653 | règle déduplication par device+path | **Fixé en 160046** |
| V2 Telnet manquant S2 | 160046 | MANDATORY renforcé dans section + checklist | **Fixé en 202717** |
| CVE MariaDB range ambigu | 160046, 202717 | exemple de rejet ajouté | En cours |
| Recon rouge (max_turns trop bas) | 160046, 080323 | recon allégé (nmap only, 20 turns) | **Fixé (à déployer)** |
| V2 code_injection web_upload | S4-080323, S7 | section web_upload POST /upload ajoutée | En cours |
| FPs insecure_update sur mauvais devices | S4-080323 | scope iot_gateway rule trop large | En cours |
| Aggregation dropping findings | 160046, S4-215728 | keep ALL findings rule | **Fixé (à déployer)** |
