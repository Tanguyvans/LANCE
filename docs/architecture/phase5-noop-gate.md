# Phase 5 : gate anti-no-op en profil full

En profil full, l'agent d'intrusion terminait parfois après des turns de
lecture sans aucune tentative, alors que des points d'entrée existaient
(run S12 `2026-10-07_211430` : 6 turns, 12 appels, 0 tentative →
`blocked:phase5_no_observable_actions`). Le profil compact possède déjà
ses gardes (completion tool, fallback) ; cette gate est l'équivalent
pour le profil full.

## Règle

Au moment du save terminal (`05_intrusion.json`), la gate refuse le
finish si, à la fois :

- le ledger ne contient **aucun** appel d'action phase 5
  (`INTRUSION_ACTION_TOOLS` : `try_credential`, `ssh_exec`, `ssh_login`,
  `mqtt_listen`, `http_get`, `curl_headers`, `telnet_connect`,
  `ftp_list` — le même classifieur que la synthèse du ledger) ;
- des points d'entrée existent (`entry_points` non vide dans
  `05_intrusion_context.json`, généré avant l'agent).

Le refus (`error_kind: intrusion_no_action`) guide le modèle vers une
tentative. Tout appel compte, même en erreur : la gate exige des
tentatives, la synthèse les juge.

## Cas passants (fail-open)

- Aucun point d'entrée : finish autorisé, `blocked` honnête.
- Stop opérateur, dry run, contexte manquant, surface sans outils
  d'action : finish autorisé, la validation avale juge.
- Autres fichiers que le livrable terminal : jamais bloqués.

## Bornes et scalabilité

Décision locale en O(1) par run, sans seuil de taille : 6 ou 300
devices, même règle. Le budget de 80 turns borne toujours la phase :
la gate redirige, ne boucle jamais. Elle ne garantit pas la
compromission — des tentatives réellement échouées gardent un verdict
`failed`/`partial` honnête.

Code : `IntrusionPhase._apply_intrusion_noop_gate`
(`src/agent/phases/intrusion/run.py`), branché dans
`AgentRunner._run_agent` après la transaction des livrables.
Règle de verdict : `has_observable_actions`
(`src/agent/phases/intrusion/evidence.py`).
