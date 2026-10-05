# Corrections LANCE : argumentation et validation ciblée

## Question et périmètre

Quels défauts réels expliquent les échecs et résultats partiels S1–S12, pourquoi les corrections retenues sont-elles générales, et que prouvent leurs validations ? Cette étude traite les décisions de correction ; le [rapport de campagne](../2026-10-05-benchmark-coverage/README.md) conserve les résultats historiques. Seuls nato/pve-nato via nato-master, avec ollama-umons / qwen3.8:27b, sont autorisés pour les audits.

## Statut et dates

- Début : 2026-10-05.
- Dernière révision du rapport : **2026-10-05 14:42 (Europe/Brussels, UTC+02:00)**.
- État expérimental gelé : 2026-10-05 14:09 (Europe/Brussels, UTC+02:00). Les tests locaux et la relecture du code sont datés séparément dans leurs artefacts.
- Statut : corrections documentées, validation réelle en cours ; aucune réussite globale annoncée.

## Synthèse

Le suivi périodique est désactivé (`PAUSED`, vérifié). Les futurs runs doivent viser un défaut nommé restant ouvert, en priorité dans les cas `failed`/`partial`, sans répétition d'une campagne identique. Le lot correctif déjà lancé continue ; son observateur archive sans lancer d'audit.

Quatorze corrections sont déployées sur `0f4e5ff` (CI 37290434113 réussie). C15 corrige le faux refus d'une inspection statique `find` de S9, avec 141 tests et un rejeu sans exécution. C16 archive les limites et compteurs par réponse pour rendre la troncature S12 diagnostiquable : neuf régressions reproduites, 189 tests ciblés passent après correction. Les limites invalides sont omises ; les compteurs de réponse inconnus restent `null`. C15–C20 restent locales, sans déploiement pendant le lot actif. C16 ne prétend pas résoudre la synthèse.

S2 correctif termine ses six phases et son nettoyage, sans erreur du scanner (35/35 contrôles arithmétiques), mais conserve F1 confirmé 0,688 : TP 11, FP 8, FN 2. S1 correctif reste partiel : DNS sans règle et identification provisoire du service 9001. S3 est en cours au gel.

C17 corrige les refus MQTT comptés comme pannes (151 tests en deux invocations ; 4 215 appels rejoués, 33 reclassifications dont huit en phase 3, 1 609 empreintes vérifiées). C18 ajoute une sonde DNS réelle au port et transport fournis (36 tests). C19 conserve HTTP 101 comme hypothèse et exige la preuve native MQTT pour confirmer (suite finale 152 tests ; 124 fichiers de scans rejoués, quatre confirmations devenues hypothèses). Ces suites se recouvrent. Aucune validation NATO de C17–C19 n’est encore établie et la couverture `tor-orport?` reste non résolue sur NATO. C20 ajoute la sonde native qui peut identifier ce port à partir de la preuve applicative, sans alias arbitraire (183 tests, dont 31 nouveaux cas ; 124 fichiers et 1 609 empreintes vérifiées, quatre requêtes proposées sans exécution). Refus, silence, outils absents, pannes et autre destination restent diagnostiqués. La clé du présondage HTTP existant est fixe : aucune clé aléatoire fraîche n’est revendiquée. La durée et la charge ajoutées devront être mesurées. C20 reste locale, commit `e6550fd`.

Le premier S12 correctif échoue en phase 1 malgré les observations des 35 nœuds ; aucune sauvegarde validée, score indisponible HTTP 404. La continuation de reconnaissance ne peut pas encore être évaluée sur ce run. Les anciens scores et la vérité terrain restent conservés ; les changements de contrat et les admissions de preuves hors réseau ne sont pas des gains mesurés.

## Documents et preuves

- [Rapport PDF](report.pdf) et [source LaTeX](report.tex).
- [Faisceau factuel de rédaction Muse](../../output/validation/2026-10-04-qwen-umons/muse-corrections-report-2026-10-05/evidence.json).
- [Manifeste de campagne](../../output/validation/2026-10-04-qwen-umons/campaign-manifest.json).
- [Diagnostic du S12 correctif](../../output/validation/2026-10-04-qwen-umons/corrective-s12-graph-failure-review.json).
- [C16 : arguments et validation](../../output/validation/2026-10-04-qwen-umons/generation-diagnostics-correction.json).
- [Matrice S1–S12 actualisée](../../output/validation/2026-10-04-qwen-umons/s1-s12-targeted-validation-matrix.json).
- [C17 : refus MQTT](../../output/validation/2026-10-04-qwen-umons/mqtt-auth-outcome-correction.json).
- [C18 : sonde DNS](../../output/validation/2026-10-04-qwen-umons/dns-scanner-correction.json).
- [C19 : preuve MQTT WebSocket](../../output/validation/2026-10-04-qwen-umons/mqtt-ws-scanner-evidence-correction.json).
- [C20 : couverture native MQTT WebSocket](../../output/validation/2026-10-04-qwen-umons/mqtt-ws-native-scanner-coverage-correction.json).
- [S2 correctif terminé](../../output/validation/2026-10-04-qwen-umons/corrective-s2-completion-review.json).
- [Politique ciblée](../../output/validation/2026-10-04-qwen-umons/manual-targeted-corrections-policy.json).

Les artefacts volumineux restent hors du dossier de recherche. Ils peuvent ne pas accompagner le dépôt Git ; leur accès est nécessaire pour reproduire les rejeux. Les références et la table C01–C20 du PDF permettent de les retrouver.

## Validation et suites

Objectif courant : S1–S12 doivent achever leurs six phases avec livrables validés, sans erreur de phase masquée et avec nettoyage terminé. Les scores, les faux négatifs et la validité sémantique restent suivis séparément ; aucun F1 parfait n’est promis par le statut complet.

Brouillons Muse C01–C15 et C17–C20 relus et corrigés par Codex ; C16 ajoutée par Codex. Compilation native réussie et export PDF inspecté visuellement sur les **15 pages**, sommaire cliquable et références résolues. Relecture indépendante finale par `interim_report_review`, distinct de la rédaction, le **2026-10-05 à 14:52 Europe/Brussels (UTC+02:00)** : aucune réserve bloquante après correction du tableau pages 11–12. Les comptes de tests, les seules requêtes proposées du rejeu C20, les statuts gelés et les limites sont conservés. Cette relecture ciblée ne certifie pas exhaustivement les preuves historiques ni les effets réels des corrections.

Observation après le gel du PDF : S3 `2026-10-05_134540` a terminé les six phases et le nettoyage. Ses 136 empreintes et 35/35 contrôles arithmétiques passent, scanner sans erreur ; F1 confirmé 0,622 (TP 14, FP 13, FN 4). Voir [la revue de S3](../../output/validation/2026-10-04-qwen-umons/corrective-s3-completion-review.json). Le PDF conserve son état gelé à 14:09 ; cette observation ultérieure ne constitue pas une relecture sémantique exhaustive ni un gain à contrat constant.

Analyser d'abord les résultats du lot existant. Ensuite, ne lancer qu'une validation motivée : S12 pour la troncature et la couverture Recon, S9 pour C15 si le défaut persiste avec le code encore déployé, S1 pour C18–C20 et la couverture inconnue, S6 uniquement pour le défaut sémantique C19 si la validation existante ne suffit pas ; autres scénarios selon le défaut réellement ouvert. Attendre fin et nettoyage, CI du SHA exact et vérification du SHA déployé. Le dossier est maintenu au fil des corrections ; sa date reste stable.
