# Corrections LANCE : argumentation et validation ciblée

## Question et périmètre

Quels défauts réels expliquent les échecs et résultats partiels S1–S12, pourquoi les corrections retenues sont-elles générales, et que prouvent leurs validations ? Cette étude traite les décisions de correction ; le [rapport de campagne](../2026-10-05-benchmark-coverage/README.md) conserve les résultats historiques. Seuls nato/pve-nato via nato-master, avec ollama-umons / qwen3.8:27b, sont autorisés pour les audits.

## Statut et dates

- Début : 2026-10-05.
- Dernière révision du rapport : **2026-10-05 13:10 (Europe/Brussels, UTC+02:00)**.
- État expérimental gelé : 2026-10-05 12:45 (Europe/Brussels, UTC+02:00). C16 a été préparée et testée après cet instant ; sa validation est datée dans son artefact.
- Statut : corrections documentées, validation réelle en cours ; aucune réussite globale annoncée.

## Synthèse

Le suivi périodique est désactivé (`PAUSED`, vérifié). Les futurs runs doivent viser un défaut nommé restant ouvert, en priorité dans les cas `failed`/`partial`, sans répétition d'une campagne identique. Le lot correctif déjà lancé continue ; son observateur archive sans lancer d'audit.

Quatorze corrections sont déployées sur `0f4e5ff` (CI 37290434113 réussie). C15 corrige le faux refus d'une inspection statique `find` de S9, avec 141 tests et un rejeu sans exécution. C16 archive les limites et compteurs par réponse pour rendre la troncature S12 diagnostiquable : neuf régressions reproduites, 189 tests ciblés passent après correction. Les limites invalides sont omises ; les compteurs de réponse inconnus restent `null`. C15/C16 restent locales, sans déploiement pendant le lot actif. C16 ne prétend pas résoudre la synthèse.

Le premier S12 correctif échoue en phase 1 malgré les observations des 35 nœuds ; aucune sauvegarde validée, score indisponible HTTP 404. La continuation de reconnaissance ne peut pas encore être évaluée sur ce run. Les anciens scores et la vérité terrain restent conservés ; les changements de contrat et les admissions de preuves hors réseau ne sont pas des gains mesurés.

## Documents et preuves

- [Rapport PDF](report.pdf) et [source LaTeX](report.tex).
- [Faisceau factuel de rédaction Muse](../../output/validation/2026-10-04-qwen-umons/muse-corrections-report-2026-10-05/evidence.json).
- [Manifeste de campagne](../../output/validation/2026-10-04-qwen-umons/campaign-manifest.json).
- [Diagnostic du S12 correctif](../../output/validation/2026-10-04-qwen-umons/corrective-s12-graph-failure-review.json).
- [C16 : arguments et validation](../../output/validation/2026-10-04-qwen-umons/generation-diagnostics-correction.json).
- [Politique ciblée](../../output/validation/2026-10-04-qwen-umons/manual-targeted-corrections-policy.json).

Les artefacts volumineux restent hors du dossier de recherche. Ils peuvent ne pas accompagner le dépôt Git ; leur accès est nécessaire pour reproduire les rejeux. Les références et la table C01–C16 du PDF permettent de les retrouver.

## Validation et suites

Brouillon C01–C15 : Muse, en lecture seule. Codex corrige les comptes S2, les affirmations trop fortes, les limites de la grammaire `find`, la preuve SNMP et le plan de reruns ; ajoute C16 et ses tests. Compilation native réussie et export PDF vérifié sur les **10 pages**, avec sommaire cliquable et références résolues. Relecture indépendante finale par `interim_report_review`, distinct de la rédaction, le **2026-10-05 à 13:12 Europe/Brussels (UTC+02:00)** : aucune réserve bloquante. Les comptes, C11, les champs C16 et les correspondances C10 : S2/S7, C11 : S3/S7 ont été corrigés avant livraison. Cette relecture ciblée ne certifie pas exhaustivement les preuves historiques ni les effets réels des corrections.

Analyser d'abord les résultats du lot existant. Ensuite, ne lancer qu'une validation motivée : S12 pour la troncature et la couverture Recon, S9 pour C15 si le défaut persiste avec le code encore déployé, autres scénarios selon le défaut réellement ouvert. Attendre fin et nettoyage, CI du SHA exact et vérification du SHA déployé. Le dossier est maintenu au fil des corrections ; sa date reste stable.
