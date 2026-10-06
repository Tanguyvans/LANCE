# LANCE : diagnostic du pipeline et rapports par campagne

## Question et périmètre

Que démontrent les métadonnées sélectionnées des runs S1–S12 sur les erreurs de workers, l'agrégation et la troncature ? Le diagnostic est une lecture hors ligne des douze runs retenus ; il ne constitue pas un nouveau run ni une validation sémantique complète.

## Documents et état

- [Diagnostic du pipeline — PDF](diagnostic-pipeline.pdf) · [source LaTeX](diagnostic-pipeline.tex). Rédaction Luna ; révision **2026-10-06 10:34 (Europe/Brussels, UTC+02:00)**. Compilation native réussie, trois pages inspectées par Codex et un relecteur indépendant le 6 octobre 2026 à 10:41 (Europe/Brussels) ; [détails et empreintes](validation.md). Le diagnostic ne démontre pas l'atteinte de l'objectif S1–S12 ; inventaire observé à 09:29 : 2 `done`, 8 `partial`, 2 `failed`, aucun `running`.
- [Run1 — PDF](run-01.pdf) · [LaTeX](run-01.tex). Révision **2026-10-05 23:38 (Europe/Brussels, UTC+02:00)** ; résultats historiques gelés à 11:32 et scores préservés. Export PDF trois pages inspecté.
- [Run2 — PDF](run-02.pdf) · [LaTeX](run-02.tex). Révision **2026-10-06 00:49 (Europe/Brussels, UTC+02:00)** ; même campagne corrective, objectif S1–S12 non atteint. Export PDF trois pages inspecté.

Le diagnostic distingue les gels de métadonnées du 5 octobre (S1–S7/S12 à 18:30, S8 à 19:31, S9 à 20:38, S10 à 21:54/21:55) et la copie valide S11 reçue le 6 octobre jusqu'à 00:31:29. Il utilise la sélection explicite et les empreintes locales dans `output/validation/2026-10-05-archive-review/pipeline-diagnostic-2026-10-06-1026/`. Les métadonnées ne sont pas des archives complètes ; les empreintes locales n'authentifient pas une provenance distante.

## Historique et limites

L'ancien journal cumulatif de 22:55 a été retiré du dossier de recherche. Sa copie intégrale et son manifeste restent dans l'archive locale non versionnée `output/validation/2026-10-05-archive-review/historical-report-2026-10-05-2255/` ; le rapport antérieur révisé à 14:42 reste consultable dans l'historique Git. Ces deux états sont distincts. Les preuves et manifestes QA sous `output/validation/2026-10-05-archive-review/pipeline-diagnostic-2026-10-06-1026/` sont également locaux et non versionnés ; voir [la fiche de validation](validation.md). Run1 et Run2 conservent leurs observations et dates historiques.

Les statuts d'inventaire et les succès de cycle de vie ne prouvent pas la validité sémantique des résultats. Un champ ou score non collecté n'est pas un zéro et ne démontre pas une indisponibilité distante. Les lectures hors ligne ultérieures devront conserver la sélection et les repères temporels et distinguer les symptômes des causes non établies.
