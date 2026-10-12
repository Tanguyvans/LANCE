# LANCE : diagnostic du pipeline et rapports par campagne

**Cycle de vie : Conclu** (inventaire du 2026-10-12) — diagnostic et rapports de campagne gelés (objectif S1–S12 non atteint, constat conservé) ; toute nouvelle campagne relève d'un nouveau dossier daté.

## Question et périmètre

Que démontrent les métadonnées sélectionnées des runs S1–S12 sur les erreurs de workers, l'agrégation et la troncature ? Le diagnostic est une lecture hors ligne des douze runs retenus ; il ne constitue pas un nouveau run ni une validation sémantique complète.

## Documents et état

- [Diagnostic du pipeline — PDF](diagnostic-pipeline.pdf) · [source LaTeX](diagnostic-pipeline.tex). Rédaction Luna ; dernière révision **2026-10-06 10:34 (Europe/Brussels, UTC+02:00)**. Relu sur la source et les trois pages PDF par Codex et un relecteur indépendant le 6 octobre 2026 à 10:41 (Europe/Brussels) : trois passes d'export, 17 destinations PDF et 13 liens internes valides, aucune réserve ([revue finale](../../output/validation/2026-10-05-archive-review/pipeline-diagnostic-2026-10-06-1026/final-review.json)). Ce diagnostic ne démontre pas que l'objectif S1–S12 est atteint. Inventaire observé à 09:29 : 2 `done`, 8 `partial`, 2 `failed`, aucun `running`.
- [Run1 — PDF](run-01.pdf) · [LaTeX](run-01.tex). Révision **2026-10-05 23:38 (Europe/Brussels, UTC+02:00)** ; résultats historiques gelés à 11:32, scores recopiés sans recalcul ; PDF réexporté et inspecté sur trois pages.
- [Run2 — PDF](run-02.pdf) · [LaTeX](run-02.tex). Révision **2026-10-06 00:49 (Europe/Brussels, UTC+02:00)** ; même campagne corrective, objectif S1–S12 non atteint ; PDF réexporté et inspecté sur trois pages.

Le diagnostic distingue les gels de métadonnées du 5 octobre (S1–S7/S12 à 18:30, S8 à 19:31, S9 à 20:38, S10 à 21:54/21:55) et la copie valide S11 reçue le 6 octobre jusqu'à 00:31:29. Il utilise la sélection explicite et les empreintes locales dans `output/validation/2026-10-05-archive-review/pipeline-diagnostic-2026-10-06-1026/`. Les métadonnées ne sont pas des archives complètes ; les empreintes locales n'authentifient pas une provenance distante.

## Historique et limites

L'ancien journal cumulatif révisé à 22:55 a été retiré du dossier de recherche ; sa copie intégrale est conservée hors de ce dossier : [source archivée](../../output/validation/2026-10-05-archive-review/historical-report-2026-10-05-2255/report.tex) · [PDF archivé](../../output/validation/2026-10-05-archive-review/historical-report-2026-10-05-2255/report.pdf) · [manifeste](../../output/validation/2026-10-05-archive-review/historical-report-2026-10-05-2255/archive-manifest.json). Run1 et Run2 restent des rapports distincts ; le diagnostic ne modifie ni leurs observations ni leurs dates.

Les statuts d'inventaire et les succès de cycle de vie ne prouvent pas la validité sémantique des résultats. Un champ ou score non collecté n'est pas un zéro et ne démontre pas une indisponibilité distante. Les lectures hors ligne ultérieures devront conserver la sélection et les repères temporels et distinguer les symptômes des causes non établies.
