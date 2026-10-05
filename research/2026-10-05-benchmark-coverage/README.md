# Validation expérimentale LANCE — Qwen UMONS S1–S12

**Question :** quels résultats, défauts et limites les premiers runs réels
S1–S12 montrent-ils, et quelles corrections sont effectivement validées ?

**Date du dossier : 5 octobre 2026**, date de publication retenue pour ce
rapport. La campagne a commencé le **4 octobre 2026**. Ce dossier prolonge la
[recherche sur la couverture du benchmark](../2026-09-29-benchmark-coverage/README.md).

**Déplacement du rapport : 2026-10-05 12:32 Europe/Brussels (UTC+02:00).** La source et le PDF conservent leur
révision du 5 octobre à 11:48 et leur gel des données à 11:32 ; leurs contenus
et empreintes sont inchangés par ce déplacement.

## Campagne Qwen UMONS du 4 octobre 2026

**Statut : premier lot terminé ; validations correctives en cours, rapport
intermédiaire.** Périmètre demandé : S1–S12, six phases, profil `full`,
modèle `qwen3.8:27b` avec `ollama-umons`, exécution sur nato/pve-nato
uniquement. La campagne relève du développement ; aucune évaluation
indépendante tenue à l'écart n'est revendiquée.

**Dernière révision du rapport complémentaire : 2026-10-05 11:48
(Europe/Brussels, UTC+02:00).** Les données numériques sont gelées au
**2026-10-05 11:32 (Europe/Brussels, UTC+02:00)** : quatorze archives,
1 582 empreintes vérifiées, deux S1 de diagnostic séparés, S1 commun du lot,
audits et rapports S2–S11, et échec de reconnaissance S12. S12 n'a ni score
ni rapport final ; son nettoyage a réussi. Le score manquant reste indisponible,
jamais zéro.

Les F1 officiels de la population confirmée sont repris sans réévaluation :
S1 commun **0,880** (11 VP, 2 FP, 1 FN) ; S2 0,750 ; S3 0,545 ; S4 0,450 ;
S5 0,541 ; S6 0,686 ; S7 0,552 ; S8 0,483 ; S9 0,538 ; S10 0,333 ; S11 0,481.
Les deux diagnostics S1 (0,917 et 0,846) ne sont pas agrégés au lot. Tous
ces scores historiques utilisent `strict-v3.14` / `evidence-v13`. Les contrôles
arithmétiques sont distincts de la validité sémantique : le S1 commun a
16 tests effectués et une ligne ignorée, mais deux compteurs périmés ; le crédit
robots de S6 est incorrect. Les revues ciblées S8–S11 et S1 commun précisent la
portée des lectures et accès, sans certification exhaustive des faux négatifs,
preuves secondaires ou propriétés de la vérité terrain.

Quatorze corrections générales étaient préparées au gel, tête
`0f4e5ff882eeb43faed6756a5c0d008a1f6a798d`, CI finale encore en cours. Leurs
rejeux hors réseau ne constituent pas des gains mesurés. Le rejeu natif compare
`b39b0b1` préparé/non déployé à `0f4e5ff`, pas au baseline `e9d7d55` ; neuf
admissions de preuves changent sans modification des traces, des scores ou de
la vérité terrain. Les futurs runs utilisent `strict-v3.16` / `evidence-v15` ;
l'étape préparée `strict-v3.15` / `evidence-v14` n'a jamais été déployée.

**Suivi postérieur au gel, séparé des tableaux expérimentaux.** La CI finale
[37290434113](https://github.com/Tanguyvans/LANCE/actions/runs/37290434113)
a réussi sur le SHA exact : 3 213 tests passés, un ignoré ; le déploiement
`deploy-master / update` a réussi. L'API principale a confirmé ce SHA et un
état inactif après nettoyage. Le **5 octobre à 11:47**, le lot correctif
`batch-a4a0a1d88e00` a été lancé avec la file exacte **S12, S1, puis S2–S11**,
six phases, profil `full`, nettoyage automatique, sans plafond monétaire.
Il valide les corrections en développement ; aucun résultat de ce lot n'entre
dans le bilan gelé. Requête, CI, réponse de lancement, watcher et état réel
sont conservés dans les fichiers `corrective-batch-*` et `corrective-main-ci.*`.

L'arrêt prévu après S12 dans la file originale a échoué : mutation sans
authentification administrateur, HTTP 401. **Tous les S13–S19 ont été exécutés
avant le S1 terminal** ; leurs scores sont exclus du bilan et leurs archives
préservées. La fin naturelle de `batch-aeedb60283ef` ne valide pas le mécanisme
d'arrêt. Le nouveau lot est explicitement borné à S1–S12 : l'ancien garde
`stop_after_scenario.py` ne doit pas être relancé pour cette nouvelle file.
Aucun déploiement ne doit avoir lieu pendant un lot actif.

- [Rapport expérimental — PDF intermédiaire](validation-qwen-umons.pdf).
- [Source LaTeX éditable](validation-qwen-umons.tex).
- Artefacts : `output/validation/2026-10-04-qwen-umons/`, avec requêtes,
  scores officiels, journaux et empreintes.
- Nouvelle rédaction Muse, faisceau gelé, relecture et validation du livrable :
  `output/validation/2026-10-04-qwen-umons/muse-baseline-report-2026-10-05/`.
- Version précédente 10:36 et gel 10:12 : `previous-report.tex/pdf` dans ce
  sous-dossier. Son historique de relecture est conservé ci-dessous.

Points ouverts : résultats du lot correctif, revue des erreurs réelles,
faux négatifs et preuves secondaires, validation en laboratoire des corrections
et bilan final. Le suivi reste actif jusqu'à la livraison finale.

## Relecture du rapport intermédiaire du 4 octobre 2026

Muse (`muse-spark-1.3`, effort `high`) a rédigé la première source à la demande
de Tanguy, à partir d'un faisceau d'archives gelé, en lecture seule. Codex a
confronté ses chiffres aux scores et registres, puis corrigé les définitions,
les références, les conditions de reproduction, les statuts de validation et
la pagination. Le rapport distingue les corrections déjà déployées des huit
commits préparés et non déployés ; les rejeux hors réseau ne deviennent pas des
résultats de nouveaux runs.

La version **2026-10-04 22:36 (Europe/Brussels, UTC+02:00)** a été compilée
avec succès par l'éditeur LaTeX intégré, puis exportée en PDF. Codex et le
relecteur indépendant `interim_report_review` ont inspecté visuellement
**toutes les pages 1–9** du dernier rendu : sommaire, tableaux, pagination et
bibliographie. Le relecteur a contrôlé le faisceau gelé, les revues S4/S5 et les
six configurations archivées. Aucune réserve bloquante de clarté, cohérence
avec ce faisceau ou rendu ne reste dans ce périmètre.

Cette relecture ne constitue ni une nouvelle expérience ni une certification
de la validité de toutes les preuves. Le relecteur indépendant n'a pas revérifié
les sources externes de CI, MySQL ou Nmap ni tous les journaux originaux.
La rédaction, les corrections Codex, les empreintes des deux fichiers livrés
et le périmètre de contrôle sont conservés dans
`output/validation/2026-10-04-qwen-umons/muse-report/`, notamment
`codex-review.json` et `delivery-validation.json`.

## Relecture du rapport intermédiaire du 5 octobre 2026

Muse (`muse-spark-1.3`, effort `high`) a rédigé la source en lecture seule à
la demande de Tanguy, avec un faisceau gelé à 10:12. Codex a corrigé les
statuts, la portée des preuves, les identifiants, les références et la mise en
page, puis vérifié les douze lignes de F1 officiels et les consommations.
Les 1 500 empreintes contrôlées couvrent les treize archives du périmètre,
dont deux S1 distincts et S12 sans score. Les inspections complémentaires
S9/S10/S12 sont explicitement séparées des données numériques gelées.

La version **2026-10-05 10:36 (Europe/Brussels, UTC+02:00)** compile avec
l'éditeur LaTeX intégré et a été exportée en PDF. Codex et le relecteur
indépendant `interim_report_review` ont inspecté **toutes les pages 1–13**
du dernier rendu ; les corrections ont été revérifiées et le sommaire
correspond à la pagination. Aucune réserve bloquante de clarté, cohérence
avec le faisceau contrôlé ou mise en page ne reste dans ce périmètre.

Cette relecture ne certifie pas les preuves complètes S8–S11 ni les
corrections en laboratoire. Le relecteur n'a pas reconsulté les sources
externes CI, MySQL et Nmap. Les contrôles, empreintes et réserves sont dans
`output/validation/2026-10-04-qwen-umons/muse-report-2026-10-05/`, notamment
`codex-review.json` et `delivery-validation.json`. L'ancienne version 22:36
du 4 octobre est conservée dans `previous-validation-qwen-umons.tex/pdf`.

## Relecture du bilan initial terminé — version du 5 octobre à 11:48

Muse (`muse-spark-1.3`, effort `high`) a rédigé un nouveau brouillon en lecture
seule sur le faisceau gelé à 11:32 ; sortie réussie, état Git inchangé par Muse.
Codex a restauré les identifiants exacts et références, contrôlé les treize
lignes de scores officiels et les 1 582 empreintes, corrigé la durée et les
compteurs du S1 commun, les définitions VP/FN et les limites de preuve. Le
rapport sépare le bilan gelé et le suivi postérieur (CI, déploiement et lancement
correctif) ; aucun résultat correctif n'est anticipé.

La version **2026-10-05 11:48 (Europe/Brussels, UTC+02:00)** compile avec
succès dans l'éditeur LaTeX intégré et a été exportée en PDF. Codex a inspecté
les pages 1–14 puis revérifié les pages affectées par les dernières retouches.
Le relecteur indépendant `interim_report_review` a inspecté **toutes les
14 pages du PDF final**, lu la source complète, confronté les tableaux au
snapshot, les revues ciblées et les pièces locales CI/lancement. Les 23 liens
du sommaire possèdent des destinations résolues, la pagination concorde et les
trois tableaux sont complets. Aucune réserve bloquante de clarté, rigueur dans
ce périmètre ou mise en page ne reste. Le compilateur local signale l'absence
de motifs de césure français préchargés ; aucun débordement ni référence
indéfinie dans le dernier export, rendu contrôlé.

Cette relecture ne certifie pas exhaustivement les preuves S8–S11, les faux
négatifs, preuves secondaires ou fixtures et ne remplace pas les nouveaux runs.
Le relecteur n'a effectué aucun contrôle réseau ni nouvelle consultation des
sources externes. Source et PDF, empreintes, corrections et contrôles sont
consignés dans `muse-baseline-report-2026-10-05/codex-review.json` et
`delivery-validation.json`, sous la base d'artefacts. La campagne et son suivi
restent actifs ; le rapport final dépend des validations réelles.
