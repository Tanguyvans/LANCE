# Gestion du contexte du pipeline LANCE

Date : 2026-09-29. Statut : investigation du code et protocole proposé, pas résultat de campagne. Base Git inspectée : `45c8dab892ecb4e5f513813387090e0cded1b85d`, avec changements documentaires locaux préexistants (réorganisation `research/` et `docs/`, `AGENTS.md`, README). Aucun modèle LANCE appelé, aucun run de laboratoire, SSH, commit, push ou déploiement. Cette étude ajoute seulement des documents et des reproductions locales ; les corrections proposées ne sont pas implémentées.

## 1. Conclusion principale

Il n'y a pas un seul problème de « taille du contexte ». Le code présente au moins quatre problèmes distincts : croissance sans budget d'entrée dans les conversations outils ; perte d'informations lors de projections arbitraires ; contexte compact non récupérable par certains agents ; confusion entre mémoire descriptive, décisions du contrôleur et véritable contribution du modèle. Augmenter la fenêtre ou le plafond de sortie ne traite pas ces quatre problèmes.

La phase 6 a déjà été refondue en fiches indépendantes avec assemblage déterministe : refaire le plan historique serait une régression de méthode. La priorité est de préserver la preuve brute avant de fabriquer des vues compactes, mesurer ce qui entre effectivement dans chaque requête, et fournir des lectures ciblées depuis des références stables. La recherche doit mesurer la conservation des preuves et des décisions, puis l'apport éventuel du LLM, sans lui attribuer les résultats produits par le scanner ou les reprises déterministes.

## 2. Point de départ correct et acquis à préserver

Le [plan historique](plan.md) reste archivé et remplacé ; cette étude rouvre le sujet à l’échelle du pipeline. Ses anciennes phases, lignes et estimations ne sont pas une description du pipeline actuel. Les pages actuelles lues sont [docs/architecture/report-writing.md](../../docs/architecture/report-writing.md), `run-artifacts.md`, `phase3-block-recovery.md`, [src/agent/phases/README.md](../../src/agent/phases/README.md), plus les index [research/README.md](../../research/README.md) et [docs/README.md](../../docs/README.md).

Acquis vérifiés dans le code :

- Chaque appel `chat_with_tools` démarre une conversation indépendante ([src/agent/provider.py:415](../../src/agent/provider.py)). Les phases ne transmettent donc pas simplement un énorme historique partagé de phase 1 à phase 6 ; elles reconstruisent leur contexte depuis l'état et les artefacts.
- Phase 3 : analyse par équipement, avec preuves du scanner de cet équipement ([src/agent/phases/analysis/run.py:1092-1111](../../src/agent/phases/analysis/run.py)) et voisinage explicite (`:1113-1128`). Il serait faux de dire que chaque micro-agent relit l'intégralité de la reconnaissance.
- Phase 4 : travail par hypothèse et équipement ([src/agent/phases/verification/run.py:137-173](../../src/agent/phases/verification/run.py)), avec contexte de revendication placé dans un stockage par thread (`:209-219`). L'évidence de phase 3 est distinguée d'une nouvelle vérification ([src/agent/prompts/exploit_device_vuln.txt:53-56](../../src/agent/prompts/exploit_device_vuln.txt)).
- Le journal donne des `evidence_ref`, horodatage, arguments, cible de revendication, phase, agent, origine et source de décision ([src/agent/core/executor.py:68-100](../../src/agent/core/executor.py)). Échec d'écriture de preuve fait échouer l'exécution ; cette frontière est précieuse.
- Les livrables sont liés explicitement au dossier du run ([src/agent/core/executor.py:49-50](../../src/agent/core/executor.py), [src/agent/tools/deliverable.py:131-140](../../src/agent/tools/deliverable.py)) ; ne pas réintroduire un répertoire global.
- Phase 1 et phase 3 distinguent troncature de sortie `finish_reason=length` et absence de sauvegarde ; phase 3 récupère en blocs validés sans rejouer le réseau ([src/agent/phases/analysis/run.py:1312-1332](../../src/agent/phases/analysis/run.py), `block_recovery.py:91-101`, `run.py:481-484`).
- Phase 6 : une fiche par hypothèse, tests orphelins et identités ambiguës visibles, commentaires distincts des faits ([src/agent/phases/report/sections.py:97-220](../../src/agent/phases/report/sections.py)) ; limite de contexte de 24 000 octets, jusqu'à une reprise après `length`, cache à empreinte des faits/prompt/modèle/politique ([src/agent/phases/report/run.py:57-155](../../src/agent/phases/report/run.py)). La synthèse ne dépend pas d'une génération LLM (`:91-94`). Une fiche trop grosse devient indisponible, les faits restent dans le rapport. C'est une limite explicite et conservatrice, pas un débordement silencieux.

## 3. Défauts et limites établis par inspection

### C1 — Le journal peut déjà avoir perdu la sortie native de l'outil (priorité P0)

[src/agent/tools/tool_loader.py:228-235](../../src/agent/tools/tool_loader.py) applique un filtre de lignes puis `stdout[:max_output]` avant `return json.dumps(result)` (`:243`). [src/agent/core/executor.py:128-132](../../src/agent/core/executor.py) archive seulement le résultat retourné. Exemples de plafonds : `http_get.yaml:12` 4 000 caractères ; `ssh_exec.yaml:3` 2 000 ; `nmap.yaml:6` 4 000.

**Établi :** sur ce chemin, le journal n'est pas une archive du stdout natif intégral. Le suffixe `[truncated]` signale une coupure, mais ne permet pas de récupérer la partie perdue. Une référence au journal « complet » garantit au plus le résultat de l'outil après transformation. Une coupe en amont et une coupe de présentation doivent être distinguées.

**Hypothèse à mesurer :** des preuves utiles après le préfixe disparaissent et réduisent le rappel ; aucune fréquence en laboratoire n'a été mesurée ici. Toute ablation de compression doit commencer par un enregistrement intégral borné par stockage explicite, ou déclarer l'absence de brut. Ne pas prétendre récupérer a posteriori ce qui n'a jamais été conservé.

### C2 — Pas de budget d'entrée des conversations génériques (P0 instrumentation, P1 correction)

[src/agent/provider.py:415](../../src/agent/provider.py) crée `messages`, `:647` renvoie la liste entière au fournisseur et `:986,1182` ajoute les réponses et résultats. Le `res[:2000]` de `:1181` ne limite que l'événement UI ; le modèle reçoit `res` entier. `read_deliverable` lit et renvoie le fichier entier ([src/agent/tools/deliverable.py:139-140](../../src/agent/tools/deliverable.py)).

Les profils fixent tours et sortie, pas l'entrée ni une réserve de contexte ([src/agent/execution_profiles.py:100-141](../../src/agent/execution_profiles.py)). Reconnaissance autorise 50 tours ; intrusion full 80. La résolution automatique choisit compact/full par nombre de paramètres, puis full si cette métadonnée manque (`:281-298`), pas par contexte réellement disponible, capacité observée ou limite du fournisseur.

**Établi :** aucune admission par budget de tokens d'entrée, réduction d'historique ou lecture paginée ne se trouve dans cette boucle. Les plafonds de tours bornent l'exécution mais pas à une taille de requête compatible avec chaque modèle. Le coût d'entrée cumulé peut croître fortement car chaque ancien résultat est renvoyé aux tours suivants.

**Non établi :** quelle part des erreurs actuelles est causée par saturation de fenêtre, dégradation attentionnelle, file GPU, timeout réseau ou sortie de raisonnement trop longue. Les diagnostics de requête n'enregistrent pas encore la composition/taille du prompt ([src/agent/core/provider_diagnostics.py:124-139](../../src/agent/core/provider_diagnostics.py)). `finish_reason=length` concerne la sortie et ne démontre pas une saturation d'entrée.

### C3 — Compact signifie parfois perte non récupérable, et pas seulement compression (P1)

La projection de phase 3 limite chaque résultat à environ 700 caractères en tête/queue et le cumul des entrées à 5 000 caractères ([src/agent/phases/analysis/compact.py:15-69](../../src/agent/phases/analysis/compact.py)). Elle parcourt l'ordre d'insertion, conserve les premières entrées qui rentrent, et peut éliminer des services entiers. Elle compte `omitted_entries`, mais pas les résultats individuellement coupés ni les octets retirés. Les détails des findings et les voisins ajoutés à côté ne sont pas compris dans ce plafond ([src/agent/phases/analysis/run.py:1142-1170](../../src/agent/phases/analysis/run.py)). Ce n'est donc pas un plafond du prompt complet.

La projection mentionne `03_scans/<device>.json`, mais l'analyse locale compacte reçoit `tools=[]` (`run.py:1173-1184`). Elle ne peut pas consulter cette référence. De même, la récupération par blocs affiche « see 03_scans » après une coupe brute de JSON à 12 000 caractères (`run.py:442-444`) mais expose uniquement la sauvegarde (`:481-484`). Le chemin vers la preuve existe pour l'humain, pas pour ce modèle.

**Établi :** des données peuvent être retirées avant la décision avec aucune voie de lecture pour le modèle. Les probes P1/P2 ci-dessous illustrent le mécanisme sans prouver d'impact sur un score réel.

### C4 — Récupération de phase 3 : observations sans références et dernier bloc potentiellement énorme (P1)

`block_recovery.py:230-236` garde les 16 dernières observations, les tronque à leurs 1 200 premiers caractères, conserve `tool,args,result`, sans identifiant de journal ni indicateur de coupe. `:239-262` limite leur représentation à 6 000 caractères, par classement textuel des ports/services et arrêt au premier élément qui ne rentre pas. Le contexte peut donc omettre une preuve initiale ou tardive dans une sortie, tout en ayant une sauvegarde valide. Le filtrage de pertinence des observations regarde `tool/result`, pas les arguments dans son score (`:249`).

La décomposition groupe deux services par bloc, avec quatre blocs maximum ; tout dépassement est fusionné dans le dernier (`:104-151`). Sur 20 services, les tailles deviennent `[2,2,2,14]` (probe P4). Le nombre d'appels est borné, la taille du dernier sous-problème ne l'est pas. Les preuves non attribuables sont également répliquées dans les blocs (`:195-225`).

**Établi :** ces mécanismes sont asymétriques selon l'ordre des preuves et des services. **Hypothèse :** bénéfice de récupération limité sur équipements riches ou tâches à preuves croisées. Garder le refus de promotion tant que tous les blocs n'ont pas validé ; ne pas substituer un succès scanner-only.

### C5 — Le passage phase 3 → 4/5 retire du sens sans toujours le signaler (P1)

Phase 4 reçoit `evidence[:500]` sans indicateur de coupe ([src/agent/phases/verification/run.py:169-172](../../src/agent/phases/verification/run.py)). Les autres champs structurés et le plan de vérification peuvent préserver une partie de l'information ; on ne peut donc pas conclure que toute attribution serait perdue. Mais le texte rendu ne permet pas au modèle de distinguer « preuve courte » de « début de preuve coupée ».

Phase 5 sélectionne une seule meilleure entrée par IP ([src/agent/phases/intrusion/run.py:644-655,691-718](../../src/agent/phases/intrusion/run.py)), tronque sa preuve à 200/400 caractères (`:698-706`) et limite les credentials transmis aux 30 premiers (`:820`). Les nombres totaux omis ne sont pas exposés dans ce contexte. Les autres services restent partiellement décrits par `all_targets`, mais les alternatives de constat et leur preuve ne sont plus toutes présentes. La présence des listes `attack_chains` et `all_targets` sans budget global signifie aussi que ce fichier n'a pas de plafond total explicite (`:814-828`).

Le prompt appelle ce contenu « bounded, complete campaign source » ([src/agent/prompts/intrusion.txt:35](../../src/agent/prompts/intrusion.txt)), exige une seule lecture du contexte et interdit le gros livrable précédent (`:25,36`), alors que le guidage injecté autorise la lecture phase 3/4 ([src/agent/core/runner.py:317](../../src/agent/core/runner.py)). `intrusion.txt:41` parle encore de credentials « from both files ». Cette contradiction concerne le chemin full utilisant ce template. Le chemin compact local remplace le guidage et le template (`runner.py`, lignes 327 et 383) ; ce constat ne lui est pas automatiquement applicable.

**Hypothèse :** perte d'alternatives utiles, d'éléments négatifs et de contradictions lors de la planification. Préserver une liste de candidats typés, leurs références et l'état « vérifié / candidat scanner / inconclusif », puis interroger les preuves à la demande.

### C6 — Mémo de phase 3 compact local : absence de contribution aux findings canoniques (P0 pour l'interprétation)

Ce constat est limité à `_uses_compact_local_moe()` ([runner.py](../../src/agent/core/runner.py), ligne 654). Le contraste D1/A1 actuel exige `full` : il n’est pas directement caractérisé par ce mémo.

La branche locale compacte fait écrire le JSON par le scanner puis demande un mémo au LLM ([src/agent/phases/analysis/run.py:1162-1169](../../src/agent/phases/analysis/run.py)). Elle sauvegarde ce mémo dans `03_device_<id>_analysis.md` (`:1197-1201`) puis retourne (`:1216`). L'agrégation des findings, la vérification et les fiches de rapport ne consomment pas ces sidecars dans les chemins inspectés. La validation CVE compacte est elle-même déterministe ([src/agent/phases/analysis/compact.py:72-180](../../src/agent/phases/analysis/compact.py)).

**Conclusion de code :** le score de détection de cette branche ne mesure pas l'apport de nouvelles hypothèses du mémo. Les bonnes performances du scanner ne prouvent pas le bénéfice analytique du LLM. À l'inverse, un mémo considéré inutilisable peut marquer l'analyse en échec (`run.py:1203-1206`) alors que le JSON scanner existe. Distinguer validité du résultat canonique, complétude de l'étape agent et qualité rédactionnelle.

Le contrôle des mémos est seulement structurel ([src/agent/core/memo.py:5-26](../../src/agent/core/memo.py)) : clôture des fences, derniers mots anglais, quelques placeholders. Cette branche n'envoie pas de `completion_metadata`, contrairement à l'analyse full et au rapport. Un texte proprement ponctué mais incomplet n'est donc pas rejeté grâce à `finish_reason=length` par ce contrôle d'appel. La probe P5 établit seulement la faiblesse syntaxique de l'heuristique, pas un taux de mémos tronqués réels.

### C7 — Isolation de contexte encore partiellement globale (P1 avant campagne concurrente)

[src/agent/tools/graph_tools.py:31-54](../../src/agent/tools/graph_tools.py) conserve topologie/graphe/découverte dans des variables globales ; charger un contexte réinitialise ce stockage. Les voisins sont lus depuis ce module global en phase 3 (`analysis/run.py:1113-1115`). [src/agent/tools/skill_tools.py:31-37,63-75](../../src/agent/tools/skill_tools.py) possède aussi une politique CVE et des filtres skills globaux.

**Établi :** deux objets Pipeline dans le même processus peuvent dépendre du même stockage mutable malgré l'isolation des livrables. **Non établi :** contamination observée dans un déploiement réel ni coexistence systématique dans ce mode serveur. La documentation [src/agent/phases/README.md](../../src/agent/phases/README.md) reconnaît déjà cette limite. Le verrou par fournisseur limite les appels modèle, pas l'accès à tout cet état. Proposer contexte run immuable injecté ou isolation de processus vérifiée, pas simplement davantage de locks fournisseurs.

### C8 — Phase 6 : correctifs existants utiles, sémantique encore à évaluer (P2)

Les observations de fiche ont un extrait de 1 600 caractères et une référence/digest ([src/agent/phases/report/sections.py:132-148](../../src/agent/phases/report/sections.py)). Une fiche reçoit aussi les objets complets hypothesis/test ; elle peut dépasser 24 kB et perdre uniquement son commentaire LLM (`report/run.py:95-96`). Aucun outil de lecture n'est alors disponible, par choix architectural.

Le contrôle de contradiction de rédaction se limite à quelques expressions anglaises ([src/agent/phases/report/validation.py:4-20](../../src/agent/phases/report/validation.py)) et il est appelé avec un contexte vide (`run.py:136-138`). Ce n'est pas un vérificateur sémantique général ; une explication française contradictoire pourrait passer. Le contexte vide peut aussi faire rejeter les expressions anglaises listées même si les faits de la fiche les étayent ; la fréquence de ce rejet indu n’a pas été mesurée. Le rendu marque déjà les commentaires comme non validés : il ne faut pas présenter cette limite comme une falsification des faits déterministes.

Proposer d'évaluer l'utilité/fidélité des recommandations séparément du score d'audit. Garder le rendu factuel même si le modèle échoue. Une synthèse narrative transversale optionnelle devra consommer des faits typés multi-équipements ; l'ajouter sans test risquerait de réintroduire l'ancien contexte global.

## 4. Observations locales et limites expérimentales

### Probes exécutées, sans réseau ni fournisseur

Commande : `python3 -B` avec un here-document stdlib, extraction AST de `_compact_phase3_scan_results`, et `runpy.run_path` des modules purs `block_recovery.py` et `memo.py`. Aucun import de Pipeline ni lancement scanner. Reproduction conservée :

```bash
python3.12 -B benchmarks/experiments/research-review/probe-context.py
```

Script conservé : [probe-context.py](../../benchmarks/experiments/research-review/probe-context.py).

Résultats observés : P1 marqueur central perdu et zéro entrée omise ; P2 20 services → 6, 14 omis ; P3 16 dernières observations, plus aucun marqueur de fin, 1 200 caractères par observation ; P4 blocs `[2,2,2,14]` ; P5 les deux mémos incomplets non rejetés. Ces résultats établissent le fonctionnement des transformations sur données synthétiques, pas des faux négatifs du benchmark.

La validation pytest consolidée est consignée dans le [journal de validation](../agent-vs-automation/validation.md). Tests existants lus pour les contrats : [tests/pipeline/test_analysis_block_recovery.py](../../tests/pipeline/test_analysis_block_recovery.py), [tests/test_execution_profiles.py](../../tests/test_execution_profiles.py), [tests/test_report_sections.py](../../tests/test_report_sections.py). Ils simulent des fournisseurs ; ne pas les compter comme expériences de qualité LLM.

### Artefacts historiques examinés, sans attribution abusive

Des répertoires `output/agent/2026-09-11_*` et `2026-09-12_*` sont présents. Exemples lus :

- `2026-09-11_185118/run_meta.json` : ancien mode `analyst_note`, statut `completed`, contexte annoncé 15 319 octets, omissions graph/recon 21 chacune. `06_phase6_context.json` fait 981 930 octets. Cela ne signifie pas que les 981 930 octets ont été envoyés au modèle.
- `2026-09-12_172518/run_meta.json` : ancien mode `deterministic_only`, `partial:timeout`, contexte annoncé 1 454 octets.
- `2026-09-12_203157/run_meta.json` : ancien contrat `report-v2`, `partial:timeout`, contexte annoncé 1 880 octets.

Ces métadonnées ne portent pas de révision, fournisseur, modèle ou résultats globaux ; les notes sont répétitives et peuvent provenir de tests/probes. **Provenance insuffisante pour les qualifier de runs réseau réels ou estimer un taux d'échec.** L'ancien schéma de logs ne donne pas les prompts ni finish reasons nécessaires. Le récit documentaire du 16 septembre sur neuf sections régénérées a été lu, mais ses preuves primaires n'ont pas été retrouvées/inspectées ici ; il reste un résultat rapporté par la documentation.

## 5. Architecture proposée, à tester avant décision

### P0 — Rendre les pertes et l'attribution observables

1. Capturer la sortie native avant filtre/troncature dans un artefact de preuve avec taille, empreinte, encodage, statut de capture complète/incomplète et quota stockage. Le journal référence cet artefact. Les vues compactes portent `source_ref`, offsets ou chemins JSON, version de projection, champs/éléments omis et motif. Ne jamais appeler « complète » une capture tronquée.
2. Pour chaque requête modèle, journaliser sans contenu sensible : tailles/tokens système, schémas outils, faits structurés, résultats outils, historique, réserve sortie ; limites configurées et limite fournisseur connue/inconnue ; temps d'attente séparé du temps fournisseur ; fin/reprises/raisons de réduction. L'usage retourné reste distinct de l'estimation locale.
3. Distinguer pour chaque décision `llm`, `scanner`, `controller_fallback`, `rule_baseline`, et sa cause. La présence d'un appel LLM dans la phase ne donne pas au LLM le crédit de toute la phase.

Critères proposés : toute coupe observable et liée à sa source ; tout résultat validé relié aux preuves originales disponibles ; aucune affirmation de brut complet si capture incomplète ; aucune requête au-delà du budget d'entrée connu (réserve sortie incluse) ; fenêtre inconnue signalée sans inventer une capacité.

### P1 — Vues de travail et lectures ciblées

- Un contexte par run/phase fondé sur les observations, décisions, tests tentés et hypothèses ouvertes, avec IDs et provenance. Les états `confirmé`, `inconclusif`, `erreur`, `non testé`, `candidat` sont explicites. Conserver les preuves négatives et les contradictions, sans écraser une observation par la dernière prose du modèle.
- Une API lecture seule bornée par `evidence_ref`, service/port/cible et intervalle/chemin JSON. Chaque lecture garde l'attribution du run, la taille totale et les omissions. Fournir cette lecture aux agents dont le contexte a été réduit. Elle ne rejoue aucun outil réseau.
- Le contrôleur décide quoi projeter avant l'appel. Une première politique déterministe préserve les preuves nécessaires au test courant, résultats négatifs récents, tâches restantes et références ; l'agent peut demander un détail. Ne pas introduire d'emblée un résumé LLM comme nouvelle vérité.
- Découper phase 3 par poids de preuves et tâche plutôt que toujours 2 services/4 blocs ; prévoir un travail explicite de corrélation pour les hypothèses multi-services. Une partition purement par équipement peut rater une chaîne distribuée : c'est une hypothèse à tester, pas un motif pour fusionner toutes les données.
- Phase 5 : registre de campagne persistant structuré (candidats, tests réalisés, résultats, questions ouvertes), chargé par vues pertinentes. Supprimer les coupes silencieuses et la contradiction du prompt ; préserver les transitions réseau comme hypothèses tant qu'elles ne sont pas observées.
- Remplacer globals graphe/CVE/skills par dépendances par run, ou isoler les workers par processus avec contrat d'entrée gelé. Le choix est à prendre après tests d'entrelacement, pas imposé ici.

Critères proposés : aucune preuve requise perdue sur fixtures de position ; résolution de toutes les références servies ; compteur explicite de candidats/credentials exclus ; aucun rejeu involontaire ; toute répétition justifiée, attribuée, comptée et admissible selon l’état et la répétabilité de l’action ; aucune contamination de run lors d'entrelacement A/B ; ambiguïtés conservées jusqu'à vérification.

### P2 — Apport du LLM et rédaction

Une fois la base observable, laisser le LLM choisir parmi des lectures/probes réellement alternatives là où une ambiguïté le justifie. Si le mémo compact doit influencer la détection, ajouter une proposition structurée distincte des findings scanner et la vérifier ; ne pas simplement promouvoir le Markdown. Si aucun bénéfice mesuré n'apparaît, retirer l'appel non causal du chemin critique ou le réserver à l'explication demandée par un utilisateur. Le rendu déterministe continue de fonctionner sans LLM.

## 6. Protocole d'ablation proposé

Ne pas commencer par opposer compact/full : ces profils changent simultanément outils, budgets, obligations, reprises et rôle du modèle. Un meilleur score pourrait venir du contrôleur plutôt que du contexte ou du LLM.

### Expérience hors ligne A — fidélité des représentations

Construire un corpus gelé d'observations synthétiques puis historiques dont la provenance est vérifiée. Pour chaque cas, annoter avant test les éléments indispensables : cible, service/port, condition positive/négative, résultat, contradiction, preuve et observation source. Placer la même preuve en début/milieu/fin ; modifier l'ordre des services ; varier volume, doublons, erreurs réseau, plusieurs hypothèses et preuves réparties.

Comparer : C0 brut intégral dans le budget ; C1 projection actuelle ; C2 projection déterministe avec référence et retrieval ; C3 C2 plus résumé LLM (option exploratoire). Même modèle, même politique et plafond d’entrée/sortie. Pour isoler la projection, rendre les mêmes outils de lecture disponibles à tous les bras ; une seconde ablation peut retirer ces outils de tous les bras. Le nombre de lectures effectivement choisi reste une mesure, et une restriction différente serait un facteur expérimental distinct. Inclure un contrôleur à règles et un témoin qui reçoit les seuls éléments indispensables ; ce dernier mesure une limite supérieure contrôlée, pas un système déployable.

Mesurer : rappel des preuves requises ; précision d'attribution cible/service/ref ; omissions signalées vs silencieuses ; taux de références résolubles ; contradictions perdues ; nombre de lectures ; octets/tokens avant/après et erreur de l'estimateur. Résultat attendu non présupposé : le retrieval peut être plus lent ou manquer la bonne preuve.

### Expérience hors ligne B — décision et utilité

À preuves initiales identiques et budgets gelés, comparer un routage déterministe, le même routage avec résumé LLM, un agent sélectionnant des lectures/actions, puis le même agent avec C2. Séparer hypothèses ajoutées par LLM, preuves obtenues par contrôleur et explication finale. Le mémo compacte-only est un témoin « rédaction sans influence sur la détection », pas un concurrent complet.

Mesurer : rappel/précision des hypothèses nouvelles validées ; résultats abstention/inconclusif ; gain marginal au-delà des règles ; coût et délai par preuve acceptable ; actions redondantes ; stabilité aux paraphrases et permutations ; fidélité des justifications évaluée en aveugle sur références. Un juge LLM n'est pas seul arbitre des preuves.

### Expérience C — futurs runs contrôlés, seulement après demande explicite

Sur nato/pve-nato via le circuit prévu, paires appariées avec reset, même inventaire public, même snapshot CVE, budget comparable et versions gelées. Répétitions par scénario/famille et intervalles d'incertitude ; zéro pooling opportuniste de variants partageant les mêmes fixtures. Le test final se fait sur variantes tenues à l'écart des règles/prompts/ajustements.

Prérequis : politique de contexte et critères d'acceptation figés ; séparation budget d'action/budget modèle/budget réparation ; diagnostics complets des erreurs, pas uniquement essais réussis. Le replay hors ligne ne reproduit pas les effets d'un choix sur le réseau : seul le test en ligne contrôlé peut établir la valeur de l'adaptation.

Définir avant le pilote une marge de non-infériorité et un budget coût/latence avec l'équipe. Ne pas inventer un seuil universel de « gain de 10 % ». Accepter une conclusion négative : s'il n'y a pas de gain valide sur la tâche testée, simplifier le chemin et redéfinir le périmètre d'utilité plutôt que multiplier les appels pour faire apparaître un avantage.

## 7. Sources primaires consultées et portée

Consultation : 2026-09-29. Cette revue est ciblée, pas systématique ; elle motive des hypothèses, ne valide aucun modèle présent dans LANCE.

1. Nelson F. Liu et al., *Lost in the Middle: How Language Models Use Long Contexts*, arXiv:2307.03172v3, 20 novembre 2023, publication TACL. [Version consultée](https://arxiv.org/abs/2307.03172v3). **Lu : page résumé, auteurs et historique de versions**, pas article intégral. Résultat rapporté : sur QA multi-documents et récupération clé-valeur, sensibilité à la position de l'information, avec difficultés au milieu. **Limite :** modèles et tâches de 2023 ; aucune mesure d'agents IoT ni des modèles 2026 de LANCE. Usage ici : justifier les permutations de position, pas affirmer que chaque modèle actuel a le même biais.
2. Cheng-Ping Hsieh et al., *RULER: What's the Real Context Size of Your Long-Context Language Models?*, arXiv:2404.06654v3, 6 août 2024, COLM 2024. [Version consultée](https://arxiv.org/abs/2404.06654v3). **Lu : page résumé et historique de versions**, pas article intégral. Le benchmark inclut récupération, suivi multi-étapes et agrégation ; il distingue capacité nominale et utilisation effective. **Limite :** tâches synthétiques et modèles de l'étude ; les chiffres ne se transfèrent pas au pipeline. Usage : compléter le test simple de « retrouver une aiguille » par attribution, contradictions et combinaison de preuves.
3. Anthropic Engineering, *Effective context engineering for AI agents*, 29 septembre 2025. [Article consulté](https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents). **Lu : corps principal, notamment Anatomy of effective context, Context retrieval and agentic search, Compaction et Structured note-taking.** Recommandations d'ingénierie : références légères, chargement à la demande, notes structurées et compression évaluée en préservant le rappel. **Limite :** retour d'un fournisseur, pas comparaison randomisée de LANCE ; bénéfice et coût du retrieval/sous-agents restent à mesurer. Usage : proposer un registre de preuves et des vues récupérables ; ne pas transformer la compression en vérité irréversible.

## 8. Questions précises à faire challenger par Muse

- Le défaut C1 existe-t-il sur tous les outils importants ou certains conservent-ils déjà un brut exploitable ailleurs ? Ne pas généraliser le chemin YAML à tout le catalogue.
- Quels champs du contexte de phase 4 compensent réellement `evidence[:500]`, et quelles familles perdent une information nécessaire ?
- Les sidecars de mémo local influencent-ils un autre chemin non inspecté, ou sont-ils bien purement explicatifs ?
- Les scénarios d'entrelacement Pipeline A/B sont-ils possibles dans les modes déployés ? Distinguer risque architectural et incident observé.
- Peut-on améliorer la projection avec une politique déterministe simple avant d'ajouter un outil retrieval ? Si oui, l'essayer comme concurrent fort.
- Le découpage par preuve crée-t-il trop d'appels et empêche-t-il les corrélations ? Tester tâches multi-services/multi-équipements et coût total.
- L'avantage mesuré vient-il du LLM, d'un meilleur index de preuves, de plus de budget ou des fallbacks du contrôleur ? Exiger l'ablation correspondante.
