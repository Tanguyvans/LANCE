# Validation du rapport d'ensemble LANCE et IoTChainBench

- Révision livrée : **2026-10-15 22:53 (Europe/Brussels, UTC+02:00)**.
- Livrables : `report.tex` autonome et `report.pdf` compilé.
- PDF : **44 pages**, huit figures TikZ, dix tableaux, un glossaire et 136 références.
- SHA-256 du PDF : `4675be0998ce8d1f64491935ec9d1390b5fd463b820784350bbcc04dc0924ae0`.
- La première synthèse de onze pages, révision 21:28, est remplacée dans les mêmes fichiers.
- La version approfondie de 41 pages, révision 21:51, est complétée par la présente relecture pédagogique.

## Rédaction spécialisée

| Auteur de la partie | Responsabilité | Périmètre de rédaction |
| --- | --- | --- |
| `architecture` | Architecte logiciel | Graphe, risque, NVD, moteur, phases, contextes, outils, profils, connaissances et ressources |
| `redacteur_reseaux` | Réseaux et infrastructure | Proxmox, topologies, segmentation, services IoT/OT, composition, cycle de laboratoire et CI |
| `redacteur_securite` | Sécurité et preuves | Modèle de confiance, attribution, critères protocolaires, accès, pivots et frontières |
| `redacteur_application` | Application et usages | Parcours opérateur, modes, fournisseurs, coordination, SSE, historique, comparaison et administration |
| `redacteur_modeles` | Modèles et apprentissage | QLoRA, données, masques, experts, entraînement, service, synchronisation et feedback |
| `avancement` | Benchmark et résultats | Corpus, métriques, politiques, parité, statistiques, historique, pilote, V2 et qualification SSH |

Codex a rédigé le contexte, la méthode et la synthèse, puis intégré les six
contributions. Le rapport final contient leur texte, leurs schémas et leurs
références dans une source unique. Les brouillons de travail ne constituent pas
des rapports de référence séparés.

## Relectures indépendantes de la version approfondie de 21:51

`relecture_globale`, distinct des auteurs, a lu toutes les contributions et
vérifié des sources primaires ciblées : risque dirigé, chemins, recherche CPE,
connaissances, événements, authentification, contrats et comparaison des
politiques. Il a contrôlé la couverture et les interfaces entre les volets.

Deux relecteurs ont inspecté toutes les pages rendues du rapport intégré :

- `relecture_finale` : pages **1–21**, puis réinspection complète de ces pages
  après correction des placements, sur la révision **21:49**.
- `relecture_globale` : pages **22–41**, puis réinspection complète après
  correction de la figure comparative, sur la révision **21:49**.
- Révision finale **21:51** : seules les pages **1 et 35–41** ont changé selon
  une comparaison textuelle page par page. Codex a revu la page 1 ;
  `relecture_globale` a inspecté visuellement les sept pages 35–41 et confirmé
  la disparition du mot isolé de la première référence.

Les pages 2–34 sont inchangées entre les deux dernières versions. Le verdict
final est **sans réserve de rendu restante** dans le périmètre inspecté.
Les flottants conservés à l'intérieur de leur section restent lisibles.

## Corrections apportées pendant l'intégration

- Harmonisation des fournisseurs autorisés et des définitions des sigles.
- Explication concrète du score de risque et de sa portée heuristique.
- Réduction des répétitions globales ; les renvois entre parties de cette version
  ont été remplacés par des explications locales lors de la relecture suivante.
- Distinction entre mode applicatif par règles et paire expérimentale D1/A1.
- Ordre du pilote décrit comme équilibré globalement, sans alternance stricte
  ni équilibre par situation.
- Marge d'amélioration statistique de 0,05 distinguée d'un niveau de test.
- Vue d'ensemble reliant les volets et contrôle des flèches des huit figures.
- Figures d'introduction, de réseau et d'application maintenues avant les
  sections qu'elles introduisent ; tableau des familles réseau replacé.
- Espacement corrigé des boîtes de comparaison D1/A1 ; style du cycle QLoRA harmonisé.
- Entrées bibliographiques rendues indivisibles et première référence raccourcie.

## Relecture pédagogique et autonomie des parties

Deux nouveaux relecteurs, distincts des rédacteurs spécialisés, ont recherché
les notions insuffisamment expliquées et les dépendances entre chapitres.
Les corrections portent notamment sur :

- Le sens d'un run, d'un agent, d'une politique, d'un contrat et d'un graphe orienté.
- ARP, Nmap, les profils d'exécution et un exemple de boucle modèle–outil.
- Les composants du laboratoire, la composition topologie–pack–posture et les protocoles IoT.
- Un exemple distinguant résultat confirmé, négatif et indéterminé.
- Les variables de QLoRA, les fenêtres, les masques, les époques et les adaptateurs.
- Le dénominateur de couverture, un calcul historique de F1, le bootstrap par familles
  et la correction de Holm.
- Les unités du corpus V2 et les rôles de l'oracle, du canari et du témoin légitime SSH.

Les renvois explicites et les invitations implicites à consulter un autre
chapitre ont été retirés. Le contrôle du source compte **12 renvois**, tous vers
une figure ou un tableau de la même section, et **aucun renvoi interchapitre**.
Le sommaire et les citations des sources restent accessibles.

Les deux agents ont inspecté visuellement la révision 22:37, puis les pages
corrigées et leur environnement dans la révision 22:39 :

- `lecture_autonome` : pages 1–24, toutes réinspectées à 22:39 ; compréhension
  autonome des sections 1–6 validée, colonnes des tableaux 4 et 5 corrigées,
  aucune réserve de composition restante. Le dernier ajustement du libellé
  du schéma d'infrastructure est contrôlé par Codex à 22:41.
- `explications_modeles_benchmark` : pages 25–44, toutes réinspectées à 22:39 ;
  ponctuation de la formule et justification des tableaux 7 et 8 corrigées,
  aucune réserve restante.

La révision 22:41 ne modifie que les pages **1 et 13**, selon une
comparaison textuelle page par page avec le PDF 22:39. Codex a inspecté ces deux
pages : date actualisée et flèche de commande Proxmox libellée « API ».
La pagination des sections est conservée.
Les 44 pages sont couvertes par les relectures finales, sans réserve restante
de compréhension ou de rendu dans le périmètre vérifié.

## Dernière relecture : découvrir le projet sans contexte préalable

Deux relecteurs supplémentaires ont lu le corps complet du rapport avant de
formuler leurs remarques. `premiere_lecture_projet` n'a utilisé que le rapport
pour reconstituer les objectifs, le fonctionnement et l'avancement.
`relecture_etat_projet` a vérifié la cohérence des statuts entre résumé,
bilans spécialisés, synthèse et conclusion. Leurs remarques ont conduit à des
corrections ciblées :

- Rôle de LANCE, d'IoTChainBench et de la chaîne d'entraînement explicité dans l'introduction.
- Parcours complet décrit depuis les choix de l'opérateur jusqu'aux fichiers consultables.
- Réseau existant, découverte, scénario personnalisé, mode aveugle et boucle simple distingués.
- Différence entre vérification de phase 4 et évaluation des accès de phase 5 illustrée avec SSH.
- Contenu de `06_report.md` précisé : les tableaux de déclarations soutenues sont
  sélectionnés, tandis que les fiches conservent toutes les hypothèses et leurs états.
- Résumé explicite sur les scores et diagnostics historiques, les comparaisons à
  achever et l'absence de gain LLM ou de spécialisation établi par ce bilan.
- « Service multi-adaptateurs » distingué des poids dont la disponibilité locale
  n'est pas attestée dans le tableau transversal.

Les deux lecteurs confirment la levée des ambiguïtés sans autre ajout nécessaire.
Les précisions ont été confrontées aux contrats documentaires et aux chemins de
code concernés, notamment l'assemblage des fiches et les entrées du pipeline.

Inspection visuelle du PDF :

- `premiere_lecture_projet` : toutes les pages **1–24** de la révision **22:51**,
  sans défaut constaté.
- `relecture_etat_projet` : toutes les pages **25–45** de **22:51** ; seule réserve,
  une dernière entrée du glossaire isolée en page 45.
- Révision **22:53** : trois définitions du glossaire raccourcies sans perte de
  leur réserve, glossaire entier en page **44**. La comparaison textuelle avec
  22:51 confirme que seules les pages **1 et 44** changent, et que l'ancienne
  page 45 disparaît. `relecture_etat_projet` et Codex ont inspecté les pages 1 et 44.

Les **44 pages finales** sont couvertes par ces inspections. Aucun renvoi
interchapitre n'a été ajouté. Aucune réserve de compréhension ou de rendu
ne subsiste dans le périmètre vérifié.

## Vérifications documentaires et techniques

- Compilation réussie dans l'éditeur LaTeX intégré et export par `latexmk -pdf`.
- Sommaire automatique et destinations vérifiés : sections 1–11 aux pages
  **4, 6, 7, 12, 17, 21, 25, 30, 36, 37, 38** ; glossaire à la page **44**.
- Huit figures et dix tableaux inspectés visuellement ; glossaire intégral et lisible.
- 136 clés de citation résolues, sans doublon de clé ni référence indéfinie.
- 138 liens PDF relatifs contrôlés vers des fichiers locaux existants. Ces liens
  supposent de conserver l'arborescence du dépôt avec le PDF.
- 187 fichiers sources identifiés par empreinte dans `sources-locales.json`.
- Recomptages : catalogue 3.2.0, 29 scénarios (19 développement et 10 test),
  22 définitions de packs ; pilote de 12 paires et 24 bras, zéro chemin de run
  renseigné, 24 précontrôles `pending`, six ordres D1/A1 et six A1/D1.
- Journal final sans boîte débordante ni renvoi indéfini. Le moteur local
  signale une césure française non préchargée et quelques boîtes peu remplies ;
  les inspections n'ont pas révélé de défaut de lisibilité correspondant.
- `git diff --check`, liens Markdown, espaces de fin de ligne et cohérence des
  dates, des sources et de l'empreinte du PDF contrôlés.

## Limites de la validation

Cette révision est documentaire. Aucun nouveau scénario, accès distant,
déploiement, entraînement, appel de modèle ni test applicatif n'a été exécuté.
Les résultats de laboratoire, volumes de corpus et pertes d'entraînement sont
attribués à leurs comptes rendus historiques ; les traces distantes et artefacts
GPU ne sont pas certifiés à nouveau. Les validations logicielles citées gardent
leur périmètre et leur date. Les empreintes identifient la copie locale sans
constituer une attestation de provenance distante.
