# Guide du dépôt

## Vue d'ensemble

LANCE est un outil d'audit de sécurité de réseaux IoT autorisés, piloté par des
modèles de langage. Son pipeline explore le réseau, analyse les failles potentielles,
vérifie les preuves, évalue les accès obtenus et produit un rapport.
Une API et une interface web permettent de lancer et de suivre les exécutions.
Le benchmark fournit des scénarios reproductibles pour comparer les résultats ;
l'entraînement des modèles constitue un volet distinct du projet.

## Organisation

- `src/agent/` : pipeline et outils d'audit.
- `src/api/` et `src/static/` : API et interface web.
- `src/benchmark/` : évaluation des résultats.
- `benchmarks/` : scénarios et infrastructure du laboratoire.
- `model_training/` : entraînement des modèles.
- `tests/` : tests de l'application ; l'entraînement possède ses propres tests.
- `research/` : recherches par sujet, sources, hypothèses, protocoles proposés et analyses.
- `docs/` : documentation de référence, organisée par architecture, guides, benchmark et entraînement.
- `objectifs/` : ligne directrice du projet ; ne recopie ni étude ni résultat.
- `presentations/` : supports de communication datés, sans autorité sur les pages de référence.

## Recherche et documentation

- Avant de créer un document, consulter les index de `research/` et `docs/` et
  compléter le sujet existant lorsqu'il couvre déjà la question.
- Placer tout travail dans `research/AAAA-MM-JJ-<sujet>/`, avec la date du jour
  de création et un nom descriptif en minuscules et tirets. Chaque dossier possède
  un `README.md` indiquant la question, le statut, les dates, la synthèse, les
  documents et les points encore ouverts.
  Suivre les [conventions de recherche](research/README.md).
- **Un dossier par révision.** Toute mise à jour de fond ou tout travail
  nouveau ouvre un dossier daté distinct : `research/AAAA-MM-JJ-<sujet>/`. Un
  dossier publié n'est plus modifié ; il devient l'archive de son état et la
  révision suivante le référence comme travaux antérieurs. La chronologie se
  lit dans l'index, pas dans l'historique Git.
- **Statut fermé.** Tout dossier prend un statut parmi `proposition`, `actif`,
  `dormant`, `conclu`, `remplacé`, avec sa date de revue et une ligne de
  format fixe dans l'index `research/README.md`. Un dossier remplacé le
  déclare en tête et pointe son successeur ; il n'est ni supprimé ni réactivé
  sans le dater.
- **Pas de recopie de statut.** Un fait de statut (V0, hypothèse mesurée,
  chiffre de couverture) a une seule page source ; les index, `objectifs/` et
  `docs/` le citent sans le réécrire. Un chiffre dérivé d'un artefact généré
  se cite avec sa définition et se recalcule, il ne se rédige pas.
- **`objectifs/` ne porte que la ligne directrice** : cible, priorités,
  critères de décision. Une analyse de corpus, un bilan de résultats ou un
  journal d'exécution reste dans `research/`. `docs/` ne décrit que le
  comportement courant de l'application ; une synthèse d'état datée y est
  citée comme « état au AAAA-MM-JJ », jamais comme contrat.
- Pour toute nouvelle étude ou révision de fond, fournir une source LaTeX éditable
  et son PDF compilé, avec des figures modifiables et un rendu vérifié. Adopter une
  structure scientifique classique : titre, résumé, table des matières, méthode,
  constats, limites, conclusion et références. Indiquer la date et l'heure de
  dernière révision du rapport avec le fuseau horaire, également dans son README.
  Suivre les
  [règles de structure et de format](research/README.md#structure-scientifique-classique).
- Distinguer les hypothèses, les faits sourcés, les résultats observés et les
  conclusions. Citer les sources primaires avec leur date/version et préciser les
  limites de lecture ou de reproduction. Pour une expérience, référencer le code,
  la configuration, les artefacts et les conditions nécessaires à sa reproduction.
- **Langue.** Les rapports d'avancement et de bilan de `research/` sont rédigés
  en anglais ; les notes de travail, les README de dossier et la `docs/` de
  référence restent en français. Une traduction archive l'original, elle ne
  l'écrase pas.
- Réserver `docs/` aux comportements implémentés, aux contrats retenus et aux
  procédures de référence, en précisant leur périmètre et leurs limites. Un plan
  proposé ou une piste bibliographique reste dans `research/`.
- Quand une conclusion est retenue et vérifiée au niveau nécessaire, mettre à jour
  la page de référence concernée et la relier à la recherche d'origine. Conserver
  les sources et le raisonnement dans `research/`, sans recopier toute l'étude.
  Une validation logicielle ne prouve pas un résultat expérimental.
- Mettre à jour les index et les liens lors de tout ajout ou déplacement. Garder
  une seule page de référence par sujet ; marquer les documents remplacés comme
  archivés et les relier à leur successeur. `docs/audit/` conserve les archives
  historiques existantes, qui ne décrivent pas nécessairement le système courant.

## Méthode de travail

**Cycle d'une révision.** Ouvrir un dossier daté en `proposition` → le passer à
`actif` au premier travail réel → clore (`conclu`, y compris par un résultat
négatif) ou passer en `dormant`. Une révision ultérieure ouvre un **nouveau**
dossier daté qui cite le précédent ; elle ne modifie pas l'ancien. Une
conclusion devenue stable migre vers `docs/` ; `research/` garde les sources,
le raisonnement et les limites.

**Ordre de mise à jour d'un résultat.** Toujours dans cet ordre : (1) la
source — protocole ou README du dossier daté ; (2) la ligne de l'index
`research/README.md` ; (3) le tableau « État vérifié » de
`objectifs/ETAT-COURANT.md` ; (4) la ligne directrice, seulement si une
décision change. S'arrêter à l'étape 1 fait mentir l'index ; sauter à l'étape 3
produit une recopie.

**Fin de session.** Un commit par sujet. Travailler sur `dev/1` : un push
déclenche le circuit de validation et met à jour l'instance du mini-PC sur le
port 8502. Un push sur `main` valide et déploie l'instance 8501 ; ne pas y
pousser un travail en cours.

**Chaque semaine.** Repérer les dossiers `actif` sans revue et les passer en
`dormant` ; confronter les index aux dossiers réels.

## Contribuer

Comprendre le module concerné et sa documentation avant de le modifier. Préserver
les changements locaux, respecter les responsabilités existantes et privilégier
des corrections générales, ciblées et testables. Mettre à jour les tests et les
guides concernés, sans dupliquer leur contenu ici.

Valider les changements avec les tests pertinents ; la suite complète se lance avec
`python -m pytest -q tests model_training/tests`, ou avec des workers pour gagner
du temps (`-p xdist -n 4`). Vérifier aussi `git diff --check`
et, pour l'interface, le rendu dans un navigateur. Indiquer ce qui a été vérifié
et les limites restantes. Les runs de laboratoire, déploiements, commits et pushes
nécessaires à la tâche demandée peuvent être effectués sans nouvelle confirmation,
dans le périmètre défini ci-dessous.

## Cible d'exécution et de déploiement

**Le mini-PC est la seule machine d'exécution.** Rien ne tourne sur un poste de
développement : ni pipeline, ni harnais, ni modèle, ni run de laboratoire. Un
travail local se limite à lire, modifier, tester les unités hors ligne
(`python -m pytest`) et committer.

- L'exécution et les déploiements LANCE ciblent **nato / pve-nato**, via le
  runner GitHub Actions **nato-master**. Son adresse Tailscale se lit sur la
  machine (`tailscale ip -4`) : elle change quand le conteneur est reconstruit,
  et aucun guide ni script ne doit en figer une. Le homelab personnel (nœud
  `pve`, distinct de `pve-nato`) reste hors périmètre ; une intervention y
  exige une demande distincte.
- **Circuit de livraison :** commit → push → GitHub Actions valide → l'instance
  sur le mini-PC tire le commit. Aucune copie manuelle entre la machine de
  développement et le mini-PC. Un push sur `main` valide et déploie ; les
  branches de développement valident et mettent à jour leur propre instance.
- **Instances sur le mini-PC**, détaillées dans
  [les branches de développement](docs/guides/development-instances.md) :
  `main` sur le port 8501 (`/opt/nato-smartcity-iot`), `dev/1` sur le port 8502
  (`/opt/lance-dev-1`), `dev/2` sur le port 8503 (`/opt/lance-dev-2`).
  `/api/environment` renvoie l'emplacement, la branche et le commit déployés.
- **`dev/1` est la branche de travail** de ce dépôt. `dev/2` appartient à un
  autre intervenant : ne pas y pousser ni la réécrire.
- **Modèles disponibles sur le mini-PC** (provider UMONS) : `qwen3.8:27b` est
  le modèle de référence, aux côtés de `qwen3.5-27b-32k`,
  `gemma4:26b-a4b-it-q4_K_M` et `lance-moe`. `GET /api/models` sur le port de
  l'instance donne la liste à jour ; un modèle absent de cette réponse n'existe
  pas sur la machine qui exécute.
- Un inventaire local, un service qui écoute en local ou une connexion SSH
  fonctionnelle n'autorisent pas à changer de cible. Ne jamais se rabattre sur
  une autre machine si le mini-PC est inaccessible ; vérifier l'identité de la
  machine et clarifier toute ambiguïté avant intervention.

Pour commencer : [README](README.md), [recherches](research/README.md), [documentation](docs/README.md),
[structure du pipeline](src/agent/phases/README.md) et [tests](tests/README.md).
