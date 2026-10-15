# Tests automatisés de l’application

Ce dossier vérifie le pipeline, les outils, les preuves, les métriques du benchmark,
l’API et leurs intégrations. Les tests du code d’entraînement et de synchronisation
GPU sont regroupés dans [model_training/tests/](../model_training/tests/).

Ne pas confondre ces tests logiciels avec les
[scénarios d’évaluation du benchmark](../docs/benchmark/v1/scenarios.md).

`test_ssh_reference.py` qualifie le premier contrat SSH V2 avec le vrai exécuteur
et l'adaptateur SSH existants, mais des entrées/sorties de processus simulées :
contrôle protégé, lecture privée fraîche, identité/cible/session, erreurs,
manquants, budget dépassé par la dernière sonde et archives complètes avec
fichiers cachés. Le CLI d'évaluation est aussi exécuté sans connexion réseau.
Ces tests ne mesurent ni serveur SSH réel ni performance LLM ; le résultat reste
explicitement non admis pour une campagne M-T. Voir la
[référence SSH V2](../docs/benchmark/agent-vs-automation-cli.md#calibration-ssh-v2).

`test_ssh_reference_live.py` ajoute le dialogue multi-tours du vrai fournisseur
et son enregistreur avec un client simulé, les pertes d'archives, les compteurs
inconnus, les avis OpenSSH liés à la cible, le nettoyage par propriété, les
archives interrompues et le lancement manuel réservé à nato/dev-2. Ces tests ne
lancent ni Docker, ni serveur SSH, ni modèle réel.
`test_ssh_reference_proxmox.py` vérifie les frontières de la fixture LXC native :
identité de pve-nato avant transfert, refus d'une campagne active, allocation
sans collision, propriété avant destruction, récupération partielle et arrêt
avant allocation lorsque Qwen est indisponible. Les appels Proxmox sont simulés.
Un test supplémentaire utilise le binaire OpenSSH présent, sans configuration
existante ni ouverture de socket, pour vérifier le chemin absolu du programme
lancé ; il est ignoré si ce binaire n'est pas installé.
`test_ssh_reference_diagnostics.py` vérifie que l'inspection autorisée des
préparations en échec ne publie que quatre champs filtrés et exclut les valeurs
privées, y compris dans les erreurs et arguments de commandes.

`test_run_graph_context.py` vérifie les graphes distincts de deux runs,
les réinitialisations et mutations pondérées, les outils et prompts exécutés
dans des threads, la restauration après exception et les entrées des six phases
avec des contextes et services explicites. Les identifiants d'appareils peuvent
être identiques sans mélanger leurs adresses ou journaux. Les fixtures de graphe
des tests de reconnaissance appartiennent au run testé. Ces tests n'exécutent
ni laboratoire, ni réseau, ni modèle.

`test_archived_campaign_summary.py` vérifie la restitution hors ligne des
statuts, diagnostics Phase 3 dont `scanner_errors` (valeur enregistrée et
présence de la clé), scores manquants, avertissements et empreintes, ainsi que
la préservation des fichiers d'entrée. Les cas synthétiques sont autonomes ; le cas utilisant
les archives locales est ignoré lorsqu'elles sont absentes. Ces tests ne lancent
aucun scénario ni appel réseau.

Depuis la racine du dépôt :

```bash
# Toute la suite : application ET entraînement
python -m pytest -q

# Application uniquement
python -m pytest -q tests

# Entraînement uniquement
python -m pytest -q model_training/tests
```

La CI exécute explicitement les deux dossiers pour les changements de code et
les exécutions manuelles. Les changements uniquement documentaires connus
suivent un [parcours léger](../docs/guides/development-instances.md#validation-ci-selon-les-fichiers-modifiés).
Les commandes qui précisent
seulement `tests/` ne lancent pas les tests d’entraînement. Certaines dépendances
optionnelles peuvent provoquer des tests ignorés : lire le résumé avant de
conclure à une validation complète.

Pour limiter les répétitions, regrouper avec `pytest.mark.parametrize` les cas
qui partagent la même préparation et les mêmes assertions, en donnant un nom
explicite à chaque cas. Garder des tests séparés pour les comportements distincts,
et vérifier les résultats observables plutôt que reproduire l'implémentation.
Une fonction paramétrée exécute plusieurs cas indépendants : réduire le nombre
de fonctions ne signifie donc pas réduire le nombre de cas vérifiés.

`test_audit_policy.py` couvre la comparaison D1/A1 sur inventaire public avec
les vrais composants de pipeline et des outils/fournisseurs simulés : preuves,
budgets, contrôles sains, erreurs et refus des paires incompatibles. Ces tests
vérifient aussi les reprises D1 et le bilan de campagne : essais manquants,
coûts des échecs, précontrôles et identités incompatibles, exports JSON/CSV. Ils
ne mesurent pas les performances d'un modèle sur un laboratoire réel ; voir le
[guide de comparaison](../docs/benchmark/agent-vs-automation-cli.md).

`test_pipeline_evaluation.py`, `test_pipeline_summary_events.py` et
`test_pipeline_summary_ui.py` vérifient aussi que le scoring `not_applicable`
du mode par règles reste informatif, dans les métadonnées et le journal réel
de l'interface. Les erreurs d'évaluation applicables, les audits en échec et les
incidents de nettoyage restent visibles ; les anciens événements `rules` sont
compatibles. Ces tests ne lancent aucun audit réseau.

`test_tool_loader.py` vérifie aussi les sondes SSH sans test de débit et la
conservation des diagnostics de connexion. `test_rules_ssh_observations.py`
distingue les résultats de configuration retournés par `ssh-audit` (codes 2/3)
des échecs sans observation ; les tests de preuve SSH restent responsables
des confirmations. Tous ces appels d'outils sont simulés.
`test_scanner_ssh_retry.py` couvre la reprise unique après un timeout de connexion
SSH, conditionnée à l'observation du même port TCP ouvert, la conservation des
tentatives, les ports personnalisés et les échecs qui restent incomplets.
`test_preflight_ansible_runtime.py` exécute aussi le contrôle SSH du routeur
avec le vrai module Ansible et des sockets locales de test : bannière valide,
connexion transitoire, mauvais protocole et port fermé. Le faux hôte Proxmox
reste injoignable pour vérifier que la sonde utilise bien le contrôleur d'audit.
Une commande `ip` simulée vérifie le renouvellement de la seule entrée ARP du
routeur et le blocage avant sonde si cette commande échoue.

`test_lab_lock.py` vérifie la réservation du laboratoire entre processus et son
annulation sans opération réseau. `test_deployment_workflow.py` vérifie les
déploiements par branche dans des dépôts temporaires ; voir le
[guide des instances](../docs/guides/development-instances.md).
`test_ci_scope.py` vérifie le classement des fichiers et de vrais intervalles Git
(pushs multiples, fusion de PR, suppressions, renommages et historique peu profond),
le repli vers tous les contrôles en cas d'incertitude et les conditions des workflows.

`test_shared_activity.py` couvre les résumés locaux, l’agrégation en lecture
seule des trois instances, les erreurs de pairs, l’absence de transmission
d’identifiants et le mode standalone sans accès réseau.

`test_knowledge_policy_isolation.py` vérifie que la source CVE reste liée au run
quel que soit l'ordre de création des pipelines, que les filtres de connaissances
restent distincts dans les threads et que le snapshot fonctionne sans importer
la base de connaissances en ligne. `test_agent_tools.py` vérifie aussi qu'un
scénario invalide ne se rabat jamais sur le laboratoire physique.

`pipeline/test_analysis_context.py` vérifie les frontières de phase 3 : fournisseur
effectif, dry-run sans découverte active, agrégation seule, comptage avec des
workers terminant dans un ordre différent, interruptions propagées, suivi fermé,
consommation limitée à la phase et deux contextes ayant les mêmes identifiants
d'appareil. Les tests de frontière et de statut fournissent une surface simulée
pour éviter le chargement implicite du laboratoire et les recherches NVD.
`pipeline/test_analysis_supplemental.py`, issu de la relecture
indépendante, caractérise l'ordre des sondes mTLS/OTA/cloud et leur provenance,
avec des outils simulés. Les tests de sauvegarde, récupération et agrégation
conservent les contrôles de preuves ; le test UMONS mesure les appels simultanés
sans réduire les preuves ni le délai. Aucun de ces tests ne mesure un modèle
sur le laboratoire réel.

`pipeline/test_aggregation_stages.py` vérifie l'agrégation avec un contexte
explicite, les preuves chargées avant la projection, la provenance MQTT et les
identifiants repris d'un membre du groupe. Les tests existants d'agrégation,
de sémantique, de planification et de reprise restent applicables aux adaptateurs.

`test_service_proof_binding.py` vérifie l'attribution des preuves aux destinations
réellement exécutées et les échanges bornés SNMP/CoAP/S7/ENIP, avec des réponses
protocolées et des contrôles négatifs. `test_credential_execution_boundary.py`
vérifie que les identifiants restent des données littérales dans les programmes
locaux, avec des substituts de netcat sans réseau. `test_intrusion_access_consistency.py`
compare les accès admis par l'outil, le livrable compact et la projection commune.

`pipeline/test_discovery_followup_boundary.py` couvre les reprises de découverte :
CIDR, arrêt, budget, journal brut, provenance et fermeture du suivi de coût.
`pipeline/test_analysis_malformed_fields.py` vérifie le refus des champs mal typés
et leur conservation sans perte des candidats valides. `pipeline/test_scanner_http_origin.py`
vérifie les origines HTTP(S) depuis le scan jusqu'au ciblage de la phase 4. Ces
tests utilisent des outils simulés et ne lancent pas de scénario de laboratoire.

`pipeline/test_pki_identity_evidence.py` vérifie les empreintes PKI communes à
deux appareils distincts, les doublons de requêtes et de topologie, les alias,
les réponses HTTP en erreur ou attribuées à une autre destination, ainsi que
les entrées malformées voisines de preuves valides. Les fichiers de scan sont
synthétiques ; aucune requête réseau n'est exécutée.

`test_pipeline_stream.py` vérifie le suivi d'un même run par deux lecteurs,
les reconnexions par curseur, la fin d'un run pendant une coupure, le nettoyage
manuel, l'expiration de l'historique et l'indépendance des opérations. Il exerce
la route SSE via le client HTTP de test et le code JavaScript du dashboard avec
Node.js, sans modèle ni laboratoire. Le contrat du suivi partagé est décrit
dans le [guide des instances](../docs/guides/development-instances.md#plusieurs-lecteurs-dun-même-run).

`test_scenario_rules_audit.py` vérifie les audits applicatifs par règles : contrat
API sans modèle, déploiement avant les sondes, preuves par équipement, métriques
sans appel LLM et exclusion des comparaisons benchmark. Les playbooks et sondes
sont simulés ; aucun audit réel n'est lancé. `test_rules_audit_ui.py` exerce le
JavaScript du dashboard avec Node.js pour le choix du mode, les requêtes sans
modèle, le graphe et les diagnostics, sans serveur ni accès réseau.
Les régressions NVR vérifient aussi le choix borné des identifiants SSH indiqués
dans le constat, la destination et le port, puis les preuves et erreurs de la
vraie phase 4 avec une sonde simulée. La projection conserve les erreurs par
équipement sans dégrader une confirmation après reprise ; les tests d'interface
contrôlent le nœud, le tableau, la fiche, l'échappement des diagnostics et la
distinction entre erreur, résultat négatif et vérification en attente.
