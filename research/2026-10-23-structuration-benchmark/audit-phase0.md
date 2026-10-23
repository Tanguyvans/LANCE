# IoTChainBench — audit préalable à la restructuration (phase 0)

> Document source de [la structuration du benchmark](README.md), classé le
> 2026-10-23. Rédigé sous `docs/benchmark/audit-restructuration-phase0.md`
> et jamais commité à cet emplacement ; contenu inchangé hormis les liens
> relatifs. Il décrit le commit `2532980` de `main`, pas un état ultérieur.

**Statut : audit statique, en attente de validation ; aucune phase suivante engagée.**

Dernière révision : 2026-10-23 14:24:39 CEST (Europe/Brussels, UTC+0200).
Base auditée : commit
`2532980eaea9145db823366a199e445f935e851d`, branche locale **main**,
arbre initial propre. La branche annoncée dans la demande est « dev2 » ; les
workflows utilisent **dev/2**. Cet audit porte uniquement sur ce checkout :
il ne certifie ni une autre branche, ni l'état de nato. Aucune connexion à
l'infrastructure, aucun playbook, aucun run de scénario, aucun commit/push.

[Documentation](../../docs/README.md) · [Référence scénarios](../../docs/benchmark/v1/scenarios.md) ·
[Catalogue des attaques](../../docs/benchmark/catalogue-attaques.md) ·
[Recherche déjà existante sur la structuration](../../research/2026-10-12-recentrage-corpus/README.md)

## 1. Méthode et constats principaux

Lecture des index `docs/README.md` et `research/README.md`, du guide pipeline,
des tests, du catalogue, des 31 définitions publiques (29 officielles et S1h/S4h),
des topologies, packs, composants de chargement/évaluation, playbooks et 15
workflows. Comparaison YAML locale des 29 topologies et inventaires Ansible.
Les commandes de validation et leurs limites figurent en section 8.

Il s'agit de documenter le comportement existant, pas de proposer une nouvelle
étude ni d'appliquer le plan V2 existant. Le livrable est uniquement ce Markdown,
conformément à la demande explicite : aucun ajout LaTeX/PDF, aucune modification
d'index, de code, de contrat ou de scénario pendant cette phase.

Constats déterminants :

- Le catalogue impose des **identifiants numériques positifs** et trois splits
  nommés ; un identifiant technologique textuel ne serait pas une substitution
  transparente. Une catégorie n'est pas un champ actuellement autorisé du catalogue.
- Deux représentations indépendantes du déploiement existent : topologies publiques
  et inventaire Ansible. Elles concordent sur les champs comparés, sauf le rôle
  LDAP de S13 (section 5).
- Le verrou est global, coopératif et optionnel. Des VMID disjoints ne permettent
  pas d'exécuter les scénarios historiques simultanément sur le réseau partagé.
- Le pipeline peut supprimer des scénarios existants avant le déploiement demandé.
  Le teardown utilise une plage entière et tolère les erreurs des destructions.
- Les chaînes déclarées ne sont pas des preuves de pivots. Le score conserve
  explicitement les métriques de provenance réseau indisponibles.
- `compose_gt.py --validate` réussit malgré des divergences legacy importantes,
  qui ne se limitent pas aux descriptions.

## 2. Chargement et exécution de bout en bout

### 2.1 CLI, catalogue, résolution

| Étape | Fichier et fonctions | Contrat constaté |
| --- | --- | --- |
| CLI | `src/agent/__main__.py:main` | `--scenario` ou `--batch`, exclusifs ; résolution du split avant construction du fournisseur ; transmet scénario, split, profil, blind et dry-run à `Pipeline`. |
| Sélection | `src/agent/batch.py:_parse_single_scenario_id`, `_parse_scenario_ids`, `_available_scenarios` | Sélecteurs dev/test/public/all ; catalogue pour les officiels, variantes historiques par GT, exports et scénarios manuels distincts. `all` peut inclure S1h/S4h. |
| Catalogue | `src/benchmark/catalog.py:load_catalog`, `BenchmarkCatalog.get`, `resolve_selector` | `benchmarks/catalog.yaml`, schéma `1`, version benchmark `3.2.0` ; clés exactes, ids numériques canoniques, tri numérique, splits `dev-public`, `test-public`, `eval-sealed`. Le corpus courant est entièrement public. |
| Chemins officiels | `catalog.py:public_scenario_split`, `public_asset_path` | S1h/S4h héritent du split du parent ; `scenarios/{dev,test}/S{sid}.yaml` et `ground_truth/{dev,test}/scenario_{sid}.yaml`. Les dossiers dépendent du catalogue, pas d'un seuil numérique dans ce helper. |
| Chemins effectifs | `src/benchmark/scenario_exports.py:resolve_scenario_split`, `resolve_scenario_path`, `resolve_topology_path`, `resolve_ground_truth_path` | Priorité aux exports validés, puis artefacts manuels, puis assets publics. Les topologies officielles sont `benchmarks/topologies/{topology}.yaml`. Les exports ne déplacent pas les scénarios officiels. |

Attention : `BenchmarkCatalog.get` retire `S` majuscule ; d'autres entrées
normalisent aussi `s`. `resolve_selector` passe sa chaîne en minuscules ; ne pas
supposer une normalisation uniforme de tous les appels internes.

### 2.2 Pipeline et vue de l'agent

`src/agent/pipeline.py:Pipeline.__init__` vérifie le split, prépare un dossier de
run et son contexte propre. `Pipeline.run`, décoré par `serialized_lab` et
`graph_bound`, encadre l'exécution **et** son nettoyage. `_execute_run` charge la
politique d'outils et les limites par les méthodes de
`src/agent/core/lifecycle.py:ScenarioLifecycle`, puis la topologie publique via
`src/agent/tools/graph_tools.py:load_scenario_topology`.

Ce dernier lit le scénario et sa topologie, construit les nœuds depuis les
services, leur rôle et la table `src/benchmark/tool_registry.py:ROLE_SERVICES`.
Il ne lit pas la GT. Un scénario ou une topologie manquant échoue explicitement ;
il n'y a pas de repli vers le laboratoire physique pour ce cas. Les arêtes de
connectivité ne sont pas les `attack_paths` de la GT.

En mode informé, `ScenarioLifecycle._load_scenario_context` fabrique un briefing
public ; en mode blind, la découverte est nécessaire et le briefing topologique
est masqué. Limite de texte constatée : le briefing informé inclut des consignes
« VLAN IPs » et exclusion du réseau de management même pour des topologies plates ;
il faudra les relire avant une généralisation. `scenario_meta.json` conserve
l'identité et le contexte d'évaluation.

Le pipeline exécute les six phases selon le profil/sélection : graphe,
reconnaissance, analyse/filtrage, vérification, intrusion, rapport. Les modes
`rules` applicatifs et les expériences analyse/vérification ont leurs propres
périmètres. Un audit applicatif par règles n'est pas automatiquement un score
benchmark. Le dry-run ne déclenche pas le déploiement normal ; aucun dry-run
n'a été nécessaire pour cet audit.

### 2.3 Déploiement Ansible

`ScenarioLifecycle._run_scenario_deploy` prépare éventuellement un overlay
(export/manuel), appelle `_teardown_all_running_scenarios`, puis :

1. `benchmarks/ansible/playbooks/03_deploy_scenario.yml` : allocations depuis
   `benchmark_scenario_vmid_ranges`, services depuis `benchmark_scenarios`,
   vérification des propriétaires existants, clone routeur OpenWrt et CT Debian,
   interfaces et connectivité. Traitements spécifiques S13 et multi-hop.
2. `04_inject_vulns.yml` : injection **par rôles, profils et conditions sur
   `source_scenario_id`** ; scripts spécialisés et simulateurs. Ce playbook ne
   compose pas les packs YAML pour en dériver automatiquement l'injection.
3. `06_verify.yml` : vérifications de préparation, également spécialisées. Le
   pipeline enregistre `preflight-v1` et
   `all_ground_truth_properties_verified: false`, même en cas de succès.

`_run_playbook` utilise l'inventaire du dépôt, le fichier de vault
`/root/.vault_pass`, `scenario_id`, `source_scenario_id` et, si nécessaire, un
fichier d'overlay ; délai configurable `ANSIBLE_PLAYBOOK_TIMEOUT` (1800 s par
défaut), logs par playbook conservés dans le run. Un échec deploy/inject/verify
interrompt et tente le teardown.

Les variables fusionnées de `group_vars/all/scenarios_v2.yml` combinent
`main.yml:scenarios/scenario_vmid_ranges` (S1–S13) et
`scenarios_v2/scenario_vmid_ranges_v2` (S14–S29). Les noms déployés par défaut
sont `s{scenario_id}-{service.name}` ; le public rend `name_template`.

**Autre chemin :** `benchmarks/ansible/deploy.sh` n'accepte que 1–7 ; il lance
03, 04 puis 05 (peuplement optionnel, échec non bloquant), **pas 06**. Aucun
`flock` n'est présent dans ce script ou les playbooks 03/04/06/99. Les appels
directs doivent donc participer au protocole de réservation extérieur.
`08_reset_scenario.yml` réinjecte et repeuple des machines existantes ; ce n'est
pas un redéploiement neuf garanti.

### 2.4 Composition de GT, preuves et évaluateur

`benchmarks/tools/compose_gt.py:compose_scenario` lit scénario → topologie →
packs, sélectionne les entrées sous la clé de rôle du pack puis applique
`_matches_selector`. Les restrictions legacy `scenarios` sont un filtre
supplémentaire ; `applies_to.roles/profiles/devices` combine les dimensions par
AND et les éléments d'une dimension par OR. Le profil absent vaut `vulnerable`.
`_stable_id` retourne `key@slug(device)` si `key` existe, sinon `Vn`/`Cn` selon
l'ordre de composition. Les doublons sont refusés. La présence de `key` est une
convention documentée pour les nouveaux packs, **pas une obligation universelle
imposée au chargement**.

Le composeur matérialise failles et contrôles, calcule les poids, rend les VMID,
et **recopie** `attack_paths` ; il ne démontre ni ne résout leurs dépendances.
`posture` du scénario n'est pas un filtre générique de ce composeur : les packs
choisis et les profils des services sont déterminants. `schema_version >= 2`
active les contrôles et la validation stricte de l'égalité avec la GT existante.

Les preuves de phase 4 passent notamment par
`src/agent/exploit_evidence.py:synthesize_exploit_result`,
`has_positive_exploit_evidence` et les validateurs propres au protocole/cible.
`src/agent/report_evidence.py:is_verified_report_finding` exige `CONFIRMED` et
un niveau de preuve ≥ 2 ; `verification_state` ne transforme pas un échec en
preuve générale d'absence. Toute nouvelle propriété devra donc conserver une
chaîne de preuve par outil, cible, opération et résultat, jusque dans le rapport
et l'évaluateur. Aucun nouveau type de propriété n'est introduit ici.

Le CLI de scénario seul termine par les résultats du pipeline ; le scoring
n'est pas une étape implicite de `Pipeline.run`. Le batch
`src/agent/batch.py:run_batch` résout la GT puis appelle
`src/benchmark/evaluator.py:evaluate`. L'API fait de même dans
`src/api/routes/pipeline.py:_evaluate_single_run` (ou renvoie `not_applicable`
pour l'audit applicatif rules). Les lectures/recalculs de runs utilisent
`src/api/routes/runs.py:_evaluate_cached` et ses routes d'évaluation.
L'évaluateur autonome prend `--run-dir` et `--ground-truth`.

`evaluate` charge GT, livrables et journal des appels outils, applique
`_strict_v3_match`/`_match_predictions`, lie les preuves et sépare détection,
confirmation, contrôles et intrusion. `src/benchmark/strict_v3.py:matching_contract_path`
remonte d'un niveau uniquement pour les dossiers nommés `dev`/`test` avec
`scenario_*.yaml` : introduire des sous-dossiers technologiques affecterait ce
contrat. `benchmarks/ground_truth/matching_contracts.yaml` contient les contrats
par id et les empreintes des GT ; un contrat absent/périmé est refusé dans les
conditions vérifiées par `evaluate`.

Versions distinctes à préserver : `strict-v3.16` et `evidence-v16` dans
`src/benchmark/metric_contract.py`, schéma de sidecar `strict-v3.2` dans
l'évaluateur. Aucune de ces versions n'est modifiée ici. Une évolution des règles
de crédit ou de preuve devra être signalée et accompagnée d'une proposition de
bump avant implémentation.

`_compute_phase5_metrics` laisse `phase5_pivot_attempts/successes/success_rate`
à `None` : l'exécuteur ne produit pas de provenance causale des transitions
réseau. Une suite d'accès directs ne prouve pas une chaîne de pivots. S28 modélise
une chaîne de dépendances sur réseau plat ; son titre ne constitue pas une
segmentation. Les dépendances credential/jeton devront être distinguées des
sauts réseau lors d'une éventuelle restructuration, sans crédit implicite nouveau.

## 3. Dépendances aux identifiants, splits et dossiers

Le registre ci-dessous distingue les dépendances opérationnelles des références
historiques. Les numéros de ligne de l'annexe sont des repères dans le commit
indiqué ; les symboles et fichiers priment après modification.

| Surface | Endroits et dépendance |
| --- | --- |
| Identité officielle | `benchmarks/catalog.yaml` : 29 ids, labels, splits. `catalog.py` impose id numérique, préfixe S, suffixes historiques et profils scellés `eval_profiles/S{id}.yaml`. |
| Définitions publiques | Les 31 fichiers `benchmarks/scenarios/{dev,test}/S*.yaml` : id, topologie, packs et chemins/nom des appareils ; les 31 GT `ground_truth/{dev,test}/scenario_*.yaml` : ids de scénario/failles/chemins/appareils. Les déplacer affecte les lecteurs et empreintes. |
| Restrictions packs | `benchmarks/packs/definitions/f1_weak_auth.yaml`, `f2_misconfig.yaml`, `f3_data_exposure.yaml`, `f5_injection.yaml`, `f6_crypto.yaml`, `f7_postexploit.yaml`, `f8_info_disclosure.yaml`, `f9_insecure_update.yaml` : listes `scenarios`, et selon les packs références aux appareils/prérequis. Les nouveaux packs utilisent aussi des sélecteurs de profil/appareil et des clés stables. |
| Topologies | `benchmarks/topologies/*.yaml` : noms `{sid}`, base VMID, rôles, profils, adresses et arêtes. Même une topologie réutilisable garde ici une base VMID associée à son scénario historique. |
| Inventaires déploiement | `main.yml`, `scenarios_v2.yml`, playbooks 03/04/05/06/08/99 : tables par id, plages, noms attendus, conditions `source_scenario_id`, scénarios particuliers. Scripts `configure_s14_control.sh`, `configure_s20_pivot.sh`, `configure_s21_sparse.sh`, `configure_heldout_pivot.sh`, `generate_s16_pki.sh`, `benchmark_simulator.py` : noms, tokens/fixtures, paramètres ou chemins historiques. `deploy.sh` borne les ids à 1–7 ; `verify.sh` transmet un id libre malgré son aide 1–7. |
| Génération hors ligne | `benchmarks/tools/compose_gt.py`, `extract_topologies.py`, `extract_packs.py` : noms de fichiers, tables historiques id→topologie, parcours récursifs ; les extracteurs écrivent à leur exécution et ne sont pas exécutés ici. |
| Chargement agent | `__main__.py`, `batch.py`, `pipeline.py`, `core/lifecycle.py`, `core/runtime.py`, `tools/graph_tools.py` : sélection, split, résolution, briefing, métadonnées, pré-teardown. |
| Scenario Lab | `scenario_generator.py:BLUEPRINT_ALIASES` : alias/blueprints et sources historiques ; `scenario_exports.py`, `scenario_deployment.py` : id source, regex exports/manuels, overlays et leases. `manual_execution.py:PROFILE_DEFINITIONS` s'appuie sur les sources **14, 20, 15** pour les profils exécutables. `scenario_builder.py`, `scenario_composer.py` et `scenario_spec.py` constituent un autre chemin de composition. |
| Évaluation et dérivés | `strict_v3.py`, `evaluator.py`, `derived_index.py`, `benchmarks/labels/derived_index.json`, `ground_truth/matching_contracts.yaml` : chemin partagé, entrées par scénario, hashes, parcours dev/test et ids. `aggregate.py`, `comparability.py`, `policy_campaign.py`, `policy_pair_runner.py` : métadonnées de split, comparaison et identité des essais. |
| API et interface | `src/api/routes/{scenarios,topology,pipeline,runs}.py`, `src/api/run_coordinator.py`, `src/static/{app.js,scenario_generator.js,index.html,comparisons.js}` : découverte du catalogue, parcours de fichiers, ids chaîne dans les requêtes, affichage S, masquage sealed et comparaison par split. **`routes/runs.py:856` et `contracts.py:_sealed_scenario_id` conservent une borne sealed 20–25 codée en dur.** |
| Apprentissage | `src/learning/error_mining.py:require_learning_scenario` refuse test/sealed et résout l'ascendance des exports ; `src/db/seed.py` recalcule depuis les GT résolues. Les imports du catalogue et les métadonnées de provenance doivent rester cohérents après migration. |
| Campagnes et CI | `.github/workflows/`, `scripts/benchmark/pilot_support.py`, manifestes `benchmarks/experiments/` : scénarios et chemins de GT des pilotes, restrictions manuelles. `.dockerignore` et `docker/worker.Dockerfile` protègent la frontière oracle du worker ; ce sont des dépendances à l'organisation des assets, pas seulement au split. |
| Tests | `tests/test_benchmark_catalog.py`, `test_benchmark_scenarios.py`, `test_benchmark_isolation.py`, `test_benchmark_contracts.py`, `test_batch_integration.py`, `test_scenario_{generator,deployment}.py`, tests API/UI, apprentissage, campagnes et pipeline : listes 1–29, 1–19/20–29, rôles, fichiers et versions attendues. Registre de repères en annexe. |

Les fichiers `docs/benchmark/v1/`, `catalogue-attaques.md`, `README.md`,
`benchmarks/README.md`, `benchmarks/ansible/README.md` et les index devront suivre
la nouvelle référence si elle est validée. `docs/audit/`, les recherches datées,
`benchmarks/results/`, journaux et archives de campagnes ne sont pas des tables
à renuméroter automatiquement : conserver leur identité historique et prévoir
une correspondance explicite. Leur existence n'autorise aucune migration ici.

## 4. Réservation, concurrence et teardown

`src/benchmark/lab_lock.py:reserve_lab` utilise `fcntl.flock(LOCK_EX|LOCK_NB)`
sur le fichier indiqué par `LANCE_LAB_LOCK`. C'est **un verrou global à l'inode**,
non un verrou par scénario. Sans variable, il ne verrouille rien. Tous les
processus doivent ouvrir le même fichier ; le remplacer/supprimer casse la
coordination. La réentrance est suivie par `threading.local`, pas par identité
de scénario. L'attente émet `lab_waiting`, vérifie l'arrêt et éventuellement une
deadline, puis émet `lab_acquired`. Le décorateur du pipeline ne transmet pas
de deadline de réservation par défaut. Il garde le verrou jusqu'à la sortie du
`finally`, y compris le teardown. Une mort de processus libère le verrou OS mais
ne garantit pas le nettoyage des machines.

L'API ajoute un coordinateur local (`src/api/run_coordinator.py`) et réserve aussi
le laboratoire pour le teardown manuel (`routes/pipeline.py:teardown_scenario`).
Le déploiement applicatif utilise le même `/var/lib/lance/lab.lock` dans
`scripts/deployment/deploy-instance.sh`. Les groupes de concurrence GitHub
(`deploy-nato-master`, `lance-lab-dev2` ou ceux des pilotes) ne remplacent pas ce
verrou partagé. L'effectivité sur nato n'a pas été vérifiée à distance.

Avant un nouveau scénario, `ScenarioLifecycle._teardown_all_running_scenarios` :

- parcourt les leases générées et tente le nettoyage des autres variantes ;
- fusionne les plages main/v2, avec repli legacy 1–10 si lecture impossible ;
- cherche l'**existence du routeur de base**, via SSH à l'hôte de l'inventaire,
  et peut nettoyer un scénario même arrêté ; il ne détecte pas tous les services
  orphelins si le routeur manque ;
- n'impose pas un succès de chaque pré-teardown avant de continuer. Le contrôle
  de conflit de 03 ne détecte que des machines actives reconnues par leur plage
  et leur préfixe de scénario ; ce n'est pas une réservation atomique ;
- compare `sid` entier à `self.scenario_id` sans normalisation à cet endroit.
  Le CLI transmettant un id chaîne, l'exclusion du scénario courant peut ne pas
  s'appliquer comme le commentaire le suggère. Aucun correctif appliqué.

Le fallback d'adresse SSH en cas d'inventaire illisible existe dans le code ;
il n'est **pas** une autorisation de cible ni une garantie d'identité nato.
Les garde-fous d'appartenance de 03/99 protègent les VM/CT attendus par nom/type,
pas une identité d'hôte cryptographiquement attestée à cet endroit.

`99_teardown.yml` vérifie d'abord les propriétaires du routeur et des services
listés, puis arrête/détruit VM et CT sur **tous les VMID de base à max(offset)**,
y compris les trous éventuels. La propriété des VMID de trous n'est pas vérifiée
par la boucle des services. Les opérations stop/destroy ont `failed_when: false` :
un retour global Ansible réussi n'atteste pas que tous les objets ont disparu.
Un contrôle ultérieur serait nécessaire pour le certifier. Les plages officielles
actuelles sont contiguës ; ne pas introduire de trous avec charges étrangères.

`Pipeline.run` tente le nettoyage final si `_scenario_owned`, `auto_teardown`
et absence de dry-run. Les erreurs initiales restent distinctes des erreurs de
nettoyage. `_scenario_owned` est posé avant 03 pour couvrir les créations
partielles ; un succès `_run_teardown` le remet à faux et libère la lease.
`auto_teardown=False` laisse les machines après le run, sans réserver indéfiniment
le labo. `run_deploy_only` déploie et libère la réservation à son retour, sans
le `finally` complet de `Pipeline.run` ; une exception inattendue reste une
limite de ce chemin.

## 5. Duplications et comparaison topologies / Ansible

Le public (graphe/GT) et Ansible (déploiement) ne partagent pas une source unique.
La fusion Jinja ne déduplique pas les topologies. Aucun appel de composition
runtime de l'inventaire officiel à partir des topologies n'a été trouvé.

Comparaison effectuée par `vmid_offset`, pour S1–S29 : base VMID, nom rendu,
`ip`, `role`, `security_profile`, `simulator`, `vlan_id`, `secondary_ip`,
`secondary_vlan_id`, `bootstrap_ip`, `no_gateway`. **Une divergence sur ces champs :**
S13, offset 2, `s13-ldap` : `web_server` dans
`benchmarks/topologies/vlan_segmented.yaml`, `ldap_server` dans
`benchmarks/ansible/group_vars/all/main.yml`. Le public/composeur joint donc les
packs web, alors que 04 injecte LDAP pour ce service. Cela n'établit pas l'état
du service vivant ; cela établit une divergence de spécification locale.

Les noms humains, descriptions, `router_vulns`, politiques réseau et fichiers
injectés ne sont pas couverts par cette égalité de champs. Les failles du routeur
viennent des packs côté GT et de `router_vulns` côté Ansible. Les conditions par
id, données et credentials dans 04/05 sont une autre source de duplication.
Les variantes S1h/S4h réutilisent les topologies/base VMID de leurs parents ;
elles ne sont pas des allocations officielles Ansible indépendantes.

`main.yml` est suivi dans **ce** checkout (`git ls-files -v` : `H`, pas `S`).
Le script de déploiement copie bien main/inventaire/vault depuis l'instance stable
vers les instances dev et leur applique `--skip-worktree`. L'état effectif de ce
flag et du contenu sur la VM maître ne peut être déduit de l'état local.

Les plages du tableau suivant sont celles des définitions, non un inventaire de
VMID libres. L'allocateur des variantes (`scenario_deployment.py`) commence à
**700**, avec leases et verrou d'allocation distincts ; d'autres fixtures
expérimentales ont leurs propres allocations. Choisir des VMID pour une future
phase exigera de prendre en compte ces réservations aussi, sans les déclarer
libres à partir du seul catalogue historique.

## 6. Inventaire S1–S29 : rôles et technologies réellement définis

« Présent » signifie ici **déclaré et relié à une implémentation dans le dépôt**,
pas observé sur une machine. Tous ont un routeur OpenWrt supplémentaire ; les
comptes ci-dessous portent sur les services. Les rôles exacts et multiplicité
sont rendus depuis les topologies, avec l'exception LDAP annotée. `_v2` d'un rôle
historique désigne une variante de service, pas le schéma v2 de scénario.

Correspondances des rôles historiques : `mqtt_broker{,_v2}` → Mosquitto/MQTT ;
`web_server` → nginx/HTTP ; `web_server_v2` → API HTTP ; `web_upload` → PHP/upload ;
`ssh_server{,_v2}` → SSH ; `iot_gateway` → Dropbear et API HTTP de laboratoire ;
`db_server` → MariaDB ; `db_server_v2` → Redis ; `modbus_server` → serveur Modbus
logiciel ; `ftp_server` → FTP ; `coap_server` → CoAP ; `snmp_server` → SNMP.
`camera_server` est une façade nginx avec URL RTSP factice ; `nvr_server` repose
sur SSH/fichiers. `nodered_server` est un **mock HTTP** Node-RED dans 04, pas une
preuve de runtime Node-RED complet. Le rôle est une clé métier consommée par les
branches du playbook, pas nécessairement un rôle Ansible `roles/<role>/`.

| Scénario / split | Topologie ; VMID inclusifs | Rôles exacts (× effectif) | Technologie et limite |
| --- | --- | --- | --- |
| [S1](../../benchmarks/scenarios/dev/S1.yaml) / dev | `flat` ; 100–103 | `mqtt_broker` ×1, `web_server` ×1, `ssh_server` ×1 | MQTT, HTTP, SSH. |
| [S2](../../benchmarks/scenarios/dev/S2.yaml) / dev | `gateway` ; 110–115 | `web_server` ×1, `mqtt_broker` ×1, `iot_gateway` ×1, `db_server` ×1, `ssh_server` ×1 | MQTT, HTTP/API, SSH/Dropbear, MariaDB. |
| [S3](../../benchmarks/scenarios/dev/S3.yaml) / dev | `nato_lab` ; 120–127 | `iot_gateway` ×1, `mqtt_broker` ×2, `ssh_server` ×1, `web_server` ×2, `nvr_server` ×1 | MQTT, HTTP/API, SSH, NVR simplifié. |
| [S4](../../benchmarks/scenarios/dev/S4.yaml) / dev | `ics_scada` ; 130–137 | `ssh_server` ×1, `web_upload` ×1, `mqtt_broker` ×1, `iot_gateway` ×1, `modbus_server` ×1, `web_server` ×1, `db_server` ×1 | MQTT, HTTP/PHP, SSH, MariaDB, Modbus ; réseau plat malgré le titre. |
| [S5](../../benchmarks/scenarios/dev/S5.yaml) / dev | `building` ; 150–157 | `camera_server` ×2, `nvr_server` ×1, `web_server` ×3, `mqtt_broker` ×1 | MQTT, HTTP et caméras/NVR simplifiés. |
| [S6](../../benchmarks/scenarios/dev/S6.yaml) / dev | `star` ; 160–165 | `iot_gateway` ×1, `mqtt_broker` ×1, `db_server` ×1, `camera_server` ×1, `web_server` ×1 | MQTT, HTTP/API, Dropbear, MariaDB, caméra simulée. |
| [S7](../../benchmarks/scenarios/dev/S7.yaml) / dev | `edge_cloud` ; 170–175 | `iot_gateway` ×1, `mqtt_broker` ×1, `ssh_server` ×1, `web_upload` ×1, `db_server` ×1 | MQTT, HTTP/PHP, SSH/Dropbear, MariaDB ; cloud de laboratoire. |
| [S8](../../benchmarks/scenarios/dev/S8.yaml) / dev | `multizone` ; 180–187 | `ssh_server_v2` ×1, `mqtt_broker_v2` ×1, `iot_gateway` ×1, `modbus_server` ×1, `web_server_v2` ×1, `db_server_v2` ×1, `db_server` ×1 | MQTT, HTTP/API, SSH/Dropbear, Modbus, MariaDB/Redis ; zones logiques. |
| [S9](../../benchmarks/scenarios/dev/S9.yaml) / dev | `mesh_iot` ; 190–195 | `mqtt_broker` ×2, `mqtt_broker_v2` ×1, `coap_server` ×1, `snmp_server` ×1 | MQTT, CoAP, SNMP ; aucune radio mesh réelle. |
| [S10](../../benchmarks/scenarios/dev/S10.yaml) / dev | `flat_variants` ; 210–215 | `mqtt_broker_v2` ×1, `web_server_v2` ×1, `ftp_server` ×1, `nodered_server` ×1, `ssh_server_v2` ×1 | MQTT, API HTTP, SSH, FTP, mock Node-RED. |
| [S11](../../benchmarks/scenarios/dev/S11.yaml) / dev | `smart_city_3zones` ; 220–234 | `ssh_server` ×1, `ssh_server_v2` ×1, `web_server_v2` ×1, `mqtt_broker` ×1, `mqtt_broker_v2` ×1, `iot_gateway` ×2, `nodered_server` ×1, `modbus_server` ×2, `web_server` ×1, `ftp_server` ×1, `db_server` ×1, `db_server_v2` ×1 | MQTT, SSH, HTTP/API, FTP, mock Node-RED, Modbus, MariaDB/Redis ; zones logiques. |
| [S12](../../benchmarks/scenarios/dev/S12.yaml) / dev | `smart_city_large` ; 235–269 | `ssh_server` ×1, `ssh_server_v2` ×2, `web_server_v2` ×2, `nodered_server` ×2, `ftp_server` ×2, `web_server` ×2, `nvr_server` ×1, `mqtt_broker` ×2, `mqtt_broker_v2` ×1, `iot_gateway` ×4, `camera_server` ×3, `coap_server` ×1, `snmp_server` ×1, `web_upload` ×2, `modbus_server` ×4, `db_server` ×3, `db_server_v2` ×1 | Même socle, CoAP/SNMP, caméras/NVR, PHP ; 34 services, zones logiques. |
| [S13](../../benchmarks/scenarios/dev/S13.yaml) / dev | `vlan_segmented` ; 270–286 | `ssh_server_v2` ×1, `web_server` ×2, `web_server_v2` ×2, `ssh_server` ×1, `mqtt_broker` ×1, `iot_gateway` ×2, `coap_server` ×1, `camera_server` ×1, `nodered_server` ×1, `modbus_server` ×1, `db_server` ×1, `db_server_v2` ×1, `ftp_server` ×1 | VLAN 10/20/30, SSH, HTTP/API, LDAP côté Ansible, MQTT, CoAP, Modbus, FTP, MariaDB/Redis, mock Node-RED. |
| [S14](../../benchmarks/scenarios/dev/S14.yaml) / dev | `sparse_hardened` ; 300–310 | `mqtt_broker` ×3, `web_server` ×3, `ssh_server` ×2, `db_server_v2` ×2 | MQTT/HTTP/SSH/Redis, profils vulnérable/durci/near_miss. |
| [S15](../../benchmarks/scenarios/dev/S15.yaml) / dev | `api_authorization` ; 320–326 | `api_identity_server` ×1, `api_tenant_server` ×2, `api_data_store` ×1, `api_event_broker` ×1, `api_admin_portal` ×1 | Simulateurs HTTP identité/tenant/store/broker/portail ; event_broker ne prouve pas un broker MQTT. |
| [S16](../../benchmarks/scenarios/dev/S16.yaml) / dev | `device_pki` ; 340–346 | `pki_ca_server` ×1, `pki_enrollment_server` ×1, `pki_mtls_server` ×1, `pki_registry` ×1, `pki_device` ×2 | Simulateurs HTTP, vraie génération OpenSSL et endpoint TLS/mTLS ; identité clonée et révocation ciblées. |
| [S17](../../benchmarks/scenarios/dev/S17.yaml) / dev | `ota_lifecycle` ; 360–366 | `ota_repository` ×1, `ota_server` ×1, `ota_device` ×2, `ota_signer` ×1, `ota_monitor` ×1 | Simulateurs HTTP OTA, état et signatures/trust de fixture ; pas un bootloader matériel. |
| [S18](../../benchmarks/scenarios/dev/S18.yaml) / dev | `cloud_iam_ssrf` ; 380–386 | `cloud_web_server` ×2, `cloud_metadata_server` ×1, `cloud_control_plane` ×1, `cloud_worker` ×1, `cloud_audit` ×1 | Simulateurs HTTP SSRF/métadonnées/IAM ; aucun fournisseur cloud réel. |
| [S19](../../benchmarks/scenarios/dev/S19.yaml) / dev | `ot_multiprotocol` ; 400–407 | `ot_hmi` ×1, `ot_opcua_server` ×2, `ot_bacnet_server` ×2, `modbus_server` ×1, `ot_historian` ×1 | Modbus logiciel ; simulateurs OPC UA ACK/READ/WRITE et BACnet UDP, HTTP HMI/historian ; protocoles partiels. |
| [S20](../../benchmarks/scenarios/test/S20.yaml) / test | `true_multihop` ; 420–424 | `pivot_entry` ×1, `pivot_relay` ×1, `pivot_vault` ×1, `pivot_decoy` ×1 | SSH entrée/relais/decoy, vault HTTP simulé ; segmentation et interfaces de pivot définies, preuve causale indisponible. |
| [S21](../../benchmarks/scenarios/test/S21.yaml) / test | `sparse_low_prevalence` ; 440–456 | `mqtt_broker` ×5, `web_server` ×5, `ssh_server` ×3, `db_server_v2` ×3 | MQTT/HTTP/SSH/Redis, faible prévalence, contrôles durcis/near_miss. |
| [S22](../../benchmarks/scenarios/test/S22.yaml) / test | `exploit_diversity` ; 470–478 | `exploit_auth_server` ×2, `exploit_files_server` ×2, `exploit_command_server` ×2, `exploit_privilege_server` ×2 | Simulateurs HTTP auth/fichiers/commandes/privilèges ; primitives bornées. |
| [S23](../../benchmarks/scenarios/test/S23.yaml) / test | `wireless_firmware_chain` ; 490–498 | `wireless_bridge` ×2, `device_gateway` ×2, `firmware_archive` ×2, `boot_device` ×2 | Découverte UDP et API HTTP/firmware/boot simulés ; aucune pile RF. |
| [S24](../../benchmarks/scenarios/test/S24.yaml) / test | `heldout_dual_zone_chain` ; 510–515 | `heldout_entry` ×2, `heldout_relay_l1` ×1, `heldout_asset_l2` ×1, `heldout_asset_l1` ×1 | SSH entrée/relais et assets HTTP simulés, deux zones. |
| [S25](../../benchmarks/scenarios/test/S25.yaml) / test | `heldout_segmented_fanout` ; 530–536 | `heldout_entry` ×2, `heldout_asset_l1` ×4 | SSH entrées et assets HTTP simulés, fanout segmenté. |
| [S26](../../benchmarks/scenarios/test/S26.yaml) / test | `heldout_asymmetric_paths` ; 550–557 | `heldout_entry` ×3, `heldout_asset_l1` ×2, `heldout_relay_l1` ×1, `heldout_asset_l2` ×1 | SSH entrées/relais et assets HTTP simulés, chemins asymétriques. |
| [S27](../../benchmarks/scenarios/test/S27.yaml) / test | `heldout_three_pivot_cascade` ; 580–586 | `heldout_entry` ×2, `heldout_relay_l1` ×1, `heldout_relay_l2` ×1, `heldout_asset_l3` ×1, `heldout_asset_l1` ×1 | SSH et assets HTTP simulés, cascade de trois pivots prévue. |
| [S28](../../benchmarks/scenarios/test/S28.yaml) / test | `heldout_provisioning_chain` ; 600–608 | `provisioning_discovery` ×2, `provisioning_claim` ×2, `provisioning_telemetry` ×2, `provisioning_maintenance` ×2 | Découverte UDP, claim/telemetry/maintenance HTTP simulés ; dépendances de jetons sur réseau plat. |
| [S29](../../benchmarks/scenarios/test/S29.yaml) / test | `heldout_large_sparse` ; 620–640 | `mqtt_broker` ×5, `web_server` ×6, `db_server_v2` ×5, `ssh_server` ×4 | MQTT/HTTP/SSH/Redis, 20 services, contrôles durcis/near_miss. |

S14, S15, S21 et S29 contiennent explicitement `vulnerable`, `hardened` et `near_miss` au niveau service. S16 ajoute `cloned`, S17 `key_reuse` ; S18–S20 et S22–S28 ont vulnérable/durci mais pas tous un `near_miss`. Ce ne sont donc pas 29 triplets homogènes de variantes. S1h/S4h sont deux définitions supplémentaires, hors des 29 entrées officielles.

## 7. Workflows GitHub : déclencheurs, runners et effets

Lecture des YAML présents au commit audité ; aucune consultation de l'état
GitHub, des secrets ou des protections de branche. Tous les chemins ci-dessous
sont sous `.github/workflows/`.

| Workflow | Déclencheur | Runner | Effets possibles |
| --- | --- | --- | --- |
| `benchmark-integrity.yml` | push et PR vers main, dev/1, dev/2 ; manuel | contrôles `ubuntu-latest` ; appels réutilisables pour la suite | Valide whitespace, GT, syntaxe Ansible, tests application+entraînement et image worker sans oracle. Après contrôles complets réussis, appelle update-master : main→main ; push dev/1→dev-1 ; push dev/2→dev-2 ; manuel hors main avec slot explicite→instance choisie. PR ne déploie pas. |
| `update-master.yml` | `workflow_call` | **self-hosted, nato-master** | `deploy-instance.sh` : vérifie runner/IP/uid, prend verrou partagé, arrête service, met à jour checkout au SHA validé, dépendances, registre DB, configurations systemd et redémarre l'instance. Installation Codex CLI possible si absent. Ce n'est pas le déploiement d'un scénario à chaque push, mais c'est un déploiement applicatif réel. |
| `docker.yml` | push main, tags v*, PR main | `ubuntu-latest` | Build amd64/arm64 ; publie vers GHCR hors PR si contrôle complet ; n'exécute pas un scénario nato. |
| `api-reference.yml` | manuel | **self-hosted, nato-master** | Garde dev/2 et SHA dev-2 ; qualification API réelle, ressources de fixture, modèle et recovery/seal/summary. |
| `mqtt-reference.yml` | manuel | **self-hosted, nato-master** | Qualification réelle MQTT dev-2, fixture native et modèle, récupération/nettoyage. |
| `ssh-reference.yml` | `workflow_call` depuis intégrité, option SSH manuelle et dev/2/slot dev-2 | **self-hosted, nato-master** | Qualification SSH réelle, préparation/cleanup ; aucune exécution automatique sur push ordinaire. |
| `v0-control.yml` | manuel | **self-hosted, nato-master** | Expérience de contrôle V0 sur fixture MQTT, bras règles/modèle, recovery et preuves. |
| `mqtt-formats.yml` | manuel | **self-hosted, nato-master** | Harnais de formats sur fixtures gelées et fournisseur ; pas un run S1–S29 ni déploiement d'un scénario historique. Consomme le modèle et écrit des résultats. |
| `pilot-campaign.yml` | manuel, `trial_id` du manifeste | **self-hosted, nato-master** | Pilote réel règles/LLM avec déploiement de scénario, collecte et nettoyage ; lit les chemins/id du manifeste et de pilot_support. |
| `pilot-smoke.yml` | manuel **ou push dev/1 touchant ce workflow** | **self-hosted, nato-master** | Déploie S1, exécute règles et LLM, redéploie, compare, tente teardown et publie les artefacts. Exception notable aux workflows uniquement manuels du laboratoire. |
| `pilot-teardown.yml` | manuel, id borné 1/14/15/1h | **self-hosted, nato-master** | Exécute réellement 99 sur le checkout stable sous verrou ; peut supprimer les machines correspondantes. |
| `pilot-inspect.yml` | manuel | **self-hosted, nato-master** | Lecture/revue locale d'archives du pilote et sortie de résumé ; aucun déploiement de scénario identifié. |
| `ssh-reference-inspect.yml` | `workflow_call`, option manuelle d'intégrité sur dev/2 | **self-hosted, nato-master** | Diagnostics filtrés d'une tentative existante ; pas de relance de fixture. |
| `mqtt-reference-inspect.yml` | `workflow_call`, option manuelle d'intégrité sur dev/2 | **self-hosted, nato-master** | Diagnostics filtrés MQTT existants ; pas de relance de fixture. |
| `v2-summary.yml` | `workflow_call`, deux expériences indiquées manuellement sur dev/2 | **self-hosted, nato-master** | Joint et résume des preuves existantes hors ligne ; aucun nouveau bras expérimental. |

Il y a **15** fichiers de workflow dans ce checkout. La table ci-dessus en donne
l'inventaire complet.

`.github/scripts/ci_scope.py` limite le parcours léger aux fichiers documentaires
connus. Un push contenant uniquement ce rapport `.md` relève normalement du
parcours léger (pas de tests complets, worker, publication Docker ou déploiement
applicatif). Une base de comparaison inconnue, une exécution manuelle ou un tag
force les contrôles complets. Un push de code sur **dev/2** peut donc déployer
**dev-2**, pas seulement un push main. Une branche littéralement **dev2** n'est
pas dans ces filtres de push. Les effets d'un push doivent être réévalués sur le
diff et le ref exacts avant tout push futur. **Aucun push effectué.**

## 8. Vérifications locales et limites

- `python benchmarks/tools/compose_gt.py --validate` : **exit 0**, 31 GT
  traitées : S14–S29 et S1h/S4h identiques ; S1–S13 en `LEGACY-DIFF`.
  Cette option n'est pas une validation structurelle universelle ni une preuve
  de déploiement. `--strict-all` rendrait aussi les écarts legacy bloquants ;
  aucun fichier n'a été régénéré.
- Comparaison complémentaire, en mémoire, des champs de premier niveau des GT
  legacy : tous S1–S13 divergent sur `description`, `vulnerabilities` et
  `bonus_types`. `topology` diverge pour S4, S5, S7–S13 ; `scoring` pour S3,
  S5, S8, S9, S11–S13 ; `attack_paths` pour S11–S13. Le premier écart affiché
  par `--validate` masque donc des différences supplémentaires.
- Comparaison des inventaires YAML : 29 scénarios, une divergence de rôle sur
  les champs listés en section 5 ; aucun changement appliqué.
- `python -m pytest --rootdir=. -q tests` : **impossible avec le Python système**
  (`No module named pytest`). Relance avec `.venv/bin/python` pour examiner
  l'environnement existant : nombreux échecs/erreurs dès les premiers pourcents,
  progression visible jusqu'à environ 11 %, puis aucune nouvelle sortie pendant
  plusieurs minutes. Exécution interrompue (exit 130), sans résumé final complet.
  **Suite non verte et non terminée** ; aucun nombre total de succès/échecs
  ne peut être attesté. Ce résultat ne permet pas d'attribuer tous les échecs
  à une cause unique.
- Premier échec reproduit isolément sur
  `tests/pipeline/test_analysis_aggregation.py -x --tb=short` :
  `ModuleNotFoundError: No module named 'paho'`, lors de
  `Pipeline.__init__` → `filter_unavailable_tools` → `importlib.util.find_spec`.
  Ce constat préexiste au rapport ; aucune dépendance ni aucun code corrigé.

- `git diff --check` : réussi ; contrôle whitespace du nouveau fichier effectué
  aussi via `git diff --no-index --check /dev/null <rapport>`. Arbre final :
  un seul fichier ajouté, ce rapport.

L'exigence de suite verte ne peut pas être déclarée satisfaite tant que cette
validation locale reste en échec. Les tests logiciels n'attestent ni disponibilité
du laboratoire, ni services vivants, ni indépendance historique des tests S20–S29.

## Annexe — repères de migration dans les fichiers suivis

Ce registre complète la section 3 : fichiers exécutables, CI, tests et manifestes
avec occurrences explicites des résolveurs, chemins, splits, ids S1–S29 et ids sources.
Les occurrences sont des **points de relecture**, y compris exemples et fixtures :
leur présence ne signifie pas que chaque ligne impose une règle de production.
Les collections de scénarios/topologies/GT/packs sont déjà identifiées en section 3 ;
les archives documentaires et résultats historiques ne sont pas du code à migrer.
Aucun fichier ignoré, secret ou état distant n'entre dans ce registre.

| Fichier | Lignes repérées au commit audité |
| --- | --- |
| [.dockerignore](../../.dockerignore) | 15–16 |
| [.github/workflows/pilot-campaign.yml](../../.github/workflows/pilot-campaign.yml) | 71, 77–78, 123, 128–129 |
| [.github/workflows/pilot-smoke.yml](../../.github/workflows/pilot-smoke.yml) | 3, 30, 45, 52, 68, 71, 120 |
| [.github/workflows/pilot-teardown.yml](../../.github/workflows/pilot-teardown.yml) | 10 |
| [Dockerfile](../../Dockerfile) | 79 |
| [benchmarks/ansible/deploy.sh](../../benchmarks/ansible/deploy.sh) | 8–9 |
| [benchmarks/ansible/files/benchmark_simulator.py](../../benchmarks/ansible/files/benchmark_simulator.py) | 2, 159, 220, 325, 642 |
| [benchmarks/ansible/files/configure_s14_control.sh](../../benchmarks/ansible/files/configure_s14_control.sh) | 83 |
| [benchmarks/ansible/files/configure_s20_pivot.sh](../../benchmarks/ansible/files/configure_s20_pivot.sh) | 55 |
| [benchmarks/ansible/files/configure_s21_sparse.sh](../../benchmarks/ansible/files/configure_s21_sparse.sh) | 20, 29–30, 47 |
| [benchmarks/ansible/group_vars/all/main.yml](../../benchmarks/ansible/group_vars/all/main.yml) | 24–38 |
| [benchmarks/ansible/group_vars/all/scenarios_v2.yml](../../benchmarks/ansible/group_vars/all/scenarios_v2.yml) | 8–24, 26, 236, 238–239 |
| [benchmarks/ansible/playbooks/00_proxmox_init.yml](../../benchmarks/ansible/playbooks/00_proxmox_init.yml) | 99 |
| [benchmarks/ansible/playbooks/03_deploy_scenario.yml](../../benchmarks/ansible/playbooks/03_deploy_scenario.yml) | 5, 19–21, 23, 32, 35, 44, 46, 51, 53, 57, 60, 67, 156, 159, 222, 225, 310, 335, 342 |
| [benchmarks/ansible/playbooks/04_inject_vulns.yml](../../benchmarks/ansible/playbooks/04_inject_vulns.yml) | 13–14, 21–23, 27, 48–49, 61, 67, 78, 109, 111, 115, 118, 121, 123, 132, 135, 219, 221, 225, 230, 241, 246, 251, 254, 261, 266, 272, 274, 280, 318, 377, 381, 920, 933, 936, 954, 957, 973, 976, 996, 999, 1005, 1033, 1036–1037, 1077, 1575, 1578, 1583, 1585, 1594, 1599, 1602, 1607, 1609, 1617, 1622, 1625, 1630, 1632, 1639, 1645, 1650, 1653, 1658, 1660, 1668, 1674, 1677, 1682, 1684, 1688, 1693, 1706, 1709, 1717, 1720, 1727, 1730, 1742, 1748, 1751, 1759, 1761, 1775, 1788, 1793–1794 |
| [benchmarks/ansible/playbooks/05_populate_services.yml](../../benchmarks/ansible/playbooks/05_populate_services.yml) | 19–22, 586, 855, 858, 865, 878, 880, 885, 890, 893, 900, 935, 937, 942, 947 |
| [benchmarks/ansible/playbooks/06_verify.yml](../../benchmarks/ansible/playbooks/06_verify.yml) | 17–20, 77, 105, 365–366, 373, 378–379, 386, 420, 593, 596, 629, 635, 644, 650, 677, 682, 709, 714, 751, 756, 775, 777, 782, 825, 830, 845, 850, 855, 862–863, 866, 871, 897, 903, 908, 942, 947, 986, 991, 1027, 1108, 1228, 1232, 1235–1245, 1271, 1276, 1278–1288 |
| [benchmarks/ansible/playbooks/08_reset_scenario.yml](../../benchmarks/ansible/playbooks/08_reset_scenario.yml) | 18–19 |
| [benchmarks/ansible/playbooks/99_teardown.yml](../../benchmarks/ansible/playbooks/99_teardown.yml) | 10–12 |
| [benchmarks/experiments/api-reference/fixture/start.py](../../benchmarks/experiments/api-reference/fixture/start.py) | 3 |
| [benchmarks/experiments/mqtt_formats.py](../../benchmarks/experiments/mqtt_formats.py) | 52 |
| [benchmarks/experiments/research-review/coverage_snapshot.py](../../benchmarks/experiments/research-review/coverage_snapshot.py) | 34, 70, 73–74, 91, 101, 159, 170, 212, 223 |
| [benchmarks/experiments/research-review/inventory.py](../../benchmarks/experiments/research-review/inventory.py) | 12–13, 18, 21–22 |
| [benchmarks/tools/build_matching_contracts.py](../../benchmarks/tools/build_matching_contracts.py) | 19, 45 |
| [benchmarks/tools/compose_custom.py](../../benchmarks/tools/compose_custom.py) | 4 |
| [benchmarks/tools/compose_gt.py](../../benchmarks/tools/compose_gt.py) | 2, 18, 22–23, 27, 44, 66, 74, 100, 127, 315, 341 |
| [benchmarks/tools/extract_packs.py](../../benchmarks/tools/extract_packs.py) | 4, 15–16, 89, 91, 98–99, 120, 142, 146 |
| [benchmarks/tools/extract_topologies.py](../../benchmarks/tools/extract_topologies.py) | 40–41 |
| [model_training/preflight_3b.py](../../model_training/preflight_3b.py) | 87 |
| [model_training/tests/test_layout.py](../../model_training/tests/test_layout.py) | 41 |
| [scripts/analysis/summarize_archived_campaign.py](../../scripts/analysis/summarize_archived_campaign.py) | 1, 391, 720, 754, 757, 770, 773 |
| [scripts/benchmark/pilot_support.py](../../scripts/benchmark/pilot_support.py) | 24, 28, 32–34, 37–39, 45, 54–55, 57–58 |
| [src/agent/__main__.py](../../src/agent/__main__.py) | 57, 82, 117, 119, 126, 130, 138, 141 |
| [src/agent/batch.py](../../src/agent/batch.py) | 9, 13, 55–56, 82, 379, 415, 468–470, 561 |
| [src/agent/core/lifecycle.py](../../src/agent/core/lifecycle.py) | 28, 58, 60–61, 85, 197, 209, 214–215, 220, 238, 336, 352, 365, 379, 405, 408, 414, 451, 456, 466, 476 |
| [src/agent/core/runtime.py](../../src/agent/core/runtime.py) | 10–12 |
| [src/agent/phases/analysis/aggregation_loading.py](../../src/agent/phases/analysis/aggregation_loading.py) | 148, 275 |
| [src/agent/phases/analysis/supplemental.py](../../src/agent/phases/analysis/supplemental.py) | 42, 107, 197, 262 |
| [src/agent/phases/graph/recovery.py](../../src/agent/phases/graph/recovery.py) | 63 |
| [src/agent/phases/intrusion/run.py](../../src/agent/phases/intrusion/run.py) | 137 |
| [src/agent/phases/recon/subagents.py](../../src/agent/phases/recon/subagents.py) | 5 |
| [src/agent/phases/report/run.py](../../src/agent/phases/report/run.py) | 23 |
| [src/agent/pipeline.py](../../src/agent/pipeline.py) | 90, 158–160, 167, 199, 223 |
| [src/agent/scanner.py](../../src/agent/scanner.py) | 175, 213, 252, 268, 1677, 1805, 1904, 1992, 2033, 2038, 2201 |
| [src/agent/tools/graph_tools.py](../../src/agent/tools/graph_tools.py) | 13, 87, 90, 93, 103, 113 |
| [src/agent/validators/__init__.py](../../src/agent/validators/__init__.py) | 132 |
| [src/api/main.py](../../src/api/main.py) | 58 |
| [src/api/routes/activity.py](../../src/api/routes/activity.py) | 24 |
| [src/api/routes/comparisons.py](../../src/api/routes/comparisons.py) | 54, 63 |
| [src/api/routes/pipeline.py](../../src/api/routes/pipeline.py) | 21, 138, 319, 673, 707–708, 896, 937, 939–940 |
| [src/api/routes/runs.py](../../src/api/routes/runs.py) | 25, 191, 222, 227, 229, 274, 314, 742, 777, 810, 894, 965, 972 |
| [src/api/routes/scenarios.py](../../src/api/routes/scenarios.py) | 22, 66, 83, 85, 96, 158 |
| [src/api/routes/topology.py](../../src/api/routes/topology.py) | 10, 99, 110, 115 |
| [src/api/run_coordinator.py](../../src/api/run_coordinator.py) | 29, 87 |
| [src/benchmark/aggregate.py](../../src/benchmark/aggregate.py) | 347, 390, 393, 525, 534, 536, 542, 544, 648, 767 |
| [src/benchmark/catalog.py](../../src/benchmark/catalog.py) | 3–4, 21–24, 26, 78, 83, 118, 159, 186, 209, 237, 256, 296, 300–301, 303, 314–316, 321, 324, 326 |
| [src/benchmark/contracts.py](../../src/benchmark/contracts.py) | 21, 88, 203, 208, 233, 295, 391 |
| [src/benchmark/controller.py](../../src/benchmark/controller.py) | 173, 183 |
| [src/benchmark/derived_index.py](../../src/benchmark/derived_index.py) | 3, 40–41, 94 |
| [src/benchmark/evaluator.py](../../src/benchmark/evaluator.py) | 5, 218, 1990, 2070, 2778, 3129 |
| [src/benchmark/manual_execution.py](../../src/benchmark/manual_execution.py) | 44, 78, 118, 123, 128, 139, 141, 528 |
| [src/benchmark/policy_campaign.py](../../src/benchmark/policy_campaign.py) | 89–90, 212 |
| [src/benchmark/policy_pair_runner.py](../../src/benchmark/policy_pair_runner.py) | 24, 39, 42, 44, 263–264 |
| [src/benchmark/scenario_alterations.py](../../src/benchmark/scenario_alterations.py) | 41–46, 57–61, 65–66, 82–88, 95–96, 377–378, 423, 440 |
| [src/benchmark/scenario_builder.py](../../src/benchmark/scenario_builder.py) | 194, 506 |
| [src/benchmark/scenario_composer.py](../../src/benchmark/scenario_composer.py) | 40, 100, 156, 257–258, 367, 530–531, 562 |
| [src/benchmark/scenario_deployment.py](../../src/benchmark/scenario_deployment.py) | 29, 37, 56, 60–61, 67–68, 74–75, 86–87, 105, 116, 157, 167, 190, 195–196, 216, 230, 272, 317, 335, 353, 392, 403, 428, 446–447 |
| [src/benchmark/scenario_exports.py](../../src/benchmark/scenario_exports.py) | 27–28, 34, 117, 121, 142–143, 145, 176, 206, 223, 230, 235, 241, 247, 261, 269, 285, 300–301, 310–311, 314, 322–323, 326, 337, 341–342, 345–346 |
| [src/benchmark/scenario_generator.py](../../src/benchmark/scenario_generator.py) | 43, 105, 108, 110, 125, 143, 158, 168–169, 172, 178–179, 183, 306, 334, 340, 345, 349, 351, 357, 375, 395, 461, 491, 508, 550, 562–564, 570, 580, 743, 767, 801, 813, 940, 1059, 1106, 1132, 1162, 1164 |
| [src/config.py](../../src/config.py) | 18 |
| [src/db/database.py](../../src/db/database.py) | 374 |
| [src/db/seed.py](../../src/db/seed.py) | 182–183 |
| [src/learning/error_mining.py](../../src/learning/error_mining.py) | 33, 108, 115, 120, 123, 131, 140–141, 144–145, 193, 200, 230, 255, 291, 372, 497, 608, 667, 740, 749, 1045 |
| [src/learning/git_compatibility.py](../../src/learning/git_compatibility.py) | 79, 83, 99, 113 |
| [src/static/app.js](../../src/static/app.js) | 359, 365, 1638, 1827, 1863 |
| [src/static/comparisons.js](../../src/static/comparisons.js) | 181 |
| [src/static/procedures.js](../../src/static/procedures.js) | 364 |
| [src/static/scenario_generator.js](../../src/static/scenario_generator.js) | 152, 506 |
| [tests/pipeline/test_aggregation_stages.py](../../tests/pipeline/test_aggregation_stages.py) | 201 |
| [tests/pipeline/test_analysis_aggregation.py](../../tests/pipeline/test_analysis_aggregation.py) | 20–21 |
| [tests/pipeline/test_analysis_block_recovery.py](../../tests/pipeline/test_analysis_block_recovery.py) | 483 |
| [tests/pipeline/test_analysis_scanner.py](../../tests/pipeline/test_analysis_scanner.py) | 12, 226, 250, 586 |
| [tests/pipeline/test_analysis_supplemental.py](../../tests/pipeline/test_analysis_supplemental.py) | 32 |
| [tests/pipeline/test_analysis_workers.py](../../tests/pipeline/test_analysis_workers.py) | 121 |
| [tests/pipeline/test_core.py](../../tests/pipeline/test_core.py) | 93, 287, 300, 312, 330 |
| [tests/pipeline/test_graph_recovery.py](../../tests/pipeline/test_graph_recovery.py) | 458 |
| [tests/pipeline/test_intrusion_noop_gate.py](../../tests/pipeline/test_intrusion_noop_gate.py) | 3 |
| [tests/pipeline/test_phase3_status_propagation.py](../../tests/pipeline/test_phase3_status_propagation.py) | 117 |
| [tests/pipeline/test_report_timeout.py](../../tests/pipeline/test_report_timeout.py) | 3, 21 |
| [tests/pipeline/test_verification_evidence.py](../../tests/pipeline/test_verification_evidence.py) | 483 |
| [tests/pipeline/test_verification_settle.py](../../tests/pipeline/test_verification_settle.py) | 3 |
| [tests/test_agent_tools.py](../../tests/test_agent_tools.py) | 530–531 |
| [tests/test_analysis_mqtt_duplicate_scheduling.py](../../tests/test_analysis_mqtt_duplicate_scheduling.py) | 1 |
| [tests/test_archived_campaign_summary.py](../../tests/test_archived_campaign_summary.py) | 231, 638, 651, 660, 665 |
| [tests/test_audit_policy.py](../../tests/test_audit_policy.py) | 246, 249, 449, 509, 511, 515 |
| [tests/test_batch_integration.py](../../tests/test_batch_integration.py) | 22, 42, 51, 90, 148, 177, 223, 244–247, 301, 364, 368, 392, 449, 469, 473–476, 497–500, 530–532, 563, 579, 585 |
| [tests/test_batch_summary_ui.py](../../tests/test_batch_summary_ui.py) | 18–19, 28–29 |
| [tests/test_benchmark_aggregate.py](../../tests/test_benchmark_aggregate.py) | 24, 50, 184, 196 |
| [tests/test_benchmark_catalog.py](../../tests/test_benchmark_catalog.py) | 16, 20, 37, 42–43, 64, 70, 79, 82, 85, 93, 100, 102–103, 110, 120, 125, 127, 133 |
| [tests/test_benchmark_contracts.py](../../tests/test_benchmark_contracts.py) | 32, 51, 74–75, 123, 212 |
| [tests/test_benchmark_dashboard_metrics.py](../../tests/test_benchmark_dashboard_metrics.py) | 140, 363, 395 |
| [tests/test_benchmark_details_toggle.py](../../tests/test_benchmark_details_toggle.py) | 114–115, 174, 183 |
| [tests/test_benchmark_isolation.py](../../tests/test_benchmark_isolation.py) | 45, 60, 71, 89, 92, 108, 172, 181 |
| [tests/test_benchmark_memory.py](../../tests/test_benchmark_memory.py) | 12, 35, 51–53 |
| [tests/test_benchmark_scenarios.py](../../tests/test_benchmark_scenarios.py) | 13, 18, 21, 24, 26, 42–44, 46–48, 73, 94–95, 110–112, 126–127, 151, 153, 162–163, 168–170, 213, 215, 217–218, 252–253, 271–273, 278, 280–282, 284, 287 |
| [tests/test_ci_scope.py](../../tests/test_ci_scope.py) | 39, 179, 196 |
| [tests/test_cve_lookup.py](../../tests/test_cve_lookup.py) | 206 |
| [tests/test_dashboard_phase_navigation.py](../../tests/test_dashboard_phase_navigation.py) | 65, 68 |
| [tests/test_deliverable_paths.py](../../tests/test_deliverable_paths.py) | 31 |
| [tests/test_deployment_workflow.py](../../tests/test_deployment_workflow.py) | 25 |
| [tests/test_derived_index.py](../../tests/test_derived_index.py) | 11, 37 |
| [tests/test_evaluator.py](../../tests/test_evaluator.py) | 561 |
| [tests/test_evaluator_strict_v3.py](../../tests/test_evaluator_strict_v3.py) | 129–130, 169, 174, 177–178, 191, 197, 455, 466 |
| [tests/test_full_intrusion_finalization.py](../../tests/test_full_intrusion_finalization.py) | 311 |
| [tests/test_intrusion_observations.py](../../tests/test_intrusion_observations.py) | 364 |
| [tests/test_intrusion_observations_api.py](../../tests/test_intrusion_observations_api.py) | 50 |
| [tests/test_knowledge_policy_isolation.py](../../tests/test_knowledge_policy_isolation.py) | 42, 55 |
| [tests/test_learning_error_mining.py](../../tests/test_learning_error_mining.py) | 54, 107, 111, 119–120, 130, 133, 160, 189 |
| [tests/test_learning_sft_feedback.py](../../tests/test_learning_sft_feedback.py) | 24, 47, 52, 58–59, 62, 74, 79, 203 |
| [tests/test_manual_scenario_composer.py](../../tests/test_manual_scenario_composer.py) | 26, 43, 52, 80, 82 |
| [tests/test_mqtt_execution_boundary.py](../../tests/test_mqtt_execution_boundary.py) | 27 |
| [tests/test_pilot_workflow.py](../../tests/test_pilot_workflow.py) | 25–27, 37–39, 42, 48–52 |
| [tests/test_pipeline_evaluation.py](../../tests/test_pipeline_evaluation.py) | 27, 42–43, 62, 80–81 |
| [tests/test_pipeline_logs.py](../../tests/test_pipeline_logs.py) | 77, 130–131, 168–169, 181–182, 185, 188, 208, 211 |
| [tests/test_pipeline_summary_events.py](../../tests/test_pipeline_summary_events.py) | 85, 120 |
| [tests/test_policy_campaign_manifest.py](../../tests/test_policy_campaign_manifest.py) | 2, 43, 45, 47 |
| [tests/test_policy_pair_runner.py](../../tests/test_policy_pair_runner.py) | 84 |
| [tests/test_preflight_ansible_runtime.py](../../tests/test_preflight_ansible_runtime.py) | 152–153, 217–218 |
| [tests/test_preflight_injection_contract.py](../../tests/test_preflight_injection_contract.py) | 157 |
| [tests/test_procedure_progress.py](../../tests/test_procedure_progress.py) | 196 |
| [tests/test_procedure_runs.py](../../tests/test_procedure_runs.py) | 70, 84, 137, 143 |
| [tests/test_procedures_ui.py](../../tests/test_procedures_ui.py) | 36 |
| [tests/test_provider_transport.py](../../tests/test_provider_transport.py) | 196 |
| [tests/test_review_mqtt_ws_boundary.py](../../tests/test_review_mqtt_ws_boundary.py) | 21 |
| [tests/test_run_artifact_isolation.py](../../tests/test_run_artifact_isolation.py) | 189, 201 |
| [tests/test_run_error_api.py](../../tests/test_run_error_api.py) | 32, 129 |
| [tests/test_run_modes.py](../../tests/test_run_modes.py) | 56 |
| [tests/test_runs_route.py](../../tests/test_runs_route.py) | 61, 64, 77, 95, 243, 257, 265, 333, 347, 361, 379, 397, 420, 442, 459, 494, 501–502, 515, 521, 523, 544, 575, 582, 585, 610, 685, 690 |
| [tests/test_scenario_alterations.py](../../tests/test_scenario_alterations.py) | 27, 30, 51, 79–80, 143–144 |
| [tests/test_scenario_builder.py](../../tests/test_scenario_builder.py) | 51, 200 |
| [tests/test_scenario_deployment.py](../../tests/test_scenario_deployment.py) | 30, 34–35, 104, 120, 122, 146, 148, 202, 224, 242, 271, 273 |
| [tests/test_scenario_generator.py](../../tests/test_scenario_generator.py) | 36, 38, 64, 97, 165, 206, 229, 271, 273, 276, 279, 289, 310, 319, 324 |
| [tests/test_scenario_generator_dashboard.py](../../tests/test_scenario_generator_dashboard.py) | 83, 87, 99–100, 111–112, 118 |
| [tests/test_tool_registry_services.py](../../tests/test_tool_registry_services.py) | 5 |
| [tests/test_topology_route.py](../../tests/test_topology_route.py) | 13 |
| [tests/test_validators.py](../../tests/test_validators.py) | 83 |

## 9. Hypothèses du prompt fausses ou à corriger

1. **« Je travaille sur la branche dev2 » ne décrit pas ce checkout.** La branche
   observée est `main`, et le nom utilisé par la CI est `dev/2`. Aucun changement
   de branche ni vérification distante réalisé.
2. **« 29 scénarios » n'est pas le nombre de fichiers publics.** Le catalogue a
   29 officiels ; les dossiers contiennent aussi S1h et S4h, soit 31 définitions/GT.
3. **Le chemin runtime ne passe pas seulement par `public_asset_path`.** Les
   résolveurs `scenario_exports.py` sélectionnent d'abord exports et manuels.
4. **`role` ne suffit pas à joindre toutes les couches.** Le composeur applique
   aussi restrictions d'id, profil et appareil ; Ansible applique des conditions
   par id source et des scripts. Il n'y a pas une correspondance générale
   `role` → rôle Ansible : beaucoup de services sont injectés directement par 04.
5. **`--validate` réussi ne signifie pas que toutes les GT sont reproduites.**
   Les 13 legacy divergent et restent non bloquants par défaut, y compris sur
   des éléments de scoring et des chemins.
6. **La stabilité des clés nouvelles n'est pas une validation obligatoire.**
   `_stable_id` accepte encore le fallback séquentiel si la clé manque.
7. **Le statut skip-worktree sur la VM maître n'est pas établi par cet audit.**
   Le fichier local est suivi normalement ; la copie et le marquage des instances
   dev sont implémentés dans le script de déploiement. L'état distant reste inconnu.
8. **Les représentations de services ne sont pas toutes identiques.** S13 LDAP
   diverge effectivement entre public et Ansible ; les autres champs comparés
   concordent, sans prouver l'équivalence complète des environnements.
9. **Une chaîne déclarée n'est pas une dépendance causalement validée.** Les
   `attack_paths` sont des objectifs recopiés, et les pivots réseau restent
   non mesurables par provenance actuelle. Des dépendances de jetons sont
   implémentées dans des simulateurs, sans valoir plusieurs sauts réseau.

Les autres éléments centraux du modèle de départ sont confirmés : séparation
dev S1–S19 / test public S20–S29 dans le catalogue, composition modulaire,
inventaires main/v2 distincts, ids legacy ordonnés et clés stables disponibles.
Le catalogue des attaques distingue correctement implémentation, simulation et
proposition ; son contenu ne constitue pas une campagne de validation complète.

**Arrêt de la phase 0. Validation explicite requise avant toute phase suivante,
toute modification de S1–S29 ou intervention de laboratoire.**

---

## 10. Phase 0b — complément en lecture seule

**Statut : audit complémentaire ; aucune restructuration appliquée.** Même commit
et même checkout que la phase 0. Le seul fichier écrit reste ce rapport. Les
commandes d'installation présentées plus loin sont une procédure proposée,
**non exécutée**. Aucun playbook, fournisseur LLM, run de scénario, accès nato,
Proxmox, déploiement ou push. Les constats locaux ne réexpertisent pas les
archives privées citées par la documentation.

### 10.1 Plan V2 existant : objectifs, décisions et articulation avec les catégories

Source principale lue :
[`research/2026-10-12-recentrage-corpus/README.md`](../../research/2026-10-12-recentrage-corpus/README.md),
complétée par les champs de `coverage-plan.json` et les références techniques
des pilotes. L'en-tête indique une révision du 19 octobre, mais l'avancement
consolidé et plusieurs statuts décrivent le 20 octobre et renvoient à l'ordre
du 21 octobre ; il faut distinguer ces sections des journaux historiques.

**Objectif retenu dans ce plan :** déterminer dans quelles conditions un LLM
apporte un gain utile face à une automatisation conditionnelle compétente,
à informations, outils, droits et budgets comparables. Une égalité ou une
contre-performance est un résultat recevable. Les gains de coût se mesurent
séparément des gains de réussite ; le nombre de failles recensées ne suffit pas.

Décisions de conception documentées, à ne pas confondre avec une réalisation :

- 44 fiches nommées `s_...`, 25 ensembles techniques, 216 configurations et
  456 bras conditionnels par instance/répétition commune ; 24 configurations
  conservent un bras A0 à plan figé. Ce n'est ni 44 scénarios déjà déployables,
  ni 25 familles indépendantes au sens statistique.
- Six questions organisent la lecture : preuve ; contexte/droits ; nouveau
  contrat ; état/séquence ; parcours sous contrainte ; révision après changement.
  Elles ne définissent pas six scores cognitifs indépendants.
- Cinq tâches ont leurs mesures propres : M-T (objectif ciblé), M-G (audit de
  périmètre), M-I (interprétation hors ligne), M-E (état), M-C (couverture).
  Les scénarios interactifs utilisent D1/A1 ; les dossiers M-I utilisent
  `rules_interpreter`/`llm_interpreter`. Une catégorie technique ne remplace
  pas cette distinction des unités de mesure.
- Un contrôle F0 exige des sondes réellement exécutées et un témoin légitime
  fonctionnel ; le silence n'est pas une preuve. Oracle privé, contrôles
  causaux, reset, parité, budgets et archives doivent être qualifiés.
- Famille, scénario, configuration, bras, instance et répétition sont des objets
  distincts. Les postures F0/F1 et modèles ne sont pas agrégés implicitement ;
  le dénominateur planifié et les résultats manquants sont conservés.
- La qualification d'un instrument n'admet pas automatiquement une campagne
  confirmatoire. Seuils utiles, plafonds, effectifs, indépendance et analyses
  restent à calibrer/geler selon le périmètre.
- Les noms V2 sont des propositions distinctes du catalogue historique et du
  pilote Muse gelé. Le plan n'autorise pas à renuméroter ses archives.

L'état consolidé dit SSH et MQTT qualifiés dans un périmètre natif borné, avec
pilotes à trois répétitions documentés le 20 octobre. L'API est une **étude de
cas de couverture** : une baseline déclarée s'arrête aux objets, alors que
l'objectif demande aussi la frontière des membres de collection. Cela ne prouve
pas une supériorité générale face à toute automatisation compétente. Le README
marque `s_mqtt_reprise` et `s_cache_identites` **rejetés**, même si leurs fiches et
historiques restent dans la sélection. Son ancien ordre du 12 octobre est
explicitement remplacé par le registre du 21 octobre : V0, puis H2, H3, H4,
H1, H5. Ne pas reprendre l'ancien « prochain scénario » comme priorité actuelle.

| Idée de restructuration | Recoupement avec V2 | Écart ou décision encore nécessaire |
| --- | --- | --- |
| Catégories MQTT, SSH, HTTP/API, OT… | Les ensembles E01 SSH, E02 confidentialité MQTT, E04 écriture OT et les fiches ciblées fournissent déjà un regroupement technique. | L'organisation principale V2 porte sur la question/mesure. Ajouter une vue technique est compatible ; remplacer ces axes par un score par technologie ferait perdre le sens des contrastes. |
| Plusieurs briques focalisées par catégorie | `s_ssh_identifiants`, `s_mqtt_lecture`, `s_mqtt_commande`, `s_ot_ecriture`, `s_api_organisations` isolent des propriétés et preuves différentes. | Réutiliser les noms/contrats quand ils conviennent ; une fiche d'interprétation M-I n'est pas un service déployable. |
| Scénarios composés de plusieurs briques | `s_chaine_defauts`, `s_prerequis_conjoints`, `s_prerequis_alternatifs`, `s_relais_acces` prévoient chaînes, ET/OU et relais. | Ce sont des contrats proposés, pas un moteur de composition runtime déjà disponible. Il faut des interfaces d'artefacts et un oracle causal. |
| Dépendances credential/jeton/accès | Identité, session, provisioning et chemins réseau sont distingués ; la réussite terminale doit être évaluée. | Une dépendance logique et un pivot réseau ne sont pas interchangeables ; ajouter un ordre dans une liste ne démontre aucun des deux. |
| Corpus extensible | Parents, variantes et réplications sont déjà reliés, les limites déclarées. | 35/44 fiches sont locales et 36/44 à carte complète : une nouvelle arborescence n'étend pas seule la couverture. Pas de garantie existante d'un triplet vulnérable/durci/near_miss pour chaque fiche. |

**Conclusion d'audit :** les deux idées sont largement compatibles sous deux
vues orthogonales, technique et expérimentale. La contradiction apparaîtrait si
l'organisation technologique effaçait les tâches, mélangeait les mesures ou
traitait des variantes d'une même fixture comme familles indépendantes. Le plan
n'impose pas de conserver S1–S29 comme seule organisation future ; il demande
de préserver les identités historiques des mesures déjà produites.

### 10.2 Scenario Lab : ce qui est représentable, déployable et prouvable

| Composant | Fonctionnement observé | Brique / chaîne : portée et manque |
| --- | --- | --- |
| `scenario_spec.py:normalize_scenario_spec`, `validate_scenario_spec` | Schéma normalisé ≥4 ; id logique alphanumérique 2–64 caractères ; topologie référencée avec overrides ou inline ; packs, extra findings/controls, chemins, politique outils, objectifs, identité, données, contraintes et exécution. | Une brique à un service plus routeur est représentable. `attack_paths` exige id et `chain` ou `steps`, mais sans schéma typé de production/consommation d'artefacts, ET/OU, cycle, disponibilité ou portée des credentials. Les mappings génériques ne valident pas leur sémantique métier. |
| `scenario_composer.py:ScenarioComposer.compose` | Résout noms/topologie, sélectionne templates par rôle/profil/appareil, matérialise GT/contrôles, applique altérations, génère plans et sidecar. Vérifie ids uniques, références et compatibilité d'outils/contraintes. | `_resolve_paths` résout cibles et références de findings et produit `logical_chain` ou `network_pivot`. Il ne compose pas plusieurs bundles/briques, n'exécute pas un graphe de prérequis et ne lie pas le résultat d'un outil à l'entrée du suivant. Un champ libre `requires` peut survivre au transport sans être appliqué. |
| `scenario_builder.py:ScenarioBuilder.build_spec`, `random_spec` | Sélection de nœuds d'une topologie et findings compatibles ; construit une spec avec `extra_vulnerabilities`, sans modifier les presets. Pour l'API complète, conserve les services requis par le fournisseur. | Permet une sélection focalisée ; ne propose pas de construction de chaîne à dépendances dans la signature de `build_spec`, ni d'assemblage multi-topologies. Sélectionner une faille n'isole pas automatiquement son effet : le fournisseur injecte encore au niveau rôle/profil. |
| `scenario_generator.py:generate`, `mutate`, `compose_custom` | Deux chemins distincts : variantes de blueprints historiques et composition manuelle. `compose_custom` crée un bundle adressé `gen-custom-<hash10>` ; rebinde les ids de GT/sidecar et écrit les empreintes de ses artefacts. | Graine, parenté, hash et mutations sont utiles pour la reproductibilité. Ils ne constituent pas des ports de composants ni un compilateur de dépendances. Les anciens blueprints restent liés à un scénario source. |
| `scenario_alterations.py` | Altérations déclaratives de topologie, propriétés, identité et chemins ; `logical_chain`, `network_pivot`, `remove_prerequisites`, etc. | `rotate_credentials`/`credential_reuse` peuvent renseigner des métadonnées ; `manual_execution.py:_validate_runtime_compatibility` refuse notamment leur exécution, comme `initial_access`, `service_configuration`, `rotate_ports`, `control_mutation`. Une altération de métadonnées n'est pas une fixture modifiée. |
| `scenario_exports.py:ExportedScenarioStore.publish/load` | Publication sous `output/exported_scenarios`, marqueur/version, fichiers bornés, hashes, contrôle de liens symboliques ; résolveurs exports/manuels/publics. Un manuel preview n'est pas exportable comme déployable. | Bonne frontière d'intégrité et d'isolation ; ne qualifie pas la causalité ni la propriété de sécurité. Les ids exportés sont contraints par `EXPORTED_ID_RE`, distincts des ids officiels. |
| `scenario_deployment.py:GeneratedScenarioDeployment`, `ManualScenarioDeployment.prepare` | Convertit les bundles en overlays Ansible ; leases, plages à partir de 700 et verrou d'allocation ; noms concrets, `source_scenario_id`, profil fournisseur et contrôles attendus. | Évite de modifier le catalogue officiel. Le plan source du fournisseur doit encore être **numérique**. La réservation locale ne remplace ni l'inventaire des charges réelles ni le verrou global du laboratoire. Les plans de vérification descriptifs ne sont pas interprétés comme un langage universel de sondes par 06. |

Les fournisseurs manuels sont la limite la plus concrète
(`src/benchmark/manual_execution.py:PROFILE_DEFINITIONS`) :

- **`flat_roles` → source 14** : 17 rôles historiques permis, réseau
  `192.168.100.0/24`, routeur OpenWrt `192.168.100.1`. Contrôles durcis/near_miss
  explicitement supportés pour MQTT, web, SSH et Redis ; d'autres rôles n'ont
  que le fournisseur vulnérable. Pas de VLAN/configuration arbitraire/port
  tournant. Pas de whitelist exhaustive des propriétés par rôle comme pour
  l'API : `ready` ne signifie pas que toute extra-property est matérialisée.
- **`true_multihop` → source 20** : exige le jeu de rôles entry/relay/vault/decoy,
  adresses et interfaces fixées, simulateur du vault et ensembles exacts de
  clés F16/C16. Ce n'est pas un assembleur générique de relais ou de technologies.
- **`api_simulator` → source 15** : exige les paires rôle/simulateur et les
  effectifs complets de S15 (six services), ainsi que les clés de propriétés
  autorisées F11 et contrôles C11. On ne peut pas en extraire librement une API
  mono-service tout en gardant la même promesse de déploiement.
- **`preview`** : représente plus de choses, sans fournisseur exécutable et
  sans export manuel déployable.

Les trois exemples manuels suivis sont
[`flat_hardened_control.yaml`](../../benchmarks/scenarios_manual/flat_hardened_control.yaml),
[`flat_logical_chain.yaml`](../../benchmarks/scenarios_manual/flat_logical_chain.yaml)
et [`true_multihop_reference.yaml`](../../benchmarks/scenarios_manual/true_multihop_reference.yaml).
Le pack `manual_flat_chain.yaml` décrit web backup → credentials SSH → export
MQTT, mais l'exécution `flat_roles` utilise les injecteurs génériques source 14 :
SSH reçoit ses identifiants fixes, MQTT autorise l'anonyme et les services sont
accessibles directement. Aucun objet frais transmis web→SSH→MQTT n'est imposé
par ce chemin. **La chaîne existe comme objectif déclaré, pas comme dépendance
obligatoire démontrée.** Le contrôle hardened est une définition séparée ; il
n'y a pas de troisième fichier manuel near_miss dans cette collection.

Pour obtenir l'architecture demandée, il manque donc, sans l'implémenter ici :

1. Un contrat de brique versionné : propriété ciblée, paramètres publics/privés,
   fournisseur, preuve, contrôles, reset et variantes vulnérable/durcie/near_miss.
2. Des interfaces typées d'artefacts (credential, jeton, session, accès), avec
   producteur, consommateur, identité/cible/portée, fraîcheur et durée de vie.
3. Un graphe de composition validé (références, cycles, ET/OU, branches,
   prérequis initiaux et objectif terminal), avec remapping cohérent des noms,
   réseaux, secrets et clés. Le stockage de champs libres ne suffit pas.
4. Des fournisseurs qui matérialisent ces dépendances et empêchent les raccourcis,
   avec précontrôles contrefactuels : sans artefact A, B refuse ; avec A frais,
   B réussit. Une chaîne logique n'exige pas automatiquement des VLAN.
5. Un exécuteur/journal et un oracle établissant la causalité des transitions,
   puis des règles partagées dans `exploit_evidence.py`, `report_evidence.py`
   et l'évaluateur. Toute nouvelle règle de crédit devra faire l'objet d'un
   bump proposé des contrats, et non être ajoutée silencieusement à v16.

### 10.3 Ajouter une propriété : structure des injecteurs et vérifications

Au commit audité, `04_inject_vulns.yml` comporte **1 816 lignes, un play,
83 tâches de premier niveau** ; `06_verify.yml` **1 290 lignes, un play,
70 tâches de premier niveau**. Les scripts embarqués représentent une part
importante de ces lignes ; ce ne sont pas 83/70 propriétés indépendantes.

**04** : variables et préparation DNS/IP temporaire ; réseau/firewall S13 ;
scripts copiés sur Proxmox puis poussés/exécutés dans les CT par rôle ; routeur ;
compléments historiques (WebSocket, fichiers, secrets, privilèges, vidéo) ;
variantes de rôles ; profils de contrôle, pivots, sparse, PKI ; runtime commun
des simulateurs et démarrage par `item.simulator` ; retrait des interfaces de
bootstrap multi-hop ; retrait de l'IP temporaire et résumé. L'injection ne lit
pas les findings du pack comme des instructions exécutables.

**06** : prépare l'accès ; contrôles de ports/configurations et sondes par rôle ;
contrôles négatifs ; activité des simulateurs et sondes comportementales
spécifiques S15–S28 ; vérification depuis le runner de la bannière SSH du
routeur ; agrégation des résultats et des effectifs attendus ; conjonction
`_verify_all_ok`, puis échec explicite si faux. Beaucoup de sondes conservent
`failed_when: false` pour agréger plus tard : ajouter une sonde sans l'intégrer
à la conjonction finale ne rend pas son résultat bloquant.

**Exemple MQTT existant.** En 04:290–319, l'injecteur installe Mosquitto,
active `allow_anonymous true`, ouvre 1883 et publie des messages retenus fixes,
dont des données sensibles. Il s'applique à `mqtt_broker` vulnérable sauf
source 21. En 06:41–81, vérification du port, de la config et publication puis
lecture locale du topic `verify/test`. Cela prouve cette opération locale,
pas la lecture privée fraîche sur une ACL particulière depuis l'auditeur.
En 06:597–630, le contrôle MQTT hardened/near_miss transforme tout échec de
souscription en `OK` : timeout, absence de message et refus ne sont pas tous
distingués. Les témoins du pilote MQTT sont plus exigeants que ce contrôle.

Pour une nouvelle propriété sur le rôle MQTT existant, le travail requis serait :

1. Fixer l'opération exacte (lecture privée, publication ou effet d'une commande),
   sa portée et ses témoins ; définir key stable, faille/contrôle et matching.
2. Fournir une configuration et des données isolées correspondant à la propriété,
   sans les autres défauts parasites du rôle générique ; compléter l'injecteur
   et les profils vulnérable/durci/near_miss. Une nouvelle entrée dans un pack
   ne change pas automatiquement Mosquitto.
3. Ajouter les sondes de précontrôle positives/négatives et témoin légitime en
   06, compter tous les services attendus, conserver les erreurs et intégrer le
   verdict à `_verify_all_ok`. Qualifier ensuite séparément les preuves agent.
4. Réutiliser les validateurs MQTT existants s'ils couvrent exactement l'opération,
   sinon ajouter la règle de preuve et ses contre-exemples (public pris pour
   privé, mauvaise cible/topic, canari périmé, transport en échec). La lecture
   MQTT existante ne prouve pas une écriture ou un effet actionneur.
5. Si le rôle reste sous un profil manuel existant, mettre son contrat fournisseur
   en cohérence avec les nouvelles propriétés réellement injectées et vérifiées.
   Préserver l'ancien comportement exige un paramètre/profil explicite, pas un
   changement transversal non annoncé du rôle.

Pour **un nouveau rôle**, ajouter en plus : implémentation native ou simulateur
explicitement qualifié, installation/démarrage/cleanup, matrice
`tool_registry.py:ROLE_SERVICES` et outils effectifs, ciblage scanner/agent si
nécessaire, `strict_v3.py:ROLE_SERVICE_DEFAULTS` ou contrat explicite complet,
fournisseur et validation dans `manual_execution.py`, injection 04 et sondes 06.
Pour un preset officiel, topologie et inventaire Ansible doivent concorder ;
pour un manuel, l'overlay peut éviter cette duplication mais pas le besoin du
fournisseur. Une nouvelle technologie nécessite aussi un oracle, des contrôles
négatifs et une qualification runtime avant toute couverture revendiquée.

#### Conditions `source_scenario_id` à traiter selon le cas

Il ne faut **pas ajouter un nouvel id à toutes les listes** : seules les
capacités utilisées doivent être activées, avec leur vérificateur et leur
agrégation. Les numéros suivants sont ceux du code audité.

| Famille | 04 : gardes à examiner | 06 : gardes et consolidation correspondantes |
| --- | --- | --- |
| MQTT/web vulnérables génériques | 318, 377 : exclusion source 21 ; filtres rôle/profil | MQTT 41–81 et comptes `_mqtt_expected`/`_mqtt_results`/`_check_mqtt_ok` ; web et comptes associés. |
| WebSocket MQTT | 933 : sources **1,6** | Pas de qualification exhaustive de ce transport par la seule sonde MQTT 1883 ; prévoir le contrôle ciblé si retenu. |
| Extras historiques | 954 **6,7** ; 973 **4,6** ; 996 **4** ; 1005/1033 **3,7** ; 1077 **5** | 105 **3,7** (SUID) ; 373/386 **7** (fichiers bridge/cloud) ; `_privesc_expected` 1108. L'étendre dépend de l'extra, pas de la catégorie affichée. |
| VLAN S13 | 61–280 : **13** | Pas un module générique de VLAN ; coordonner aussi 03 et le contrôle de routage visé. |
| Durci/near_miss | 1583/1594 : **14,21,29** | 629 : même liste ; 1226–1230 `_check_s14_ok`, avec exception manuelle si zéro contrôle attendu. Étendre la liste d'injection seule oublierait les négatifs. |
| Pivots S20 | 1607/1617 : **20** | 850 et 1240 `_check_s20_ok` ; sonde spécifique à la fixture fixe. |
| Réseau held-out | 1630/1645 : **24–27** | 986 et 1244 ; paramétrage encore par id source. |
| Sparse dédié | 1658/1668 : **21** | 866 et 1241. Conserver l'exclusion des injecteurs génériques pour éviter les défauts parasites. |
| PKI | 1682–1742 : **16** | 709 et 1236 ; génération et diffusion des certificats liées à cette fixture. |
| Runtime simulateurs | 1759/1775 : **15,16,17,18,19,20,22,23,24,25,26,27,28** | 644 et 1232 : même liste ; garde comportementale propre à chaque source : 677/709/751/777/825/850/903/942/986/1027 et `_check_s15…s28_ok` 1235–1245. |
| Retrait bootstrap | 1788 : **20,24–27** | Les contrôles de connectivité/isolation correspondants doivent rester cohérents ; un bootstrap conservé peut court-circuiter la chaîne. |

Un manuel `flat_roles` garde aujourd'hui la source 14 : pas besoin d'ajouter son
id `gen-custom-*` aux listes 14/21/29. Même principe pour sources 15/20. En
revanche, créer un **nouveau profil source** ou de nouveaux ids officiels impose
de modifier ces gardes ou de remplacer ce dispatch par des capacités explicites,
ce qui serait un chantier ultérieur soumis à validation.

**Coût relatif, déduit des couplages, pas estimé en jours :** faible à modéré pour
paramétrer une propriété déjà prouvable sur un fournisseur existant ; modéré
pour une nouvelle propriété MQTT avec fixture/oracle/contre-exemples ; élevé
pour un rôle/protocole nouveau ; élevé pour une composition causale générique,
car elle traverse spec, fournisseurs, exécution et évaluation. Chaque ajout
comporte au minimum définition, matérialisation, précontrôle, preuve, tests et
documentation ; le laboratoire resterait une étape distincte à autoriser.

### 10.4 Inventaire des expériences et réemploi comme pilotes

Inventaire des **sources suivies** sous `benchmarks/experiments/`, en excluant
`__pycache__` (artefacts locaux, pas des expériences supplémentaires) :

| Ensemble | Fichiers / responsabilités | Réemploi et limites |
| --- | --- | --- |
| SSH | `ssh-reference/README.md`, `briefing.example.json`, `fixture/start.py` ; `ssh_reference.py` contrat/oracle/D1 ; `ssh_reference_llm.py` boucle et enregistreur ; `ssh_reference_live.py` orchestration ; `ssh_reference_proxmox.py` adaptateur Ansible. | Pilote focalisé d'accès SSH et lecture privée ; pas de preuve de privilège root ou de pivot. |
| MQTT | Même organisation sous `mqtt-reference/` et modules `mqtt_reference{,_llm,_live,_proxmox}.py`. | Pilote focalisé de confidentialité MQTT, avec témoins publics/privés et ACL différentielle ; ne qualifie ni publication ni commande appliquée. |
| API | `api-reference/README.md`, briefing et fixture ; modules `api_reference{,_llm,_live,_proxmox}.py`. | Pilote d'autorisation objet/collection paramétrique ; fournisseur HTTP commun, ids renouvelés. Étude de couverture de la baseline déclarée. |
| V0 | `v0_control.py`, `v0_control_llm.py`, `v0_control_live.py`, `v0-control-manifest.json`. | Réutilise fixture/adaptateur MQTT pour vérifier fidélité à une procédure publique ; porte de validité instrumentale, pas hypothèse de gain LLM. |
| Formats MQTT H2 | `mqtt_formats.py`, `mqtt_formats_llm.py`, `mqtt_formats_live.py`, `mqtt-formats-corpus.json`. | Dossiers figés, 8 fixtures, vues brute/normalisée ; règles déclarées, règles par conventions et LLM ; mesure M-I. Aucun broker ni collecte réseau dans ce harnais ; utile pour l'interprétation, pas une nouvelle brique de compromission. |
| Campagne V2 | `v2_campaign.py`. | Identité campagne/essai/famille/posture, ordre contrebalancé, admission de paire/campagne, bilan par posture et configuration. Pas un lanceur de scénarios. |
| Pilote historique | `policy-comparison/{README.md,pilot.example.json,pilot-2026-10.json,pilot-2026-10-preflight.md,reconciliation-2026-10-16.json,offline-review-2026-10-16.json,review.csv,next-trial.txt}`. | S1/S14/S15/S1h, plan gelé et tentatives réconciliées ; `blocked-new-freeze-required`. Réutiliser la méthode de gel/revue, pas réécrire le manifeste ou fusionner ses observations avec V2. |
| Revue hors ligne | `research-review/{README.md,inventory.py,probe-context.py,probe-evaluation.py,coverage_snapshot.py}`. | Inventaires/empreintes/contre-exemples, pas des fixtures de sécurité déployables. Les probes historiques décrivent leurs révisions et ne sont pas une validation du code actuel. |

Les contrôleurs invités associés sont sous
`benchmarks/ansible/files/{ssh,mqtt,api}_reference_proxmox.py` et leurs playbooks
sous `playbooks/{ssh,mqtt,api}_reference.yml`, hors du dossier experiments. Ils
allouent les LXC natifs dans **7000–7099**, avec adresses de fixture
`192.168.100.220–239`, vérifications d'identité/collision/propriété. Ces plages
s'ajoutent à celles des scénarios et variantes ; elles ne sont pas proposées
pour de nouveaux scénarios dans cet audit. Aucun de ces contrôleurs n'a été lancé.

#### Propriétés et oracles des quatre pilotes demandés

| Pilote | Fixture / variation | Preuve exigée côté oracle | Ce qui est réutilisable |
| --- | --- | --- | --- |
| SSH `s_ssh_identifiants` | OpenSSH natif port 2222 ; compte témoin et trois comptes du dictionnaire public. F1 : un mot de passe du dictionnaire accepté, choisi par la fixture ; F0 : aucun. Fichier privé et canari frais, compte témoin distinct, paramètres sans forwarding. | `ssh_reference.py:evaluate_trial` lie appel `ssh_exec` provenant du runner, hôte/port/user/password, commande exacte, identité exécutée et lecture du même objet au hash privé. F0 exige témoin valide et refus pour tout le dictionnaire ; connexion ou texte de succès seuls insuffisants. | Frontière d'exécution commune, vérification de session/objet, précontrôles avant/après, fixture jetable et archives. Ne pas transformer cette preuve en preuve d'accès administratif. |
| MQTT `s_mqtt_lecture` | Mosquitto réel, messages retenus privés/publics frais ; F0/F1 ne diffèrent que par une ligne d'ACL de lecture privée anonyme. `allow_anonymous true` existe dans les deux : connexion anonyme ≠ lecture privée. Pas de persistance disque. | `mqtt_reference.py:evaluate_trial` lie broker/port/topic/credential, observation MQTT structurée et hash du canari frais. D1 effectue témoin privé authentifié, lecture publique anonyme, sonde privée anonyme. F0 exige témoins valides et refus ou fenêtre bornée sans livraison privée ; pas de succès déduit du silence isolé. | Meilleur point de départ pour une brique MQTT focalisée et son contrôle near_miss « connexion/publique autorisée mais privé refusé », à formaliser comme variante distincte avant intégration au catalogue. |
| API `s_api_organisations` | Fixture HTTP 8080 ; organisations, utilisateurs, objets et collections paramétrés ; posture différente par le filtrage du membre étranger d'une collection autorisée. Routes documentées dans le contrat public v2. | `api_reference.py:evaluate_trial` recalcule `object_own`, `object_foreign`, `collection_own`, `collection_cross`, canari frais privé et témoin propre à l'organisation, politique/inventaire et appels liés à la cible. Un simple 200 ou une déclaration finale ne prouve pas une fuite. | Paramétrisation des identités, oracles d'autorisation et journal HTTP commun. Le D1 existant parcourt les objets mais pas les collections : conserver cette limite visible si on réutilise la comparaison. |
| V0 `v0_fidelite_mqtt` | Réutilise la fixture MQTT protégée ; procédure publique alternant lectures privée authentifiée/publique ; 8/16/24 étapes sélectionnables au workflow, 24 au manifeste courant. Même fixture partagée par les deux bras d'une répétition, créée/fermée autour de celle-ci ; pas un LXC neuf par bras comme SSH/MQTT/API. | `v0_control.py:evaluate_trial` exige une référence distincte d'observation par étape dans l'ordre déclaré, requête liée et payload au hash attendu ; compte étapes sautées, payloads erronés et références surnuméraires. `gate` distingue `valid_control`, `instrument_defect`, `competence_or_omitted_coverage`, `out_of_scope`. | Test préalable de fidélité et de clôture des preuves, pas scénario de faille additionnel ni test d'adaptation causale. |

SSH/MQTT/API distinguent résultat manquant (`unknown`), constat sans preuve,
faux positif et contradiction d'oracle (`oracle_conflict`). Si une fuite réelle
est observée sous oracle protégé, ce dernier est contradictoire : ne pas compter
ce cas comme succès ou simple faux positif de l'auditeur. Le briefing public ne
contient pas la posture ni les canaris privés ; les secrets de contrôle publics
sont séparés des secrets de fixture. Les références sont recoupées avec le journal,
pas crues parce que la politique les cite.

Les modules `*_live.py` gèrent précontrôles, exécution bornée, coûts et
archivage ; les README attestent des qualifications déjà obtenues, mais cet
audit ne les reproduit pas. `v0-control-manifest.json` déclare un seuil X=0,9
figé le 21 octobre, trois répétitions réussies dans chaque bras et une limite
de saturation explicite ; c'est une déclaration versionnée avec référence de
run, pas une nouvelle observation de cet audit.

#### Workflows correspondants et séparation avec strict-v3

Les quatre workflows s'exécutent sur **`[self-hosted, nato-master]`**, prennent
`/var/lib/lance/lab.lock`, vérifient la branche `dev/2`, le checkout servi
`/opt/lance-dev-2` au SHA attendu et la configuration de l'instance. Fournisseur
fixé `ollama-umons`, choix dans le panneau Qwen/Gemma déclaré, sans repli.

- `mqtt-reference.yml` et `api-reference.yml` : `workflow_dispatch` direct,
  1–3 répétitions ; respectivement 8 appels/12 tours et 16 appels/16 tours.
- `ssh-reference.yml` : **`workflow_call`**, appelé par l'intégrité sur demande
  manuelle SSH ; vérifie que l'événement appelant est bien manuel et dev/2.
  8 appels/12 tours, 1–3 répétitions par l'entrée exposée.
- Les trois ont recovery sous `if: always()`, puis seal et summary ; le statut
  du recovery est conservé. Preuves privées sur nato, sans téléversement de
  l'ensemble brut par ces workflows.
- `v0-control.yml` : manuel ; plafond d'appels égal au nombre d'étapes, tours
  égal étapes+8 (réserve de clôture et routage). Nettoyage/résumé final en
  `always()` mais commandes tolérant l'échec (`|| true`) : ne pas prendre un
  job vert comme attestation de nettoyage ou de validité du contrôle.
- Les timeouts extérieurs sont des gardes de processus ; coût et durée sont
  mesurés, sans plafond financier/temporel des bras de ces pilotes.

**Ils ne passent pas automatiquement par le scoring historique.** Leurs
`evaluate_trial` rendent des verdicts de calibration et exposent
`mt_admissible: false`, `evidence_only_not_admitted`. Dans
`v2_campaign.py:campaign_admission`, `strict_v3_metrics_adopted` reste une
condition nommée, avec parité, complétude, postures, répétitions et familles.
Trois répétitions d'une seule fixture ne créent pas deux familles indépendantes.
Réutiliser fixture, adaptateur et oracle est possible ; les intégrer au pipeline
complet exige encore le branchement des preuves et un contrat de mesure explicite.
Leurs règles locales n'ajoutent aucun crédit implicite à `strict-v3.16/evidence-v16`.

### 10.5 Identifiants non numériques : travail nécessaire et compatibilité

Il existe déjà des ids textuels **hors catalogue officiel** (logiques `s_...`,
`flat-logical-chain`, exports `gen-*`). Cela démontre une capacité partielle des
bundles et de l'évaluateur à les transporter ; pas une prise en charge complète
dans le catalogue public et le dispatch Ansible.

| Contrat / composant | Adaptation nécessaire avant ids officiels textuels |
| --- | --- |
| `catalog.py:load_catalog`, `get`, `resolve_selector`, `public_scenario_split` | Remplacer l'obligation numérique et le tri `int(id)` par un identifiant canonique validé et un ordre déterministe ; lookup exact avant les alias S ; ne plus déduire le parent d'une regex numérique. Préserver S1/S1h explicitement et la casse décidée. Un id commençant par `s` ne doit pas perdre sa première lettre via `removeprefix('s')`. |
| Sélecteurs | Réserver `all/dev/test/public/eval` ou définir un échappement ; normaliser une seule fois, détecter collisions/casse, rejeter chemins absolus, séparateurs et traversées. Décider séparément label, catégorie, identité et variante : pas de parsing implicite de ces informations dans le nom. |
| Catalogue et assets | Définir le nouveau schéma de catalogue et sa version ; inscrire ids/splits et éventuellement un chemin relatif contrôlé, ou conserver provisoirement `S{id}.yaml` et `scenario_{id}.yaml`. Les noms textuels sans S ne sont pas trouvés par les glob `S*.yaml`. Toute nouvelle arborescence technologique exige de modifier les lecteurs concernés et leurs tests. |
| CLI/API/Scenario Lab | Réviser `batch.py` (branche `.isdigit()`, préfixe/tri), routes catalogue/runs, tris et affichage systématique S, résolveurs exports/manuels et regex ; adapter discovery des blueprints et alias sans casser `gen-*`. Définir une identité stable de fournisseur distincte du nom public. |
| Déploiement | `GeneratedScenarioDeployment.prepare` et `ManualScenarioDeployment.prepare` imposent encore un `source_sid.isdigit()`. Le pré-teardown de lifecycle fait `int(k)` sur les clés et a un fallback 1–10. Les gardes Ansible 03/04/06, regex de conflit, noms propriétaires et scripts dédiés doivent garder un dispatch compatible ou migrer ensemble vers des capacités/fournisseurs. Il faut éviter un nettoyage mal attribué après renommage. |
| `strict_v3.py` | Les conversions numériques repérées concernent surtout les **ports**, à conserver. Le matching d'une propriété n'exige pas un id numérique. En revanche, `matching_contract_path` suppose les dossiers `dev/test` et le préfixe `scenario_` ; changer ces chemins exige un résolveur explicite du sidecar avec même frontière d'intégrité. Ne pas confondre cette adaptation de stockage et une modification des règles de score. |
| `matching_contracts.yaml` / `evaluator.evaluate` | Les clés `scenarios` et `source_hashes` peuvent être des chaînes ; pas de réécriture nécessaire du moteur de matching uniquement pour leur type. Faire correspondre **exactement** l'id du YAML GT, les clés sidecar et les métadonnées ; recalculer le SHA-256 des octets de chaque nouvelle GT et les manifests/fingerprints dépendants. Une GT renommée sans mise à jour du sidecar est refusée ou introuvable. Garder les ids `key@device` cohérents avec les références de chemins si les noms d'appareils changent. |
| Sealed | `contracts.py:_sealed_scenario_id` et `routes/runs.py` conservent des bornes 20–25 et des repli historiques. Remplacer cette classification par le catalogue/profil de confiance, en conservant le comportement fail-closed. Les chemins `eval_profiles/S{id}.yaml` font aussi partie du contrat. |
| Données dérivées et historique | Mettre à jour index dérivé, manifests de nouvelles campagnes, imports DB/apprentissage et comparabilité. Conserver une table explicite ancien id→nouvelle identité/version ; ne pas réétiqueter silencieusement anciennes mesures ou anciennes GT sous leurs empreintes d'origine. |
| Validation | Tests de lookup/alias/casse/collisions/path safety, dev/test/sealed, CLI/API, sidecar partagé/export-local, hash périmé refusé, comparabilité/historique et mapping fournisseur. Vérifier aussi négatifs et versions attendues, puis validation GT et suite complète dans l'environnement prévu. |

Proposition de versionnement à discuter, **non appliquée** : un schéma catalogue
acceptant de nouveaux types d'ids mérite un bump explicite du schéma et une
nouvelle version du corpus si les identités publiques changent. Le sidecar
`strict-v3.2` peut conserver sa forme si seuls ses ids/hashes changent ; il ne
faut pas promettre une équivalence des anciennes/nouvelles mesures sans vérifier
leurs manifests. Aucun bump de `strict-v3.16/evidence-v16` n'est nécessaire par
principe pour une chaîne de caractères ; **un changement de preuve ou de crédit**,
notamment la causalité des dépendances, nécessitera une proposition de bump.

Une migration propre peut donc conserver temporairement les ids historiques
comme alias explicites et introduire les ids textuels dans une nouvelle version
de corpus. Cette possibilité reste un constat de faisabilité, pas une décision
prise pendant la phase 0b.

### 10.6 Tests locaux : cause établie et préparation de l'environnement validé

Constats effectués sans installation :

- Python système et `.venv/bin/python` annoncent **3.13.5**.
  `.venv/pyvenv.cfg` confirme une création par `/usr/bin/python3.13`, sans
  site-packages système. Aucun exécutable Python 3.12 trouvé sous `/usr/bin`
  lors de ce contrôle ; cela ne prouve pas son absence dans tout le système.
- Le Python système n'a pas pytest (constat de la phase 0). La `.venv` possède
  pytest **9.1.1**, mais **`paho-mqtt` et `pytest-xdist` sont absents**, bien
  qu'ils figurent dans `requirements.txt`. Le module `ansible` est également
  absent ; `ansible-core` est ajouté séparément par la CI, pas par requirements.
- `src/agent/tools/tool_loader.py:filter_unavailable_tools` appelle
  `importlib.util.find_spec` sur un module qualifié. Avec le parent `paho`
  absent, Python lève `ModuleNotFoundError` au lieu de retourner `None`.
  `Pipeline.__init__` échoue ainsi **avant les assertions métier** dans les
  tests qui construisent le pipeline. Ce mécanisme explique la large cascade
  observée ; il n'autorise pas à attribuer tous les échecs historiques à cette
  seule cause, puisque la suite de phase 0 a été interrompue.
- `pip check` dans la `.venv` dit « No broken requirements found » : cela ne
  signifie pas que tous les paquets de **requirements.txt** sont installés.
  Il vérifie les dépendances déclarées des distributions déjà présentes,
  sans comparer ce fichier d'entrée. Le contrôle des métadonnées package par
  package a établi les deux absences ci-dessus.
- Les versions installées des autres distributions listées satisfont les
  bornes de requirements au moment de l'audit. Cela ne prouve pas leur
  compatibilité d'API ni l'égalité avec une ancienne CI. Python 3.13 est un
  écart à l'environnement validé, **pas une cause démontrée** du premier échec.

La référence du dépôt et `benchmark-integrity.yml` utilisent **Python 3.12**,
installation de `requirements.txt` + `ansible-core`, collections depuis
`benchmarks/ansible/requirements.yml`, puis tests avec désactivation de l'autoload
pytest et xdist explicitement chargé. `requirements.txt` utilise surtout des
bornes minimales, pas un lockfile exact : reconstruire cet environnement aujourd'hui
ne garantit pas de retrouver toutes les versions du dernier run vert. Il faut
conserver le relevé des versions résolues et l'associer à la validation suivante.

**Procédure à exécuter seulement après accord d'installation** (aucune de ces
commandes de préparation n'a été lancée) :

```bash
# Prérequis : fournir un Python 3.12 par le mécanisme système autorisé.
# Créer un environnement séparé ; conserver la .venv actuelle pour diagnostic.
python3.12 -m venv .venv-py312
.venv-py312/bin/python -m pip install --upgrade pip
.venv-py312/bin/python -m pip install -r requirements.txt ansible-core
.venv-py312/bin/ansible-galaxy collection install -r benchmarks/ansible/requirements.yml
.venv-py312/bin/python -m pip check
.venv-py312/bin/python --version
.venv-py312/bin/python -m pip freeze

# Validations locales après préparation ; aucune commande de laboratoire.
PYTHONDONTWRITEBYTECODE=1 .venv-py312/bin/python benchmarks/tools/compose_gt.py --validate
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  .venv-py312/bin/python -m pytest --rootdir=. -q -p no:cacheprovider tests
# Variante CI : application + entraînement, quatre workers explicitement chargés.
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  .venv-py312/bin/python -m pytest --rootdir=. -q -p no:cacheprovider \
  tests model_training/tests -p xdist -n 4
```

La création du venv, pip et Ansible Galaxy peuvent écrire hors du seul rapport
et télécharger des dépendances : ils restent suspendus à l'accord demandé par
la consigne, sans tentative de contournement. Les tests ayant besoin d'une
écoute locale doivent être distingués d'un accès au laboratoire ; en cas de
refus du sandbox, documenter ce refus avant d'évaluer leur résultat. Même après
installation, une suite verte devra être observée, jamais présumée.

### 10.7 Validation de ce complément et arrêt

Dernière révision du complément : **2026-10-23 15:11:52 CEST (Europe/Brussels, UTC+0200)**.

- `compose_gt.py --validate` relancé sans écriture de GT : **exit 0**,
  31 vérités terrain, mêmes `LEGACY-DIFF` S1–S13.
- Reproduction ciblée avec `PYTHONDONTWRITEBYTECODE=1`, cache pytest désactivé,
  `tests/pipeline/test_analysis_aggregation.py -x --tb=short` : **1 échec**,
  `ModuleNotFoundError: paho` en 0,51 s, avant les assertions. La suite
  complète n'a pas été relancée dans cet environnement déjà incomplet ;
  aucune validation verte n'est revendiquée.
- `git diff --check` et contrôle whitespace du rapport via
  `git diff --no-index --check /dev/null` : aucun défaut signalé. Les liens
  locaux du rapport ont été vérifiés. L'arbre Git ne présente toujours que
  ce fichier de rapport ajouté ; aucun changement suivi ailleurs.
- Aucun paquet installé, aucun environnement créé, aucun contrat ou scénario
  modifié. Les procédures d'installation et d'évolution ci-dessus sont
  documentées pour décision, pas exécutées.

Précision de lecture V2 : les notes historiques conservent un ancien ordre
API/reprise/cache, remplacé dans l'avancement courant ; les prérequis ET/OU
sont décrits mais leur contraste comparatif n'est pas automatiquement admis
comme traitement sélectionné. Ces mentions ne sont pas des autorisations de
réalisation supplémentaires.

**Arrêt de la phase 0b. Aucune phase suivante engagée.**
