# Un pipeline, organisé par phase

`src.agent.pipeline.Pipeline` reste le point d'entrée de l'API, du CLI et des
benchmarks. Il initialise le run, résout le profil de chaque modèle, vérifie
les prérequis et garantit la finalisation. `registry.run_phase` appelle un seul
`run(context, config, stream_callback)` par phase, pour les deux profils. Sa table
référence directement les six modules : aucun chemin d'import n'est construit
dynamiquement et il n'y a pas de système de plugins à maintenir.

```text
agent/
├── pipeline.py
├── execution_profiles.py       # Budgets, résolution du profil, sélection d'outils
├── core/
│   ├── runner.py               # Boucle modèle/outils, transactions, événements
│   ├── lifecycle.py            # Préparation, déploiement, nettoyage
│   ├── runtime.py              # Dépendances d'infrastructure et catalogue d'outils
│   ├── probes.py               # Sondes protocolaires communes aux phases 4 et 5
│   └── memo.py                 # Contrôles structurels des mémos Markdown
└── phases/
    ├── registry.py             # Routage par numéro de phase, pas par profil
    ├── graph/                  # Phase 1 : run.py, compact.py, recovery.py
    ├── recon/                  # Phase 2 : run.py, compact.py
    ├── analysis/               # Phase 3 : contexte, scan, appareils, sondes, agrégation
    ├── verification/           # Phase 4 : run, contract, evidence, prompts
    ├── intrusion/              # Phase 5 : run, compact, evidence, scope
    └── report/                 # Phase 6 : run, sections, context, rendering, validation…
```

Les éléments sous chaque phase sont des modules Python, pas des commandes shell
indépendantes. Chaque dossier contient son implémentation, pas une copie du moteur.

Les modèles de livrables sous `agent/templates/` portent directement le nom
configuré dans le registre : par exemple `06_report.md` pour le rapport. Le runner
n'a pas à compenser un ancien numéro de phase. La lecture des anciens rapports
enregistrés sous `05_report.md` reste prise en charge par l'application.

## Profils et responsabilités

- **Full** utilise le déroulement commun avec ses budgets et tous les outils
  autorisés par la phase. Il n'a plus de dossier de fichiers relais.
- **Compact** adapte la présentation des preuves, les outils et les budgets.
  Les guidages/récupérations spécifiques vivent dans le `compact.py` de la phase
  concernée. Une phase sans implémentation compacte distincte n'a pas ce fichier.
- **Paramètres** : modifier `execution_profiles.py` pour les budgets et le routage
  des outils ; ne pas recopier ces valeurs dans les phases.
- **Contrats et preuves** : modifier les fichiers de la phase concernée. Le contrat
  de vérification est commun : full reçoit ses exigences comme guidage, compact
  peut imposer leur exécution. Les règles d'intrusion compacte sont dans `scope.py`.
  Pour HTTP(S), le plan et les consignes partagent la construction de l'origine
  dans `verification/contract.py` : le service détermine HTTP ou HTTPS et un port
  explicite reste inchangé. Une consigne correctement ciblée n'est pas une preuve.
- **Infrastructure** : `core` porte le cycle de vie et les dépendances techniques,
  pas les règles métier des six phases.

Les conditions liées au moteur local restent inchangées. Choisir compact sur un
modèle distant n'active pas les récupérations locales ; utiliser un moteur local
avec full ne force pas compact. Le rapport utilise une rédaction par fiches
indépendantes et un assemblage déterministe, communs aux deux profils.
Voir la [rédaction du rapport](../../../docs/architecture/report-writing.md) pour les limites,
les fichiers produits et la reprise des fiches.

## Frontières d'exécution de la phase 3

`analysis/run.py` construit un `AnalysisContext` au début de la phase, après
l'application d'un éventuel changement de modèle. Il capture le fournisseur,
le profil, le dossier de run, les variables de prompt et les politiques.
L'exécution suit trois étapes explicites :

1. `scan.scan_phase` produit les observations et les erreurs de scanner.
   `supplemental.py` conserve les sondes mTLS, OTA et cloud dérivées de preuves
   déjà observées, avec leur provenance.
2. `devices.analyze_devices` prépare les prompts et appelle les analystes.
   Chaque worker renvoie un `DeviceResult` ; le coordinateur calcule les nombres
   de réussites et d'échecs. Les preuves intégrales du profil full, les mémos
   locaux en fichiers annexes et la récupération par blocs restent inchangés.
3. `run.aggregate_phase` appelle l'agrégation avec des entrées explicites puis
   valide le livrable. Il renvoie
   un `PhaseResult` avec statut, erreurs, références d'artefacts existants et
   consommation de cette phase (tokens, coût et durée). Les fichiers de diagnostic
   référencés ne sont pas des certifications ; le livrable principal n'est inclus
   dans ce résultat que si sa validation réussit.

Une agrégation valide conserve le statut partiel si un appareil, le scanner ou
l'inventaire a échoué. Une validation invalide donne un échec. Les budgets,
arrêts et erreurs d'archivage restent des interruptions propagées ; ils ne
deviennent pas des résultats partiels réussis. Le suivi de coût du worker est
fermé même lors d'une interruption.

`03_phase3_status.json` décrit le scan et les analyses par appareil ; le résultat
de validation de l'agrégat reste porté par le statut de phase. La registry et le
runner de compatibilité traduisent le résultat structuré vers les chaînes déjà
utilisées par l'API et le CLI. Les champs publics des événements sont conservés.
La politique `rules` n'appelle aucun modèle. Le dry-run renvoie `skipped` avant
toute découverte active, scan, analyse ou agrégation.

Les configurations internes personnalisées peuvent encore demander une
agrégation seule (`has_device_agents=False`) ou un agrégateur maître LLM
(`deterministic_aggregation=False`). Les méthodes `_run_phase3` et
`_aggregate_device_vulns` restent des adaptateurs internes, notamment pour la
découverte complémentaire après vérification. Le chemin courant de phase 3
n'utilise plus la boucle générique pour son agrégation déterministe.

## Reconnaissance et restitution

En profil complet (et hors adaptation locale compacte), `02_recon.md` est
construit par `recon/rendering.py` depuis les observations du journal d’outils.
Le modèle choisit toujours les sondes ; il ne recopie plus leur inventaire.
Une note de fin suffit à demander la sauvegarde. Si le dialogue se termine sans
sauvegarde, le contrôleur tente une seule sauvegarde locale, sans nouveau scan
ni appel au modèle, via les mêmes contrôles de couverture et de validation.

La finalisation exige le contrat de reconnaissance satisfait et des observations
exploitables. Un journal invalide ou absent ne donne pas un succès. Un arrêt
utilisateur reste un arrêt ; une exception fournisseur ou de budget n’est pas
convertie en réussite. Les échecs de sondes restent explicitement signalés,
même lorsque leurs tentatives répétées satisfont le contrat d’exécution.
Un inventaire généré n’est pas une certification de couverture exhaustive.
L’adaptation locale compacte conserve sa restitution et ses contrôles existants.

## Clôture d’intrusion et délais fournisseur

En profil complet, `save_deliverable` en phase 5 reçoit un petit marqueur de fin
(`{"finish":true}`), pas une copie de toute la campagne. Le contrôleur produit
le JSON depuis le journal, filtre les accès avec les règles communes de preuve
et valide la structure avant promotion. Le bilan porte `assessment.status=recorded`
et `objectives_status=not_certified` : finir l’évaluation ne certifie pas un accès,
un objectif ou un pivot. La projection actuelle ne reconstruit pas les transitions
réseau ; les traces originales restent disponibles. Sans signal de fin accepté,
les observations sont conservées mais la campagne reste incomplète. Les arrêts,
budgets et journaux invalides ne sont pas convertis en succès.

Un identifiant récupéré sans protocole déclaré porte `service: null` (jamais un
protocole deviné ni la chaîne `"None"`) ; les services connus sont conservés
tels quels et les valeurs malformées restent refusées. La découverte
d'identifiants ne constitue pas un accès corroboré. Un marqueur de fin soumis
puis refusé donne `failed:phase5_completion_invalid` ; seul un marqueur absent
donne `failed:phase5_completion_missing`. Un arrêt ou un budget épuisé gardent
leur cause d'interruption.

`LANCE_API_TIMEOUT_S` configure le délai maximal d’une requête (120 secondes par
défaut, 90 pour `local-moe`). Le délai effectif est le minimum de ce délai et du
temps restant dans la phase. `LANCE_PHASE3_DEVICE_TIMEOUT_S` conserve son plafond
global configurable (240 secondes par défaut). Un timeout réseau/SDK autorise au
plus une reprise de la même requête, sans rejouer les outils, uniquement s’il reste
du temps et du budget. Les reprises des autres erreurs transitoires restent
bornées par le mécanisme de transport existant.

### Agrégation et reprise des découvertes

`aggregation.capture_context` capture la surface et la topologie au moment de
l'agrégation, après les analystes : identité publique des appareils, rôles, liens,
profil compact, politique de décision, split du benchmark et catalogue d'outils.
Le cœur reçoit un `AggregationContext`, sans `Pipeline` ni callback métier.
Le traitement suit quatre étapes :

1. `aggregation_loading.load_inputs` lit les candidats dans un ordre stable,
   promeut les observations scanner admises par le profil et charge les preuves
   CVE/MQTT archivées ainsi que les identifiants du précédent agrégat.
2. `aggregation_normalization.normalize_candidates` travaille sur des copies,
   conserve le candidat avant la normalisation sémantique et inscrit les motifs
   d'exclusion dans le registre brut. Une CVE non vérifiée reste planifiable ; sa
   compatibilité pour le score reste distincte. Une incompatibilité explicite
   exclut la revendication de la file canonique.
3. `aggregation_projection.project_candidates` déduplique, conserve la provenance
   de chaque membre et reprend les identifiants existants. Ce stade utilise les
   preuves MQTT déjà chargées : il ne relit pas le disque et ne transfère pas la
   preuve du scanner au candidat modèle retenu dans un groupe MQTT.
4. `aggregation.render_projection` construit les résultats, puis
   `write_projection` écrit les fichiers `03_vuln_analysis.json`,
   `03_vuln_analysis_raw.json` et, en compact, `03_config_observations.json`.

La reprise de découverte conserve l'adaptateur `_aggregate_device_vulns` et ces
noms de fichiers, même lorsqu'elle est déclenchée depuis la phase 4. Le remapping
des identifiants `discovered-*` conserve son comportement historique : il utilise
les surfaces contenant une clé `nodes`, pas les surfaces représentées par une
liste. Le snapshot est local à cette agrégation ; sa capture dépend encore du
contexte global de graphe. Les étapes de normalisation et de projection modifient
les copies de travail et le registre de décisions reçus, sans modifier les
fichiers d'entrée ni les valeurs originales conservées dans `raw_finding`.

Limite PKI préexistante : la promotion d'une clé clonée compte les observations
de fingerprint, sans dédupliquer les identifiants d'appareil. Deux observations
identiques d'un seul `pki_device` peuvent donc produire une déclaration confirmée
de clé partagée. Le découpage conserve ce comportement ; sa correction exige un
test distinguant observations répétées et appareils distincts.

## Limites conservées explicitement

Les autres phases et plusieurs services de phase 3 restent des mixins utilisant
l'état du même `Pipeline`. La phase 3 rend ses dépendances visibles et ses étapes
testables avec un contexte explicite, mais les transactions, récupérations
et validations CVE locales utilisent encore des callbacks liés au moteur.
Ce contexte est construit pour une invocation de phase ; modifier le moteur
pendant cette invocation n'est pas pris en charge. Le runner coordonne encore
certaines adaptations des autres phases. Les livrables et
validateurs utilisent désormais un dossier explicite par run ; d'autres outils
conservent des états globaux, notamment le contexte de graphe.
Ce ne sont pas six moteurs autonomes, ni une garantie de runs complets concurrents.

La source CVE appartient au run (`cve_lookup_policy`) et le filtre de connaissances
à la configuration de la phase. La frontière d'exécution des outils les lie pour
chaque appel, y compris dans les threads des sous-agents, puis restaure le contexte
précédent. Créer un autre pipeline ne change plus ces politiques. Le passage CVE
compact applique la même liaison ; le snapshot figé ne dépend pas de ChromaDB.
Les setters de `tools/skill_tools.py` servent seulement aux appels autonomes dans
leur contexte, et ne configurent plus le pipeline.

Un scénario absent, sans topologie déclarée ou avec un fichier de topologie absent
échoue explicitement au chargement. Il ne se rabat pas sur le laboratoire physique.

L'API, le CLI et les workers passent par `Pipeline`. Le worker fournit son dossier
parent via `Pipeline(output_dir=...)`, sans modifier une variable globale.
Voir le [contrat d'isolation des livrables](../../../docs/architecture/run-artifacts.md) pour
les responsabilités, les exemples et les limites. Les helpers internes doivent être importés
depuis leur module propriétaire, pas depuis la façade. Les réexportations ajoutées
pendant la migration et les fichiers relais `agent/report_context.py` et
`agent/report_rendering.py` ont été retirés : seuls les tests les utilisaient.
Les anciens chemins internes `phases.shared`, `phases.full` et `phases.compact`
ont également été retirés.

Dans les tests, simuler les dépendances techniques via `src.agent.core.runtime`
et les règles métier dans leur module propriétaire. Les tests de structure
contrôlent le routage des deux profils, l'absence de fichiers relais et l'import
des phases sans passer par la façade.
