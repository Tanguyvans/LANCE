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
    ├── analysis/               # Phase 3 : run, compact, aggregation, evidence, prompts
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
Voir la [rédaction du rapport](../../../docs/report-writing.md) pour les limites,
les fichiers produits et la reprise des fiches.

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

## Limites conservées explicitement

Les composants restent des mixins utilisant l'état du même `Pipeline`. Ce passage
clarifie la propriété du code ; il n'isole pas encore les phases dans des contextes
indépendants. Le runner coordonne encore certaines adaptations. Les livrables et
validateurs utilisent désormais un dossier explicite par run ; d'autres outils
conservent des états globaux, notamment le contexte de graphe et la politique CVE.
Ce ne sont pas six moteurs autonomes, ni une garantie de runs complets concurrents.

L'API, le CLI et les workers passent par `Pipeline`. Le worker fournit son dossier
parent via `Pipeline(output_dir=...)`, sans modifier une variable globale.
Voir le [contrat d'isolation des livrables](../../../docs/run-artifacts.md) pour
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
