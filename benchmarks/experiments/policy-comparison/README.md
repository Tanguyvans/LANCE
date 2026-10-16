# Pilote D1/A1

## Campagne active et reprise

Le [plan gelé](pilot-2026-10.json) conserve les 12 paires prévues (S1, S14,
S15, S1h, trois répétitions). Le [registre réconcilié du 16 octobre](reconciliation-2026-10-16.json)
est le suivi opérationnel des tentatives déjà exécutées. Les chemins nuls du
plan historique ne signifient plus « aucun essai exécuté » ; le registre relie
chaque tentative à ses runs, artefacts Actions, précontrôles et ressources.

La réconciliation recense **15 tentatives de campagne et 8 de calibration**,
ainsi que 13 workflows d'inspection, dont six ont lancé un diagnostic isolé.
Sous le gel `b636f0a5…`, **8 tentatives de paires couvrent 7 des 12 paires
prévues** : trois comparables et cinq incomparables. S1 r1 a été exécutée
deux fois ; le second essai a atteint la durée limite et avait écrasé son
résumé dans le dossier partagé. Les deux essais restent distincts.

Les preuves des trois premières paires S1 sont retrouvées par l'API de nato :
six exports de runs, 214 fichiers, 725 entrées de journal d'outils ; les 18
fichiers de métadonnées publiés initialement sont identiques. Leur
comparabilité est recalculée hors ligne. La revue humaine de l'état initial
et des preuves reste à faire. Voir le [journal détaillé](pilot-2026-10-preflight.md#réconciliation-complète-du-16-octobre).

Restent sans exécution sous ce gel : **S15 r2–r3 et S1h r1–r3**.
`next-trial.txt` porte maintenant `blocked-new-freeze-required` : l'ancien
pointeur S14 r1 était périmé et le code courant ne correspond plus au gel.
Aucun nouveau run ni déploiement n'a été lancé pendant cette reprise.

## Poursuite V2 distincte du pilote historique

Le [plan V2 et son suivi](../../../research/2026-10-12-recentrage-corpus/README.md#avancement-consolidé)
conservent la sélection proposée et rattachent la qualification SSH native
réussie du 15 octobre. Cette qualification ne complète aucune paire manquante
ci-dessus et n’admet pas une campagne confirmatoire M-T.
**La prochaine réalisation V2 est `s_mqtt_lecture`** ; le blocage du manifeste
historique reste conservé dans son propre périmètre.

## Modèle générique

Ce dossier contient les **entrées de préparation** de l'expérience, pas ses
résultats ni un lanceur de laboratoire.

- [pilot.example.json](pilot.example.json) : 12 paires, soit 24 exécutions prévues
  (S1, S14, S15 et contrôle sain, trois répétitions). L'ordre est alterné et
  équilibré sur l'ensemble ; il n'est pas randomisé.
- [review.csv](review.csv) : grille vide pour la revue indépendante des preuves,
  sans colonne révélant la politique.

Le manifeste est un **modèle non gelé** : `configuration` est vide, les contrôles
préalables sont `pending` et les dossiers d'exécution sont `null`. Le contrôle
sain reste à préparer et sa vérité terrain est explicitement absente. Les quatre
groupes sont des situations de calibration, pas quatre familles indépendantes
permettant à elles seules une conclusion de généralisation.

Copier le modèle sous un nom de campagne dans ce même dossier, puis fixer modèle,
budgets et ressources avant exécution. Tous les chemins sont relatifs au fichier
manifeste ; un déplacement exige de les recalculer. Conserver le plan initial,
puis renseigner les références d'artefacts sans supprimer les essais échoués.
Les inventaires publics transmis à l'agent sont distincts de ce manifeste, qui
contient des chemins vers les vérités terrain privées de l'évaluateur.

Les sorties vont sous `output/`, déjà ignoré par Git. Les contrôles, remises à
zéro, audits et revues humaines ne sont pas exécutés par le calcul du bilan.
Voir le [guide de campagne](../../../docs/benchmark/agent-vs-automation-campaign.md)
pour les commandes, la matrice D1 et le protocole de revue.


## Artefacts récupérés le 16 octobre

Le blocage de téléchargement est levé après enregistrement des paramètres.
Le premier relevé de sept essais donnait trois paires S1 comparables et quatre
paires incomparables (S14 r1–r3, S15 r1 ; bras LLM à 200 appels). Le registre
complet ajoute la seconde tentative S1 r1, arrêtée à 1 800 s. Les anciens
artefacts cumulatifs ne sont pas comptés comme de nouvelles exécutions.
Voir le [journal détaillé](pilot-2026-10-preflight.md#récupération-des-artefacts-actions--2026-10-16).

## Manifeste historique et évolution de l'application

`pilot-2026-10.json` est le plan gelé du pilote d'octobre, distinct du modèle
`pilot.example.json`. Son empreinte de ressources d'audit
`b636f0a57a94badc6da6cbcda85656c31bf2a1e6b256d70bed1d411e6171f5c6`
et ses limites restent celles de ce plan. La livraison du catalogue et de la
comparaison guidée change les ressources applicatives ; elle ne constitue pas
une nouvelle version de ce pilote et ne requalifie pas ses anciens essais.

Le workflow `pilot-campaign.yml` refuse toujours une exécution si le checkout
servi ne correspond pas à l'empreinte du manifeste, avant de produire les
paramètres de déploiement. Ce pilote ne peut donc pas continuer sur le code
actuel sans un plan expérimental distinct. Pour reproduire le plan historique,
utiliser une révision compatible avec son empreinte ; pour une nouvelle
campagne, geler un autre manifeste et un nouvel identifiant, puis conserver
chaque version et ses artefacts. Ne pas remplacer l'empreinte historique pour
faire accepter les nouveaux runs.

`test_pilot_workflow.py` exerce le garde réel du workflow avec des ressources
conformes et différentes. Il vérifie le refus avant tout paramètre de
déploiement, plutôt que d'interdire toute évolution future du code de LANCE.


## Diagnostic d'archives sur nato

Le [relevé agrégé du 16 octobre](offline-review-2026-10-16.json), produit par le
[workflow 38905591684](https://github.com/Tanguyvans/LANCE/actions/runs/38905591684),
vérifie les cinq archives disponibles (483 fichiers). Il ne contient ni
arguments d'outils, ni réponses brutes, ni identifiants. S15 LLM consomme
199 appels en phase 3 et un en phase 4 ; les S14 consomment 175 à 182 appels
en phase 3. Le budget de 200 appels limite donc la vérification.
Voir le [diagnostic et la décision de reprise](pilot-2026-10-preflight.md#diagnostic-hors-ligne-sur-nato--2026-10-16).

Le lecteur se relance sur nato, sans réseau ni pipeline, avec :

```bash
python3 scripts/benchmark/pilot_archive_review.py \
  --evidence-root /opt/nato-smartcity-iot/output/pilot-evidence \
  --output /tmp/pilot-offline-review/summary.json
```

Seul le résumé agrégé peut être publié par `pilot-inspect.yml` ; les archives
complètes restent sur nato. L'absence d'archive ou une vérification en échec
font échouer le contrôle et restent visibles dans le résumé.
