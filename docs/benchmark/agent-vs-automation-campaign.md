# Campagne D1/A1 : préparation, bilan et revue

L'outillage de campagne prépare le pilote de **24 exécutions** et calcule son
bilan à partir d'artefacts existants, sans déployer ni lancer d'audit. Le
parcours guidé décrit plus bas orchestre quant à lui une paire réelle.
Le [protocole](../../research/2026-09-27-agent-vs-automation/protocol.md) fixe les questions scientifiques ; le
[guide CLI](agent-vs-automation-cli.md) décrit l'exécution d'un bras.

Le [bilan du 15 octobre 2026](../../research/2026-09-27-agent-vs-automation/README.md#automatisations-et-comparaison-guidée--15-octobre-2026)
conserve l'implémentation du parcours guidé, les incidents et une paire
exploratoire réelle S1 avec Qwen 3.8 27B. Ce résultat unique ne valide pas une
campagne ni une supériorité générale du modèle.

## Structure et responsabilités

```text
src/agent/phases/verification/rules.py       décisions D1 et reprises bornées
src/benchmark/compare_policies.py           évaluation d'une paire D1/A1
src/benchmark/policy_campaign.py            bilan de tous les essais prévus
benchmarks/experiments/policy-comparison/
  pilot.example.json                       plan de 12 paires, encore à préparer
  review.csv                               grille de revue indépendante
  README.md                                mode d'emploi des modèles
research/2026-09-27-agent-vs-automation/
  protocol.md                              protocole scientifique proposé
  state-of-the-art.md                      références et choix méthodologiques
  implementation-plan.md                   plan et suivi des lots logiciels
docs/benchmark/
  agent-vs-automation-campaign.md            ce guide opérationnel
tests/test_audit_policy.py                  vérifications logicielles hors ligne
output/                                    artefacts locaux, ignorés par Git
```

L'agent ne lit ni le manifeste de campagne ni les vérités terrain. Il reçoit
l'inventaire public validé du guide CLI. Les outils, limites et validateurs de
preuve restent communs. Aucun pipeline parallèle n'est créé pour D1.

## Mise à jour sur nato

La cible est **nato / pve-nato**. Le **homelab personnel est exclu** des transferts,
déploiements et audits de cette campagne, même si un inventaire local y pointe.
Respecter la [consigne de ciblage du dépôt](../../AGENTS.md) ; un accès à nato
indisponible ne justifie pas un repli vers le homelab.

Un push de code sur `main` déclenche les contrôles complets de
[Benchmark integrity](../../.github/workflows/benchmark-integrity.yml).
Les changements uniquement documentaires suivent le
[parcours CI léger](../guides/development-instances.md#validation-ci-selon-les-fichiers-modifiés)
sans déploiement ; une exécution manuelle conserve tous les contrôles.
Après réussite des tests et de la construction de l'image isolée, le workflow
[Update LANCE instance](../../.github/workflows/update-master.yml) s'exécute sur le
runner `nato-master` de `pve-nato` : récupération du commit exact, mise à jour des
dépendances et redémarrage de LANCE. Un accès SSH depuis le poste de développement
n'est donc pas requis pour cette publication. La réussite du job de déploiement
doit être vérifiée dans GitHub Actions.

Les [instances de développement](../guides/development-instances.md) utilisent
le même laboratoire avec une réservation commune. Pour une campagne CLI,
charger également `LANCE_LAB_LOCK=/var/lib/lance/lab.lock` et
`LANCE_DEPLOYMENT_ROOT=/opt/nato-smartcity-iot/output/scenario_deployments`.

Ce déploiement **ne lance pas la campagne**. Le périmètre D1/A1 est accessible
par CLI ou par le parcours d’une paire décrit ci-dessous. L'inventaire Ansible
local d'une autre machine ne détermine pas la destination du runner.

## Comparer une paire depuis l’interface

Dans **Automatisations → Comparer règles / LLM**, choisir un scénario public et
un modèle disponible dans le registre. Le formulaire affiche le réseau et le
nombre d’équipements TCP publics. Ce parcours n’applique aucun plafond de durée
ou de coût, ni de délai maximal d’analyse par équipement. La durée et l’usage
restent mesurés. Le nombre maximal d’appels d’outils est prérempli à 200 par
audit ; il est ajustable, ainsi que l’ordre règles/LLM. Le bouton d’arrêt
interrompt les deux audits et déclenche le nettoyage.

L’API exige `max_duration_s=null` et `max_cost_usd=null` (ou leur absence).
Le contrôleur active explicitement `comparison_unlimited` pour les deux
workers ; ce choix et l’absence de délai par équipement sont archivés et
contrôlés par le comparateur. Les autres modes, expériences CLI et campagnes
conservent leurs contrats et leurs limites. Les délais techniques des requêtes
réseau restent applicables. Les résultats historiques conservent leurs plafonds
d’origine dans l’affichage et les exports.

**Lancer la comparaison** appelle `POST /api/pipeline/start` avec
`runner_kind="comparison"`. Le coordinateur applicatif n’autorise qu’une
opération active par instance ; la réservation commune du labo couvre les deux
bras, le nettoyage, l’évaluation et la publication du résultat terminal. Le
contrôleur annonce l’état inactif avant de libérer cette réservation, pour
permettre un déploiement en attente. Le lancement exige le contrôleur nato, la réservation
configurée, Ansible/Nmap et une vérification SSH de l’identité `nato` ou
`pve-nato` avant toute modification. Aucun repli vers un autre labo n’est prévu.

Le contrôleur supprime explicitement le scénario avant **chaque** déploiement,
puis réutilise les playbooks de déploiement, injection et vérification existants.
Il sonde les ports TCP déclarés publiquement pour chaque rôle, conserve les
observations et impose une surface identique avant le second audit. Une sonde
incomplète ou un équipement TCP inaccessible bloque ce bras. Le parcours exige
une topologie dont chaque équipement possède des services TCP publics connus,
dans un même /24 ; les topologies non résolues ou multi-sous-réseaux ne sont pas
proposées. Il ne constitue pas un inventaire exhaustif de tous les ports.

Les deux workers `Pipeline` reçoivent exactement le même inventaire validé et
les mêmes limites : `analysis-verification`, profil `full`, phases `[3,4]`,
un worker, mémoire persistante désactivée et connaissances CVE figées. Seul le
bras LLM construit un fournisseur. Le contrôleur conserve les identités du
scénario et de la préparation séparément ; aucune vérité terrain n’est fournie
aux workers. Après leur fin, il nettoie le scénario dans la réservation commune,
puis appelle `compare_runs`, le comparateur CLI existant. Cette évaluation après
nettoyage ne lance aucun outil réseau.

Les résultats affichent confirmations correctes, confirmations incorrectes,
manqués, précision, rappel, F1, spécificité et ressources par bras. Les écarts
LLM−règles sont affichés uniquement si le comparateur accepte la paire. Une
paire incomplète conserve ses bras présents et ses motifs, sans classement.
Les mesures absentes et le F1 indéfini d’un contrôle sain restent distincts de
zéro. Les durées des audits excluent attente, préparation et nettoyage ; les
coûts concernent l’usage LLM déclaré ou estimé, hors infrastructure et travail
humain. Un échec de nettoyage reste visible même si les audits sont comparables.

`GET /api/comparisons/options` fournit les choix et la disponibilité du
contrôleur ; `GET /api/comparisons` fournit l’historique paginé (10 par défaut,
50 maximum), et `GET /api/comparisons/{id}` les étapes et résultats. Le lien
`/#comparison/{id}` rouvre la paire ; `/{id}/download` sous l’API exporte son
JSON. Les artefacts de contrôle sont conservés dans
`output/policy_comparisons/{id}/` : identité et étapes `pair.json`, inventaire
commun, précontrôles datés, sondes et journaux de préparation. Les dossiers
d’audit restent dans `output/agent/`. Les demandes d’arrêt utilisent le mécanisme
coopératif commun et nécessitent une session administrateur.

Ce parcours crée **un essai déclaré par lancement**, sans remplacer les essais
échoués ni lancer automatiquement une campagne ou une répétition. Les
précontrôles couvrent les playbooks et la surface TCP publique, sans attester
toutes les propriétés de la vérité terrain ni l’indépendance des scénarios.
L’empreinte de configuration ne certifie pas l’état complet du système. La
revue indépendante, les répétitions, l’alternance et l’analyse par famille
restent nécessaires avant une conclusion scientifique.

## Décisions D1 en phase 4

La version `shared-scanner-bounded-verification-v2` réutilise la phase d'analyse
déterministe et les plans de vérification existants. Pour chaque candidat :

| Observation | Décision |
| --- | --- |
| Plan absent, arguments incomplets ou outil indisponible | Arrêt indéterminé et erreur de couverture explicite. |
| Preuve confirmée par le validateur commun | Arrêt, sans sonde supplémentaire. |
| Timeout, connexion réinitialisée, HTTP 408/502/503/504 ou erreur transitoire reconnue de l'adaptateur | Une reprise au plus, seulement pour un outil admissible à la répétition. |
| Réponse de `http_get` ou `curl_headers` insuffisante pour confirmer, sans erreur ni statut HTTP négatif observé | Une requête structurée `http_request` sur la même URL, en GET anonyme sans redirection. |
| Refus 401/403, réponse négative, autre erreur, reprise déjà consommée ou preuve toujours insuffisante | Arrêt sans confirmation ; les erreurs techniques restent signalées. |

La reprise est permise pour `http_get`, `curl_headers`, `ssh_audit`, `tls_inspect`,
`ftp_list`, `http_request` en GET/HEAD sans corps et les écoutes MQTT sans
identifiants. Les requêtes de modification, essais d'identifiants et commandes
TCP arbitraires ne sont pas repris automatiquement. La lecture structurée ne
change ni l'URL ni l'identité et nécessite que l'outil soit disponible.

Une reprise et une lecture complémentaire au maximum donnent **trois appels par
candidat au plus** dans cette boucle, sous les budgets globaux. Ce plafond ne
comprend pas les scans de phase 3. Un arrêt, budget épuisé ou défaut d'archivage
interrompt la boucle. Chaque décision est enregistrée dans
`04_rules_decisions.jsonl`, avec la référence de l'observation du journal commun
`tool_calls.jsonl`. Le verdict final provient toujours du validateur de preuves.

Cette extension renforce une référence encore bornée ; elle n'invente pas de
plans pour les vulnérabilités non couvertes. La couverture et les connaissances
propres aux simulateurs restent à examiner avant toute conclusion générale.

## Préparer et figer le manifeste

Le [modèle](../../benchmarks/experiments/policy-comparison/pilot.example.json)
contient S1, S14, S15 et un contrôle sain à préparer, répétés trois fois chacun.
Il déclare toutes les paires avant exécution et alterne leur ordre. `family_id`
sert ici à grouper les situations ; ce libellé n'atteste pas leur indépendance.

1. Copier le modèle sous un nom de campagne dans le même dossier. Fixer
   `campaign_id`, les identifiants des essais, l'ordre et les vérités terrain.
   Préparer effectivement le contrôle sain : ne pas transformer artificiellement
   un scénario vulnérable en contrôle en vidant sa vérité terrain.
2. Compléter `configuration` avec `provider`, `model`, `rules_version`,
   `resource_manifest_sha256`, `execution_profile`, `max_tool_calls`,
   `max_duration_s` et `max_cost_usd` (éventuellement `null` pour ce dernier).
   Les valeurs doivent correspondre aux métadonnées produites par le CLI.
   L'empreinte des ressources se calcule avec
   `src.agent.audit_experiment.resource_manifest()` après gel du code.
   Le modèle vide est lisible, mais le bilan expose les champs non fixés dans
   `unfixed_configuration_fields` : il ne constitue pas un protocole gelé.
3. Préparer une entrée publique par paire. Son bloc `experiment` doit reprendre
   `id = campaign_id`, `trial_id`, `family_id`, `instance_id` et l'empreinte réelle
   de l'état initial. Garder exactement la même entrée pour les deux bras.
4. Sur demande explicite de laboratoire, contrôler et rétablir l'état avant
   chaque bras. Renseigner son `preflight.status` (`valid` ou `invalid`) et son
   `evidence_ref`, chemin vers un constat conservé. Si le précontrôle échoue,
   conserver l'essai prévu ; ne pas lancer l'audit puis attribuer son échec au
   laboratoire a posteriori.
5. Après les exécutions autorisées, renseigner chaque `run_dir`, même pour les
   échecs. Garder `null` pour un bras non exécuté. Un même dossier ne peut pas
   servir à deux essais. Toute nouvelle tentative exige une entrée distincte,
   sans remplacement des coûts ou artefacts de la première.

Le hash d'un constat de précontrôle assure sa traçabilité, pas sa validité.
L'outil ne vérifie ni son contenu ni sa chronologie, ni la remise à zéro réelle.
Conserver les manifestes successifs et les constats datés pour la revue humaine.
Les chemins sont relatifs au manifeste, jamais au répertoire courant du shell.

## Calculer le bilan hors ligne

Pour le pilote historique d'octobre, le [registre des tentatives réconciliées](../../benchmarks/experiments/policy-comparison/reconciliation-2026-10-16.json)
complète le plan gelé : 23 tentatives de campagne/calibration et les inspections
sont conservées sans remplacer les reprises. Le plan historique n'a pas été
rempli en choisissant un seul résultat pour les identifiants réexécutés.
Son bilan seul décrit ses références locales vides, pas l'activité réelle.
Les exports bruts récupérés restent dans `output/`, ignoré par Git.

Le registre se régénère depuis les téléchargements locaux, sans accès réseau,
modèle ou laboratoire :

```bash
python scripts/benchmark/reconcile_pilot.py \
  --source output/policy-comparison/reconciliation-2026-10-16 \
  --plan benchmarks/experiments/policy-comparison/pilot-2026-10.json \
  --output benchmarks/experiments/policy-comparison/reconciliation-2026-10-16.json
```

Le dossier source contient les inventaires Actions, les journaux et artefacts
par identifiant de workflow, et les copies de runs obtenues par les API nato.
Chaque copie de comparaison n'est admise que si les deux bras ont été lancés
dans cette tentative et si leurs références correspondent aux journaux.
Les essais annulés gardent des coûts inconnus lorsqu'aucune mesure n'existe.
Les précontrôles déclaratifs restent distincts d'une revue humaine.

Depuis la racine du dépôt, le modèle vide peut déjà être inspecté :

```bash
python -m src.benchmark.policy_campaign \
  --manifest benchmarks/experiments/policy-comparison/pilot.example.json \
  --output output/policy-comparison/pilot-summary.json \
  --csv output/policy-comparison/pilot-trials.csv
```

Il doit donner **12 paires prévues, 24 bras non exécutés, zéro paire admissible**,
et des consommations inconnues (`null`), pas des coûts nuls mesurés. Utiliser
ensuite le manifeste réellement renseigné. Un code de sortie zéro signifie que
le bilan a été produit, pas que la campagne a réussi. Le JSON conserve le détail
des paires et motifs ; le CSV contient une ligne pour chaque bras prévu.

Le bilan distingue trois vues :

- **Opérationnelle** : nombre prévu, issues et fraction de bras exploitables sur
  tous les bras prévus, pour chaque politique. Aucun échec ou essai absent ne
  disparaît du dénominateur.
- **Ressources** : somme des consommations observées, y compris celles des échecs,
  nombre de bras renseignés et nombre prévu. `complete_total` reste inconnu si
  une consommation manque ou si une comptabilité est incomplète. Les coûts
  observés sont ceux du LLM ; infrastructure, développement et revue humaine
  ne sont pas chiffrés. La nature estimée et les sources de prix restent visibles.
- **Technique conditionnelle** : écarts A1−D1 uniquement sur les paires admissibles,
  séparés par configuration et situation. Les moyennes sont descriptives et
  pondèrent chaque paire également ; des nombres inégaux de répétitions exigent
  une analyse adaptée. Aucun F1 manquant ou indéfini n'est remplacé par zéro.

| Issue d'un bras | Signification |
| --- | --- |
| `usable` | Exécution achevée, artefacts évaluables, usage complet, identité conforme et précontrôle valide déclaré. Cela ne signifie pas que les vulnérabilités ont été trouvées. |
| `failed`, `partial`, `stopped`, `budget_exceeded` | Échec/arrêt déclaré ou budget observé dépassé ; les consommations disponibles restent comptées. |
| `not_run`, `running`, `missing_artifacts` | Exécution absente, en cours ou sans métadonnées lisibles. |
| `environment_invalid` | Précontrôle invalide documenté et aucun artefact d'audit détecté. |
| `protocol_violation` | Audit détecté malgré un précontrôle déclaré invalide. |
| `environment_unverified`, `configuration_mismatch` | Précontrôle non attesté par un fichier ou identité différente du plan. |
| `completed_unusable`, `unknown` | Exécution non exploitable pour l'évaluation ou état non reconnu ; consulter les motifs et le statut brut. |

Un bras peut être exploitable sans partenaire disponible ; aucune différence
appariée n'est alors calculée. Le comparateur vérifie aussi l'égalité des entrées,
ressources et contrats au sein de la paire. Des configurations distinctes ne
sont pas fusionnées dans la vue technique. Les scores éventuels des bras exclus
restent consultables mais ne sont pas des résultats de paires admissibles.

## Revue indépendante des preuves

L'évaluateur partage des validateurs avec l'agent. Une revue humaine doit donc
contrôler des observations brutes et l'état de référence de la cible, et ne pas
simplement relire les verdicts produits par ces mêmes validateurs.

Pour ce petit pilote, proposer avant exécution la revue de tous les constats
confirmés, de tous les désaccords D1/A1 et de toutes les alertes sur contrôles
sains. Ajouter un échantillon tiré au sort de constats rejetés ou indéterminés,
réparti entre les situations et politiques ; fixer sa taille avant de voir les
résultats. Un échantillon enrichi en désaccords ne donne pas directement un taux
d'erreur représentatif de toute la campagne.

L'opérateur prépare sous `output/policy-comparison/review/` des copies portant
des identifiants neutres : observation brute, requête effectivement exécutée,
propriété à vérifier et constat indépendant de l'état de la cible. Il retire
labels de politique, modèle, noms de dossiers révélateurs et verdict automatique.
Il conserve la correspondance originale dans un fichier séparé, inaccessible
aux relecteurs pendant la revue. **Cette préparation est manuelle** : le CSV
vide ne réalise aucune anonymisation et le contenu d'une trace peut encore
permettre de deviner la politique.

Le relecteur remplit [review.csv](../../benchmarks/experiments/policy-comparison/review.csv) :
`decision` vaut `supported`, `refuted` ou `indeterminate`, avec un motif et les
références consultées. Il examine cible, service, endpoint, autorisations et
preuve de la propriété annoncée. Prévoir un second avis sur les désaccords,
puis conserver l'arbitrage sans effacer les avis initiaux. Les nouvelles failles
hors vérité terrain suivent la même procédure pour les deux politiques.

## Ce que permettra le pilote

Le pilote sert à calibrer les budgets, vérifier les traces, détecter les lacunes
de D1 et observer les premières différences. Trois répétitions ne justifient
ni une puissance statistique ni une généralisation. Aucun intervalle de confiance
n'est calculé ici. D1/A1 mesure l'apport global de la politique LLM sur les phases
3–4 ; isoler l'adaptation demandera ensuite un bras A0 au plan figé et des
imprévus reproductibles. La revue humaine, l'inventaire des connaissances des
simulateurs et les variantes réservées restent du travail expérimental à mener.

## Workflow du pilote et conservation des preuves

Le [workflow pilote](../../.github/workflows/pilot-campaign.yml) exécute un essai
par `workflow_dispatch`, avec son `trial_id`. Un push ne lance plus d'audit.
Il conserve le verrou commun, sans annuler une exécution déjà en cours.
Son checkout propre sert uniquement à l'orchestration : l'agent est exécuté
depuis `/opt/nato-smartcity-iot`, après vérification de l'empreinte de ressources
déclarée dans le manifeste. Les changements d'orchestration ne modifient ni
`src/agent`, ni `src/benchmark`, ni les budgets et le modèle gelés.

S1 conserve le chemin `deploy.sh 1` utilisé pour sa calibration. S14 et S15
utilisent directement les playbooks du catalogue natif : nettoyage de la cible,
déploiement, injection, peuplement et vérification. S1h utilise un overlay propre
à la tentative, construit depuis la topologie S1 : mêmes VMID et adresses,
noms `s1h-*`, aucune faille routeur et profils MQTT/web/SSH durcis. Le fournisseur
de configuration et de vérification est celui des contrôles S14
(`source_scenario_id=14`), tandis que l'identité du scénario reste `1h`.
Un échec de playbook bloque les étapes suivantes. Les contrôles existants ne
certifient pas toutes les propriétés de la vérité terrain.

Chaque tentative écrit dans
`output/pilot-campaign/<trial_id>/<github_run_id>-<github_run_attempt>/`.
Elle garde les journaux de déploiement et de nettoyage, les précontrôles,
l'inventaire, les codes de sortie, les références des runs, les snapshots du
manifeste/scénario/vérité terrain et l'overlay effectivement utilisé. Les reprises
n'écrasent donc pas les essais précédents. Le nettoyage intervient aussi après
un échec de préparation ou de comparaison, avec les contrôles d'appartenance
des VMID des playbooks existants.

Après l'essai, y compris en cas d'échec, le
[support du pilote](../../scripts/benchmark/pilot_support.py) conserve sur nato :

```text
output/pilot-evidence/<trial_id>/<github_run_id>-<github_run_attempt>/
  evidence.tar.gz
  evidence-manifest.json
  comparison-<trial_id>.json    si la comparaison a été produite
```

L'archive contient la tentative et les dossiers complets des deux runs : traces
`tool_calls.jsonl`, scans, candidats, décisions, preuves, livrables et fichiers
cachés. Les dossiers interrompus sans métadonnées lisibles sont conservés ; un
bras absent reste explicitement absent. Le manifeste donne les chemins relatifs,
tailles et SHA-256 de chaque fichier et de l'archive. Les liens symboliques et
références hors du magasin de runs sont refusés. Les archives complètes restent
sur nato ; leur conservation n'est pas limitée aux 90 jours des artefacts Actions.

GitHub conserve seulement le manifeste d'empreintes, la comparaison et les
métadonnées/inventaires/coûts déjà publiés, limités à cette tentative. Les réponses
brutes des outils et l'archive complète ne sont pas téléversées. Les noms d'artefact
incluent l'identifiant du job et de la tentative ; leur rétention est de 90 jours.
Une archive complète permet une relecture et un recalcul ; elle ne transforme
pas une paire incomplète en résultat admissible.
