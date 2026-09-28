# Campagne D1/A1 : préparation, bilan et revue

Cette extension prépare le pilote de **24 exécutions** et calcule son bilan à
partir d'artefacts existants. Elle ne déploie rien et ne lance aucun audit.
Le [protocole](agent-vs-automation.md) fixe les questions scientifiques ; le
[guide CLI](agent-vs-automation-cli.md) décrit l'exécution d'un bras.

## Structure et responsabilités

```text
src/agent/phases/verification/rules.py       décisions D1 et reprises bornées
src/benchmark/compare_policies.py           évaluation d'une paire D1/A1
src/benchmark/policy_campaign.py            bilan de tous les essais prévus
benchmarks/experiments/policy-comparison/
  pilot.example.json                       plan de 12 paires, encore à préparer
  review.csv                               grille de revue indépendante
  README.md                                mode d'emploi des modèles
docs/benchmark/
  agent-vs-automation.md                    protocole scientifique
  agent-vs-automation-state-of-the-art.md    références et choix méthodologiques
  agent-vs-automation-campaign.md            ce guide opérationnel
tests/test_audit_policy.py                  vérifications logicielles hors ligne
output/                                    artefacts locaux, ignorés par Git
```

L'agent ne lit ni le manifeste de campagne ni les vérités terrain. Il reçoit
l'inventaire public validé du guide CLI. Les outils, limites et validateurs de
preuve restent communs. Aucun pipeline parallèle n'est créé pour D1.

## Mise à jour sur nato

Le push sur `main` déclenche [Benchmark integrity](../../.github/workflows/benchmark-integrity.yml).
Après réussite des tests et de la construction de l'image isolée, le workflow
[Update Master VM](../../.github/workflows/update-master.yml) s'exécute sur le
runner `nato-master` de `pve-nato` : récupération du commit exact, mise à jour des
dépendances et redémarrage de LANCE. Un accès SSH depuis le poste de développement
n'est donc pas requis pour cette publication. La réussite du job de déploiement
doit être vérifiée dans GitHub Actions.

Ce déploiement **ne lance pas la campagne**. Le périmètre D1/A1 reste accessible
par CLI, avec inventaire public, modèle et budgets renseignés. L'inventaire
Ansible local d'une autre machine ne détermine pas la destination du runner.

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
