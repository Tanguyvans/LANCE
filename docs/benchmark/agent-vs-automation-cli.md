# Comparaison règles / agent : premier incrément logiciel

Le CLI permet de comparer **D1 (`rules`) et A1 (`llm`) sur les phases 3 et 4** :
analyse puis vérification. Il utilise `Pipeline`, le scanner, les outils,
l'exécuteur, les agrégateurs et les validateurs de preuve existants. Le mode
`rules` ne construit aucun fournisseur LLM et ne consulte aucun catalogue de prix.
Les résultats restent à mesurer sur un laboratoire ; les tests locaux utilisent
des outils simulés et ne démontrent aucun avantage de l'IA.

Voir le [protocole scientifique](../../research/2026-09-27-agent-vs-automation/protocol.md) et le
[suivi d'implémentation](../../research/2026-09-27-agent-vs-automation/implementation-plan.md).

## Entrée publique commune

Préparer un fichier JSON **sans vérité terrain, liste de failles ni solution** :

```json
{
  "schema_version": 1,
  "provenance": "Inventaire public validé par l'opérateur avant la paire",
  "target_network": "192.0.2.0/24",
  "devices": [
    {
      "id": "web",
      "ip": "192.0.2.10",
      "services": [{"name": "http", "port": 80, "protocol": "tcp"}]
    }
  ],
  "experiment": {
    "id": "pilote-d1-a1",
    "family_id": "http",
    "instance_id": "instance-01",
    "trial_id": "repetition-01",
    "environment_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

Les adresses et l'empreinte ci-dessus sont des exemples. Remplacer l'empreinte
par le SHA-256 du manifeste réel de l'état initial du laboratoire. Le contrôleur
doit rétablir cet état avant chaque bras et conserver la même entrée pour la
paire. **Le logiciel vérifie l'égalité de la déclaration ; il n'atteste ni le
déploiement ni la remise à zéro.** Changer `trial_id` pour chaque répétition.

Chaque appareil exige un identifiant unique utilisable comme nom de fichier,
une IP unique dans le CIDR et des services avec nom et port. `role` et
`public_context` sont facultatifs. Le validateur refuse les champs inconnus,
mais ne peut pas déterminer si un texte présenté comme public contient un
indice privé : cette sélection relève du protocole expérimental.

Le CIDR définit le périmètre réseau autorisé. Les services constituent
l'inventaire initial, pas une liste restrictive de ports : certaines règles
existantes sondent aussi des ports ou chemins associés au protocole.

## Lancer les deux bras

Commandes à utiliser sur un laboratoire autorisé, après préparation explicite.
Les budgets ci-dessous illustrent la syntaxe ; ils ne sont pas calibrés par une
campagne. Aucun déploiement n'est déclenché par ce mode.

```bash
python -m src.agent --decision-policy rules \
  --experiment-scope analysis-verification --audit-inventory inventory.json \
  --execution-profile full --max-tool-calls 200 --max-duration-s 600 \
  --max-cost-usd 2

python -m src.agent --decision-policy llm --provider minimax --model MODELE_CHOISI \
  --experiment-scope analysis-verification --audit-inventory inventory.json \
  --execution-profile full --max-tool-calls 200 --max-duration-s 600 \
  --max-cost-usd 2
```

Rétablir l'état initial entre ces commandes et alterner/randomiser l'ordre selon
le protocole. Les deux runs créent des dossiers distincts sous `output/agent/`.
La première commande ignore les paramètres de fournisseur présents dans
l'environnement ; la seconde exige une configuration de fournisseur valide.

Ce mode impose le profil explicite `full`, les phases `[3, 4]` et un seul worker.
Il accepte `--phases 3 4`, sans ajouter les phases amont. L'inventaire validé
satisfait le prérequis d'entrée de la phase 3 : aucun faux livrable de
reconnaissance n'est créé. Il refuse les options scénario, batch, blind,
dry-run, split, target-network et les substitutions de modèle par phase.
Il désactive la mémoire persistante et utilise le catalogue CVE figé.
Les suivis de nouveaux hôtes après la phase 4 sont désactivés.

Les limites de durée et d'actions sont obligatoires. La durée est une limite
coopérative vérifiée entre opérations, également transmise aux appels modèle ;
une opération déjà en vol peut dépasser l'échéance. Le plafond monétaire est
fondé sur l'usage observé et peut aussi être dépassé par un appel en vol.
Un arrêt ou défaut d'archivage ne devient pas une preuve d'absence de faille.

## Ce que fait D1

La phase 3 utilise la matrice de scans, les suivis conditionnels à partir des
observations et les extracteurs existants, puis l'agrégation commune. A1 exécute
la même base déterministe et y ajoute les analyses et appels du modèle.

En phase 4, D1 part du plan de vérification et applique une
[matrice de décisions bornée](agent-vs-automation-campaign.md#décisions-d1-en-phase-4) :
une reprise sur erreur transitoire admissible et une lecture HTTP structurée
complémentaire au maximum, soit trois appels au plus par candidat. Une preuve
insuffisante reste non confirmée ; un plan indisponible est signalé. Les
confirmations viennent des traces d'exécution, avec les mêmes contrôles de
cible, endpoint et contenu que pour A1.

Les règles réutilisées contiennent des connaissances publiques propres aux
simulateurs : chemins, identifiants de test, versions de firmware et rôles
API/PKI/OTA/cloud. Les deux bras partagent cette base et son empreinte. Cette
version ne constitue donc pas un test indépendant de généralisation. Inventorier
ces connaissances et préparer les variantes avant une conclusion scientifique.

## Évaluer puis comparer une paire

La vérité terrain n'est fournie qu'au comparateur, après la fin des deux runs :

```bash
python -m src.benchmark.compare_policies \
  --rules-run output/agent/DOSSIER_D1 \
  --llm-run output/agent/DOSSIER_A1 \
  --ground-truth CHEMIN_VERITE_TERRAIN.yaml \
  --output comparaison.json
```

Le comparateur réexécute le même évaluateur `strict-v3` sur les deux dossiers.
Il conserve les scores de chaque bras et produit les écarts **A1 − D1** pour
les candidats, prédictions retenues, confirmations, erreurs, consommation LLM
et durée. Pour un contrôle sans faille, le F1 reste `null` et la spécificité
est séparée. Le coût par vrai positif confirmé reste `null` lorsqu'il n'y en a
aucun. Les coûts d'infrastructure, de développement et de revue humaine ne sont
pas mesurés.

La paire doit partager inventaire, instance, état déclaré, répétition, profil,
workers, budgets, ressources, outils indisponibles et contrats de preuve/mesure.
La politique, le fournisseur et le modèle sont les différences attendues.
Les runs incomplets ou artefacts insuffisants ne produisent aucun écart ; les
motifs restent exportés. On peut omettre un des deux arguments de run pour
consigner un bras manquant. Code de sortie : `0` pour une paire comparable,
`2` sinon. Les valeurs indisponibles ne sont pas remplacées par zéro.

Une paire n'autorise aucun intervalle de confiance par famille. Le
[bilan de campagne](agent-vs-automation-campaign.md) conserve désormais tous les
essais prévus, leurs issues et leurs coûts, avec des écarts descriptifs par
configuration et situation. Le calcul d'incertitude multi-familles, D0, A0 et
D1-R restent à implémenter. `aggregate.py` conserve son rôle d'agrégation au sein d'une
configuration et refuse de mélanger les politiques.

## Traces et compatibilité

- `audit_inventory.json` conserve l'entrée validée et `run_meta.json` son
  empreinte, la politique et les conditions expérimentales.
- `resource_manifest_sha256` couvre le contenu courant des ressources sous
  `src/agent` et `src/benchmark`, y compris les modifications non commitées,
  les prompts, compétences, règles et le catalogue CVE. Il ne constitue pas une
  empreinte de l'OS, des binaires externes ou du laboratoire.
- `tool_calls.jsonl` archive chaque appel traversant l'exécuteur, sa durée,
  sa source de décision et sa référence. Les appels du scanner sont aussi
  journalisés et reliés aux fichiers `03_scans`. Les projections dérivées d'une
  réponse conservent une référence d'origine et ne comptent pas comme un nouvel
  appel réseau.
- `04_rules_decisions.jsonl` relie chaque décision D1 de phase 4 à l'observation
  correspondante ; il ne remplace pas le journal brut des outils.
- `cost_summary.json`, schéma `3`, compte les appels de l'exécuteur une fois,
  y compris les refus et erreurs, indépendamment des tours modèle. La durée
  murale couvre l'exécution jusqu'à la finalisation des mesures.

L'identité expérimentale utilise `policy_schema_version: 1` et le journal
`execution_ledger_version: 2`. `provider` et `model` valent `null` en `rules`.
Les anciennes identités restent lisibles et séparées des nouvelles mesures.
Les contrats sémantiques courants `strict-v3.16` / `evidence-v15` ne sont pas assouplis.

L'API et l'interface ne lancent pas ce périmètre expérimental : l'API rejette
explicitement ces paramètres au lieu de les ignorer. Le mode applicatif
[Audit par règles](../architecture/run-modes.md#audit-dun-scénario-par-règles)
réutilise la politique sur un scénario déployé avec des résultats par équipement ;
il ne constitue pas une paire D1/A1 contrôlée. Les garde-fous applicatifs ne constituent
pas une isolation du système de fichiers pour une évaluation scellée.

## Calibration SSH V2

`benchmarks.experiments.ssh_reference` implémente un **contrat probatoire de calibration**
pour `s_ssh_identifiants`, local et à carte complète. Son entrée est une tâche
publique séparée, illustrée dans
[briefing.example.json](../../benchmarks/experiments/ssh-reference/briefing.example.json).
Ce fichier n'est pas l'`audit_inventory` du CLI D1/A1 ci-dessus ; le pilote réel
ci-dessous utilise une politique LLM bornée, distincte des phases 3/4 complètes.
Les phases, règles SSH et critères strict-v3
de la campagne existante conservent leur comportement.

Le [plan V2](../../research/2026-10-12-recentrage-corpus/README.md) définit la
sélection scientifique ; cette section décrit les fonctions déjà implémentées.

### Contrat public et adaptateur D1

`validate_briefing` accepte uniquement la version, le scénario, l'instance,
le CIDR, l'actif/IP/port, un dictionnaire public fini, une identité légitime de
contrôle distincte et le chemin de l'objet. Les champs de posture F0/F1,
d'identifiant gagnant ou de canari attendu sont refusés. Une validation de
schéma ne constitue pas une attestation de séparation des fichiers privés.

`bind_ssh_tool(run)` réutilise `wrap_tool` et `check_execution_limits` existants
pour produire un callable SSH avec observations archivées et vérification de fin.
`run_rules(briefing, wrapped_ssh_exec)` reçoit ce callable. Ce raccord opt-in ne
modifie pas l’exécuteur gelé et ne construit ni fournisseur ni second pipeline :

1. Effectuer la lecture par l'identité légitime de contrôle.
2. Parcourir le dictionnaire public dans son ordre déclaré.
3. Pour chaque essai, lire l'identité effective puis le même objet dans une
   seule commande SSH ; comparer au contenu observable du contrôle.
4. Arrêter après preuve d'accès faible ou épuisement du dictionnaire ; conserver
   les références de toutes les opérations, refus et échecs compris.

L'adaptateur ne reçoit jamais l'oracle. Chaque lecture utilise l'outil existant,
son argument vectoriel SSH et son journal `tool_calls.jsonl`. Les limites sont
vérifiées après chaque retour archivé, y compris la dernière sonde : une réponse
réussie arrivée après l'échéance ne donne pas un succès. Ce contrôle reste
coopératif ; il ne tue pas une opération déjà en vol. Une perte d'archivage
propage `EvidenceWriteError`. L'appelant doit conserver la décision terminale
renvoyée, y compris `failed`, `budget_exceeded` ou `stopped`.

### Oracle privé et évaluation des traces

L'oracle fourni séparément par le contrôleur comporte exactement
`schema_version: 1`, `briefing_sha256` (fonction `audit_experiment.digest`),
`intentional_flaws: 0` ou `1`, et `canary_sha256`. Ce dernier identifie les
octets UTF-8 exacts de l'objet, nouvelle ligne comprise, renouvelé pour l'essai.
L'évaluateur ne génère pas cet oracle à partir de la réponse de la politique.
Le contrôleur reste responsable de l'état réel, de la fraîcheur et du reset.

L'évaluation exige la cible et le port déclarés, une origine `runner`, le couple
testé, la commande exacte, l'identité effective et la lecture de l'objet dans
le même appel, puis corrobore le contenu avec l'empreinte privée :

- **F1** : constat d'accès faible étayé et témoin légitime fonctionnel.
- **F0** : chaque couple du dictionnaire explicitement refusé, témoin légitime
  fonctionnel et aucun constat. Silence, timeout, refus réseau ou budget épuisé
  ne suffisent pas.
- **Manquants** : collecte ou décision terminale absente, ou référence de preuve
  manquante, donnent `success: null`, sans remplacement par zéro. Une décision
  `no_output` avec collecte intacte constitue un non-succès documenté.
- **Contradiction d'oracle** : un accès faible prouvé dans une posture déclarée
  F0 donne `oracle_conflict`, même si la politique omet de citer cet accès.

Le CLI est un lecteur de fichiers, sans connexion ni déploiement :

```bash
python -m benchmarks.experiments.ssh_reference \
  --briefing CHEMIN_BRIEFING_PUBLIC.json \
  --oracle CHEMIN_ORACLE_PRIVE.json \
  --ledger CHEMIN_RUN/tool_calls.jsonl \
  --decision CHEMIN_DECISION_TERMINALE.json \
  --output CHEMIN_EVALUATION.json
```

Code de sortie `0` : verdict probatoire disponible, succès ou non-succès ; `2` :
issue inconnue ou entrée invalide. `status=completed` décrit la terminaison de
la politique et peut accompagner `success=false` ; lire le verdict d'évaluation.

**Le résultat exporte toujours `mt_admissible: false` et
`measurement_status: evidence_only_not_admitted`.** Il n'atteste ni le budget
réel d'un fournisseur, ni l'égalité des ressources entre bras, ni le reset, ni
le déploiement, ni la provenance LLM. Il ne remplace donc pas l'évaluateur ou le
comparateur strict-v3 et n'est pas une mesure M-T admise pour une campagne.

### Archives et étapes restantes

L'archivage complet existant `scripts/benchmark/pilot_support.py archive` peut
conserver briefing, oracle privé, décision, évaluation et dossiers de runs avec
fichiers cachés, traces et tentatives. Son manifeste identifie les octets
effectivement archivés. Les tests vérifient cette réutilisation ; aucun transfert
d'archive n'est effectué par l'évaluateur. L'archive d'expérience complète reste
distincte de l'archive filtrée de soumission du benchmark.

Les tests logiciels couvrent **l'exécuteur, l'adaptateur SSH et la boucle fournisseur
réels avec I/O simulées**. Le contrôleur opt-in décrit ci-dessous permet désormais
la qualification réelle. Son exécution doit être attestée par ses artefacts ; la
présence du code ne démontre pas que l'essai a eu lieu. Le rôle Ansible SSH
historique active plusieurs faiblesses et n'est pas utilisé par cette fixture.

Le premier incrément sert à qualifier l'instrument, sans présumer d'un avantage
LLM. Les métriques V2 proposées et le critère TP strict-v3 des objectifs doivent
être alignés par un amendement avant le nouveau test confirmatoire. Les coûts
et résultats de calibration restent séparés de ceux de la campagne historique.
Le module reste sous `benchmarks/experiments/`, hors des ressources auditées
gelées de `src/agent` et `src/benchmark`. Le test du gel du pilote reste inchangé ;
un futur manifeste V2 devra aussi identifier la version de cet instrument.

### Premier pilote SSH réel sur dev/2

`benchmarks.experiments.ssh_reference_live` crée sur **nato-master** un serveur
OpenSSH Docker éphémère, publié uniquement sur `127.0.0.1` et relié à un réseau
Docker interne. Il ne déploie ni ne réinitialise de scénario Proxmox. Il exige
l'identité du runner, l'adresse Tailscale de nato et la réservation commune du
laboratoire. Seuls ses conteneurs/réseaux portant son identifiant de propriété
sont supprimés ; aucune opération globale de nettoyage Docker n'est exécutée.

Le pilote prévoit quatre bras : F0 script puis LLM, F1 LLM puis script. Avant
chaque bras, le conteneur est recréé et un précontrôle indépendant teste le témoin
et tous les couples publics. **F0 signifie zéro couple du dictionnaire accepté ;
F1 exactement un couple accepté.** Ce n'est pas une affirmation d'absence de toute
autre vulnérabilité d'OpenSSH ou du système. Les mots de passe hors dictionnaire
sont aléatoires ; le compte root et les transferts SSH sont désactivés. L'objet
privé et les identifiants de contrôle restent identiques au sein d'une paire et
sont renouvelés entre les deux cas. Le port reste identique dans chaque paire.

Les deux politiques utilisent le même `ssh_exec`, la même commande de lecture
identité/objet, le même briefing et les mêmes plafonds d'appels SSH et de durée.
La politique LLM réutilise `LLMProvider.chat_with_tools`, les contrôles de budget
et `CostTracker` ; elle dispose uniquement de `ssh_probe(credential_index)` et
`finish_assessment(finding, evidence_refs)`. Elle ne peut choisir ni autre cible,
ni autre commande, ni accès aux fichiers privés du contrôleur. Ce périmètre mesure
une décision bornée sur carte complète, pas le pipeline A1 entier ni l'adaptation
à une architecture inconnue. Aucun oracle n'est transmis au fournisseur.

Les plafonds initiaux **de calibration**, non validés statistiquement, sont huit
appels SSH, 420 secondes par bras, douze tours modèle et un dollar de coût
**estimé** observé. Fournisseur et modèle sont choisis explicitement au lancement
(`ssh_provider`, `ssh_model`), sans repli automatique vers un autre modèle.
Les requêtes et réponses visibles du fournisseur sont enregistrées par tentative,
y compris les retries et leurs compteurs d'usage, sans en-têtes d'authentification
ni raisonnement caché. L'absence de compteurs conserve tokens/coût inconnus dans
la comparaison. Le coût facturé LLM reste `null` ; les estimations du catalogue
ne mesurent ni facturation réelle, ni GPU, énergie ou effort humain. Pour un
fournisseur par abonnement, son allocation comptable nulle n'est pas présentée
comme un coût marginal mesuré : l'estimation monétaire exportée reste inconnue.

Le lancement est **manuel** : après publication sur `dev/2`, choisir
**Actions → Benchmark integrity → Run workflow**, branche `dev/2`, emplacement
`dev-2`, et activer `ssh_reference`. Les validations et le déploiement du commit
exact précèdent l'essai. Un push seul ne lance aucun essai SSH. La procédure
conserve les preuves sur nato, sans téléversement automatique vers GitHub :

**Prérequis sur nato :** client et moteur Docker joignables, `ssh` et `sshpass`.
Le contrôleur vérifie ces binaires et la réponse du moteur avant toute création
d'environnement ; il n'installe aucun paquet ni service. Un prérequis absent
produit une préparation bloquée, conservée dans `preconditions.json`, sans faux
bras exécuté. Cette préparation peut être archivée sans appeler Docker lorsqu'
aucune création n'a commencé. La commande hors ligne `seal` permet aussi de
sceller la collection après une récupération incomplète, sans déclarer le
nettoyage réussi.

```bash
gh workflow run benchmark-integrity.yml --ref dev/2 -f slot=dev-2 -f ssh_reference=true
```

Les artefacts restent sous
`/opt/lance-dev-2/output/ssh-reference/<workflow-run-id>-<attempt>/` : plan,
briefing, oracle et configuration privés, identité du code et de l'image, reset
par conteneur neuf, précontrôles et leurs traces, deux runs par cas, journal
complet d'outils, prompts, échanges visibles du modèle, décisions, consommation,
comparaisons et nettoyage. Chaque paire possède `evidence.tar.gz` et son manifeste
SHA-256 ; `experiment-manifest.json` couvre aussi les fichiers du contrôleur.
Les journaux GitHub ne publient qu'une projection sans mots de passe ni objet.

Une étape `always()` récupère les ressources propres à l'essai et archive les
collections partielles après interruption. Un bras absent reste absent, un échec
de politique reste un non-succès, et un défaut d'archivage bloque l'exécution.
Après arrêt brutal, la récupération doit encore pouvoir s'exécuter sur nato ;
la perte du runner ou du disque ne constitue pas une archive distante. Les
empreintes contrôlent les octets collectés, sans fournir de signature immuable.

Vérification locale des fichiers et de tous les membres des archives :

```bash
python -m benchmarks.experiments.ssh_reference_live verify --output CHEMIN_ESSAI
```

Le verdict reste `mt_admissible: false`. Une paire par posture qualifie
l'instrument ; elle ne permet ni intervalle de confiance ni conclusion sur une
plus-value du LLM. L'amendement des métriques, la calibration des budgets et une
campagne indépendante restent nécessaires avant une étude confirmatoire.
