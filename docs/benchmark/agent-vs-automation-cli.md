# Comparaison règles / agent : premier incrément logiciel

Le CLI permet de comparer **D1 (`rules`) et A1 (`llm`) sur les phases 3 et 4** :
analyse puis vérification. Il utilise `Pipeline`, le scanner, les outils,
l'exécuteur, les agrégateurs et les validateurs de preuve existants. Le mode
`rules` ne construit aucun fournisseur LLM et ne consulte aucun catalogue de prix.
Les résultats restent à mesurer sur un laboratoire ; les tests locaux utilisent
des outils simulés et ne démontrent aucun avantage de l'IA.

Voir le [protocole scientifique](../../research/agent-vs-automation/protocol.md) et le
[suivi d'implémentation](../../research/agent-vs-automation/implementation-plan.md).

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
Les contrats sémantiques `strict-v3.14` / `evidence-v13` ne sont pas assouplis.

L'API et l'interface ne lancent pas ce périmètre : l'API rejette explicitement
ces paramètres au lieu de les ignorer. Les garde-fous applicatifs ne constituent
pas une isolation du système de fichiers pour une évaluation scellée.
