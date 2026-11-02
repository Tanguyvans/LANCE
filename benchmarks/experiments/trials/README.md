# Une épreuve — gabarit

Une **épreuve** est ce qu'on soumet au filtre et au test de clôture. Elle
contient une ou plusieurs **séries**, ces séries regroupent des **scénarios**
existants sous `benchmarks/scenarios/{dev,test}/S<N>.yaml`, et l'ensemble compte
pour **une seule observation**.

Ce fichier vit à côté de `benchmarks/experiments/` et ne duplique aucun autre
lieu : le déploiement est dans `benchmarks/topologies/`, la faille dans
`benchmarks/packs/`, la vérité terrain dans `benchmarks/ground_truth/`, et la
liste des scénarios dans `benchmarks/catalog.yaml`.

## Le filtre, avant toute création

Écris la règle d'une ligne qui trancherait le cas. **Si elle s'écrit, le fichier
n'est pas créé** : le cas n'est pas une question d'interprétation, c'est une case
de catalogue, et la construire est une perte de temps.

Le filtre se juge sur la règle écrite, pas sur l'intention. Il prend quelques
minutes et il a rejeté deux dispositifs qui avaient résisté à six relectures.

## Format

```yaml
schema_version: "1"
trial_id: t_segmentation_voisinage      # identifiant stable, en minuscules

# Ce que l'épreuve prétend mesurer, en une phrase vérifiable.
claim: >
  Distinguer un hôte joignable via un relais applicatif d'un hôte réellement
  segmenté demande de croiser ce que deux services répondent, pas de lire une
  seule réponse.

# Les séries qui composent l'épreuve. Chaque entrée renvoie à des scénarios
# existants ; aucune n'est créée ici.
series:
  - id: serie_vlan_segmente
    scenarios: [dev/S13]              # chemins sous benchmarks/scenarios/
    varies: "rien : une seule série, un seul scénario"
  - id: serie_hote_sain
    scenarios: [dev/S1h]              # contrôle : doit rester sans faille
    varies: "rien : le scénario sain de référence"

# La règle d'une ligne qui devrait trancher. Elle est écrite même quand le filtre
# est franchi : c'est elle qui donne sa valeur à l'épreuve.
one_line_rule: |
  def decide(obs):
      return "joignable" if any(o.port_open for o in obs) else "segmente"

# Pourquoi cette règle ne tranche pas, et quelle observation la met en défaut.
why_it_fails: >
  Un relais applicatif laisse un port ouvert sur le relais et non sur l'hôte :
  la règle conclut « joignable » pour un hôte que rien n'atteint, et
  « segmenté » pour un hôte atteint par un chemin détourné.

# Ce qui doit échouer avant la mesure : l'automatisation de référence D1+.
closure_test:
  script: benchmarks/experiments/closure/t_segmentation_voisinage.py
  expected: D1+ fails                        # D1+ doit échouer, sinon rien n'est mesuré
  status: planned                            # planned | runs | rejects | admits

# Ce que l'épreuve ne prouve pas, écrit avant les résultats.
limits:
  - "un seul protocole de relais"
  - "deux séries seulement"
```

## Les cas à connaître

- **Un scénario sans variante** est une épreuve d'une seule série (`series` a
  une entrée, `varies: "rien"`). Ce n'est pas une erreur.
- **Une série partage une vérité terrain** : ses scénarios ne diffèrent que par
  un axe, donc la même entrée `ground_truth` décrit ce qu'on attend d'eux.
- **Deux épreuves ne partagent rien** : ni simulateur, ni vocabulaire, ni
  mécanisme d'échec. Sinon c'est la même épreuve sous deux noms.
- **Cinq épreuves** sont nécessaires pour qu'une inférence conclue ; trois pour
  produire un chiffre. Une seule épreuve ne prouve jamais rien sur le programme.

## Où l'enregistrer

Une ligne par épreuve dans `benchmarks/catalog.yaml`, sous une clé `trials:`.
L'index reste la seule table : aucun autre fichier n'énumère les épreuves.
