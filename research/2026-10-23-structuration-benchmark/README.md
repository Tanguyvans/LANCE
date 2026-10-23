# Structuration du benchmark par appareil, architecture et faille

**Cycle de vie : Actif.** Étude commencée le **2026-10-23**.
Dernière révision : **2026-10-23 18:26 (Europe/Brussels, UTC+02:00)**.
Branche de travail : `dev/2`.

## Question

Comment organiser le corpus en familles de scénarios qui varient selon
l'**appareil**, l'**architecture** et la **faille**, comme l'annonce la
présentation du 2026-10-23 ? Il faut le faire sans perdre l'identité
historique de S1–S29 et sans séparer ce que le benchmark prétend tester de
ce que le code déploie réellement.

## Statut

Première étape implémentée, lecture seule. On dispose d'un vocabulaire des
trois axes, d'une mesure de l'architecture réellement encodée dans les
topologies et des matrices de couverture. La référence implémentée est
décrite dans [docs/benchmark/taxonomie.md](../../docs/benchmark/taxonomie.md) ;
l'état mesuré est dans [couverture-axes.md](../../docs/benchmark/couverture-axes.md).
Aucun scénario, aucune vérité terrain, aucun pack, aucun playbook n'est
modifié. Aucun run de laboratoire n'a été effectué.

## Principe retenu

- **La cible vient de la présentation, l'état vient du code.**
  `benchmarks/taxonomy.yaml` déclare les classes visées. Le module
  `src/benchmark/taxonomy.py` mesure ce que les fichiers encodent. Un écart
  entre les deux désigne un scénario à mettre en conformité. On ne corrige
  jamais une étiquette pour faire disparaître l'écart.
- **Les étiquettes sont dérivées, jamais recopiées.** Elles se calculent à
  partir des rôles, des topologies et des catégories existants. Il n'existe
  qu'une source de vérité par information.

## Constats (mesurés au 2026-10-23 sur `dev/2`)

Ce sont des faits mesurés dans les fichiers du dépôt. Ils ne constituent pas
une observation des machines déployées.

1. **L'architecture visée n'est réalisée que pour 19 scénarios sur 29.**
   23 topologies sont un seul sous-réseau plat. S3 à S8, S11, S12, S18 et S23
   visent une architecture passerelle, segmentée, en étoile ou local–cloud,
   mais leurs services sont tous joignables directement. Seuls S13
   (segmenté), S25 (passerelle) et S20, S24, S26, S27 (multi-sauts)
   encodent une structure réseau. Côté Ansible, seul S13 reçoit des zones de
   pare-feu VLAN.
2. **Les failles se concentrent sur l'authentification (93), la
   configuration (73) et l'exposition de données (70)**, sur 288. Injection
   (13), crypto (10), mise à jour (12), CVE (9) et contrôle d'accès (8) sont
   rares. Aucune faille n'est rattachée aux équipements de supervision OT.
3. **`misconfiguration` sert de fourre-tout** dans les vérités terrain.
   Environ 30 des 70 failles de cette catégorie sont des défauts
   d'authentification (MQTT anonyme, FTP anonyme…). La famille
   « authentification » est donc sous-estimée.
4. **Plusieurs rôles portent le nom d'un scénario plutôt que d'un appareil**
   (`heldout_entry`, `exploit_auth_server`, `pivot_vault`…). La taxonomie les
   ramène à leur classe réelle (hôte SSH, application web).

## Feuille de route

Les étapes sont planifiées une à une. Chaque étape garde la suite de tests
verte et ne touche pas au laboratoire sans demande explicite.

1. **Fait.** Taxonomie, mesure, matrices, tests de garde.
2. **Contrat de faille.** Les packs `f*` ne listent plus de numéros de
   scénario. Chaque faille porte son injecteur, sa preuve et son contrôle
   durci.
3. **Source unique.** L'inventaire Ansible est généré depuis les topologies,
   avec des VMID alloués. La divergence LDAP de S13 relevée par l'audit sert
   de premier cas.
4. **Mise en conformité des architectures.** Les dix scénarios non conformes
   sont soit construits selon leur intention (VLAN, relais, zones OpenWrt
   déjà utilisés par S13 et S20–S27), soit reclassés explicitement.
5. **Familles V2 par contraste.** Un seul axe varie à la fois. Le choix des
   familles suit les trous des matrices et le
   [registre d'hypothèses](../2026-10-21-hypotheses-benchmark/README.md).

## Documents

- [audit-phase0.md](audit-phase0.md) : audit statique de la chaîne
  catalogue → déploiement → évaluation, préalable à cette étude (commit
  `2532980` de `main`).
- Études liées : [plan V2 et structuration du corpus](../2026-10-12-recentrage-corpus/README.md),
  [registre d'hypothèses](../2026-10-21-hypotheses-benchmark/README.md),
  [couverture du benchmark](../2026-09-29-benchmark-coverage/README.md).

## Points ouverts

- Rapport LaTeX/PDF de l'étude, à produire quand la conception des familles
  (étape 5) sera arrêtée. Ce README est pour l'instant un document de travail.
- Signature structurelle propre des architectures `star` et `local_cloud`
  (règles de conformité provisoires).
- Correction des catégories dans les vérités terrain (point 3), qui modifie
  les vérités terrain et donc les scores : à décider avec l'équipe.
- Articulation entre ces trois axes techniques et les six questions du plan V2.
