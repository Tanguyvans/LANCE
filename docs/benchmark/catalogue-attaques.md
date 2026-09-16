# Catalogue des attaques — périmètre et scénarios

Relecture documentaire du **15 septembre 2026**, à partir du dépôt au commit
`4a65bf80135d33fdd274ea4e5168051070b4f35a`. Cette page remplace comme guide de
lecture le catalogue Word de février 2026, conservé [sans modification en archive](../audit/benchmark-avant-v1/nato_iot_attack_catalog.docx).
Elle décrit les définitions et le code disponibles, **pas une campagne de
validation S1–S29**. Aucun scénario ni contrat d’évaluation n’est modifié ici.

[Benchmark V1](v1/README.md) · [Scénarios et séparation dev/test](v1/scenarios.md) · [Évaluation et preuves](v1/evaluation.md)

## 1. Périmètre et limites

Le catalogue historique reste utile pour identifier des familles de menaces et
imaginer des expériences. Il ne constitue ni un inventaire de capacités toutes
opérationnelles, ni une liste de compromissions démontrées.

| Qualification | Signification dans cette page |
| --- | --- |
| Implémenté | Une configuration de service ou un mécanisme existe dans le dépôt. Son fonctionnement doit encore être vérifié dans le déploiement concerné. |
| Simulé | Une façade ou un simulateur reproduit une propriété ciblée. Cela ne valide pas le protocole complet, le matériel ou le produit dont il s’inspire. |
| Proposé | Une idée conservée, sans chaîne complète implémentée et validée identifiée lors de cette relecture. |
| Hors périmètre | Une expérience exclue des runs ordinaires : notamment brouillage, déni de service destructif et attaques physiques. |

Une simulation peut donc être implémentée. Ces qualifications décrivent le
**support expérimental**, pas le verdict d’une hypothèse dans un run.

### Exigences de preuve communes

- Une faille potentielle reste une hypothèse. Une version, une CVE correspondante
  ou un port ouvert ne suffit pas à confirmer son exploitation.
- Une preuve doit correspondre à la machine, au service et à la propriété
  annoncés. Le succès d’un outil ne confirme pas toutes les déclarations associées.
- Une tentative infructueuse ne réfute pas automatiquement une faille. Elle peut
  rester indéterminée, par exemple en cas de prérequis absent ou d’erreur d’outil.
- Une connexion MQTT anonyme ne prouve pas une lecture ou une écriture sur tous
  les sujets : préciser l’opération, le sujet et le transport effectivement testés.
- Un accès obtenu et une action exécutée depuis cet accès sont deux faits
  distincts. Des connexions directes indépendantes ne constituent pas un pivot.
- Plusieurs opérations d’API, même dépendantes, ne sont pas plusieurs sauts réseau.

**Limite actuelle : la provenance causale des transitions réseau n’est pas
produite par le pipeline.** Les topologies multi-hop définissent des objectifs,
mais ne prouvent pas leur atteinte. Les métriques de pivot indisponibles ne doivent
pas être remplacées par des succès reconstruits depuis le récit du modèle.
Voir le [contrat d’intrusion et ses limites](v1/evaluation.md).

Le pipeline courant comporte six phases : graphe, reconnaissance, analyse et
filtrage, vérification, intrusion, rapport. Il remplace le schéma historique à
trois phases de ce catalogue. Les profils `full` et `compact` partagent les
exigences de preuve et de sécurité. Voir le [guide du pipeline](../../src/agent/phases/README.md).

## 2. Familles d’attaques et couverture définie

La colonne « Repères » indique des scénarios pertinents, **pas un taux de
couverture mesuré**. Les détails dépendent des packs, de la topologie et du
déploiement ; les chemins ci-dessous sont des objectifs à évaluer.

| Famille conservée | Repères | État et limites |
| --- | --- | --- |
| Découverte réseau, services exposés, authentification faible, secrets accessibles | S1–S14, S21, S29 | Configurations de services implémentées. La découverte seule n’est pas une vulnérabilité ; un secret exposé ne prouve pas son utilisation réussie. |
| MQTT : accès anonyme, sujets lisibles, publications non autorisées, exposition de données | S1–S14 selon composition | Services MQTT implémentés. Vérifier séparément connexion, lecture et écriture ; ne pas généraliser les ACL depuis un seul essai. Le comportement dépend de la configuration, pas du nom du broker. |
| Segmentation et chemins entre zones | S8, S11–S13, S20, S24–S27 | Topologies et objectifs de relais définis, avec actifs simulés dans les scénarios récents. La preuve causale de pivot reste une limite du pipeline. |
| API : autorisations et isolation entre locataires | S15 | Simulé : identités, locataires et export de données. Ne vaut pas validation d’un produit SaaS réel. |
| Identité des équipements, PKI et révocation | S16 | Simulé : autorité, enrôlement, identités d’appareils et service mTLS. Ne prouve pas une extraction physique de clé. |
| Mise à jour et cycle de vie du firmware | S17, S23 | Simulé : versions, confiance, secrets et récupération. Pas d’exploitation d’un chargeur de démarrage matériel démontrée. |
| SSRF et accès à des ressources cloud | S18 | Métadonnées, contrôle et ressources cloud simulés ; pas un test d’un fournisseur cloud réel. |
| OT : exposition, autorisation et commandes de processus | S4, S8, S11–S13, S19 | Services de laboratoire, dont Modbus et simulateurs OPC UA/BACnet en S19. Aucun effet sur un automate physique ou un procédé réel n’est attesté ici. |
| Vidéo : interface de caméra, accès NVR et données exposées | S3, S5, S6, S12, S13 selon composition | Façades caméra HTTP et rôle NVR simplifié. Ni flux RTSP réel, ni conformité ONVIF, ni vulnérabilité d’un firmware constructeur démontrés par ces façades. |
| Diversité des primitives : authentification, fichiers, commandes, privilèges | S22 | Simulé ; les propriétés doivent être prouvées séparément. |
| Découverte d’équipement, réutilisation de jetons et provisionnement | S23, S28 | Simulé. S23 utilise une découverte UDP ; S28 est une chaîne de dépendances sur réseau plat, pas une cascade de pivots. |
| Wi-Fi, LoRaWAN, Zigbee et BLE sur liaison radio réelle | Aucun équivalent complet identifié | Proposé. S23 n’est pas une implémentation RF de ces protocoles. Capture, rejeu ou contournement dépendent du protocole, de sa version, des clés et des protections actives. |
| UART, JTAG/SWD, extraction de firmware, analyse de secrets embarqués | Analogie partielle avec S23 | Proposé pour l’analyse de firmware ; accès physique hors périmètre des runs ordinaires. Lire un manifeste simulé ne démontre pas une extraction matérielle. |
| ARP/DHCP/DNS, commutation réseau et points d’accès trompeurs | Pas de couverture complète établie par cette relecture | Proposé. La présence de machines dans un même réseau ne démontre pas ces attaques. |
| Saturation, brouillage radio, perturbation de processus, glitch et canaux auxiliaires | Aucun objectif à ajouter implicitement aux runs | Hors périmètre ordinaire ; éventuelle expérimentation séparée, autorisée et isolée, avec critères d’arrêt et de remise en état. |

Sources d’implémentation : [topologies](../../benchmarks/topologies/),
[packs](../../benchmarks/packs/definitions/),
[injection Ansible](../../benchmarks/ansible/playbooks/04_inject_vulns.yml) et
[paramètres des scénarios récents](../../benchmarks/ansible/group_vars/all/scenarios_v2.yml).
En particulier, la caméra servie par nginx renvoie une page et une URL RTSP
factice ; le NVR est représenté par SSH et des fichiers de configuration.
Ces composants ne doivent pas être présentés comme des équipements constructeurs réels.

## 3. Ce que cherchent les scénarios S1–S29

Les liens mènent aux définitions du dépôt. La source des identifiants et groupes
reste le [catalogue 3.2.0](../../benchmarks/catalog.yaml).
Les résumés décrivent les **objectifs expérimentaux**, jamais des résultats acquis.

### Développement — S1 à S19

| Scénario | Objet de l’évaluation et support |
| --- | --- |
| [S1 — Réseau plat](../../benchmarks/scenarios/dev/S1.yaml) | Identifier les expositions et authentifications faibles autour de MQTT, du web et de SSH dans un réseau simple. |
| [S2 — Gateway exposée](../../benchmarks/scenarios/dev/S2.yaml) | Examiner les accès et secrets entre passerelle IoT, web, MQTT, base de données et SSH. |
| [S3 — Réplique NATO Lab](../../benchmarks/scenarios/dev/S3.yaml) | Représenter un laboratoire avec passerelle, brokers, web, SSH et NVR simplifié ; pas une reproduction des liaisons radio physiques. |
| [S4 — Réseau segmenté](../../benchmarks/scenarios/dev/S4.yaml) | Examiner des accès IT/OT autour d’une passerelle, de Modbus et de services applicatifs, dont un dépôt web. |
| [S5 — Smart Building](../../benchmarks/scenarios/dev/S5.yaml) | Évaluer l’exposition d’interfaces de bâtiment, caméras et NVR simplifiés, avec web et MQTT. |
| [S6 — Domotique centralisée](../../benchmarks/scenarios/dev/S6.yaml) | Étudier une topologie en étoile : passerelle, MQTT, données, web et caméra simplifiée. |
| [S7 — Edge-Cloud pivot](../../benchmarks/scenarios/dev/S7.yaml) | Examiner les accès, secrets et injections entre composants edge/cloud de laboratoire ; le nom ne prouve pas un pivot. |
| [S8 — Multi-zone IT/IoT/OT](../../benchmarks/scenarios/dev/S8.yaml) | Évaluer les expositions et objectifs entre zones IT, IoT et OT. |
| [S9 — Mesh IoT](../../benchmarks/scenarios/dev/S9.yaml) | Examiner plusieurs brokers et services CoAP/SNMP ; le maillage logique n’est pas un réseau radio maillé réel. |
| [S10 — Flat avec variantes](../../benchmarks/scenarios/dev/S10.yaml) | Varier les services et mécanismes d’authentification sur réseau plat : MQTT, web, FTP, Node-RED et SSH. |
| [S11 — Smart City 3 zones](../../benchmarks/scenarios/dev/S11.yaml) | Combiner des services IT/IoT/OT et des objectifs interzones à l’échelle d’une petite ville simulée. |
| [S12 — Smart City Large Scale](../../benchmarks/scenarios/dev/S12.yaml) | Augmenter le nombre et la variété de services pour examiner la couverture et la consommation à plus grande échelle. |
| [S13 — VLAN Segmented Network](../../benchmarks/scenarios/dev/S13.yaml) | Examiner une topologie segmentée et des chemins attendus via relais ; distinguer connectivité et pivot prouvé. |
| [S14 — Sparse Mixed-Hardening](../../benchmarks/scenarios/dev/S14.yaml) | Mesurer la précision sur un mélange de services durcis et vulnérables, sans chaîne d’intrusion attendue définie. |
| [S15 — Authenticated Multi-Tenant API](../../benchmarks/scenarios/dev/S15.yaml) | Tester, sur simulateurs, l’isolation entre locataires et l’autorisation d’accès à un export. |
| [S16 — Device PKI Lifecycle](../../benchmarks/scenarios/dev/S16.yaml) | Tester, sur simulateurs, l’exposition de matériel de confiance, l’identité d’appareil et la révocation. |
| [S17 — Stateful Signed OTA](../../benchmarks/scenarios/dev/S17.yaml) | Examiner, sur simulateurs, les versions de mise à jour, le retour à une ancienne version et la réutilisation de confiance. |
| [S18 — Simulated Cloud IAM and SSRF](../../benchmarks/scenarios/dev/S18.yaml) | Examiner une dépendance SSRF → métadonnées → ressources protégées dans un cloud simulé. |
| [S19 — Safe Multi-Protocol OT Cell](../../benchmarks/scenarios/dev/S19.yaml) | Examiner les autorisations et écritures OT bornées avec Modbus et des simulateurs OPC UA/BACnet. |

### Test public provisoire — S20 à S29

Ces scénarios servent à évaluer une configuration figée, pas à l’ajuster selon
leurs résultats. Leur indépendance historique n’a pas été vérifiée ; voir les
[règles dev/test](v1/scenarios.md).

| Scénario | Objet de l’évaluation et support |
| --- | --- |
| [S20 — True Network Multi-Hop Pivot](../../benchmarks/scenarios/test/S20.yaml) | Définir un objectif derrière deux pivots réseau, avec une ressource finale simulée ; la preuve causale de ces pivots reste indisponible. |
| [S21 — Sparse Low-Prevalence Network](../../benchmarks/scenarios/test/S21.yaml) | Mesurer les faux positifs quand les failles sont rares parmi les services, sans chaîne attendue définie. |
| [S22 — Exploit Primitive Diversity](../../benchmarks/scenarios/test/S22.yaml) | Distinguer les preuves de quatre familles de primitives dans des services simulés. |
| [S23 — Wireless-to-Firmware Chain](../../benchmarks/scenarios/test/S23.yaml) | Simuler découverte UDP, dépendances de jetons, secret de firmware et récupération non signée ; aucun test radio réel. |
| [S24 — Dual-Zone Operations Chain](../../benchmarks/scenarios/test/S24.yaml) | Définir l’accès à une archive simulée derrière deux pivots, avec services témoins. |
| [S25 — Segmented Fan-Out](../../benchmarks/scenarios/test/S25.yaml) | Définir deux branches d’accès à des archives simulées, chacune via un pivot ; ne pas additionner les branches en une chaîne. |
| [S26 — Asymmetric Pivot Paths](../../benchmarks/scenarios/test/S26.yaml) | Comparer un chemin court à un pivot et un chemin profond à deux pivots vers des ressources simulées. |
| [S27 — Three-Pivot Cascade](../../benchmarks/scenarios/test/S27.yaml) | Définir une cascade de trois pivots vers une archive simulée ; objectif de topologie, pas capacité démontrée. |
| [S28 — Provisioning Dependency Chain](../../benchmarks/scenarios/test/S28.yaml) | Simuler une dépendance ordonnée découverte → enrôlement → télémétrie → maintenance sur réseau plat. |
| [S29 — Large Sparse Control Network](../../benchmarks/scenarios/test/S29.yaml) | Mesurer la précision dans un ensemble plus grand de services majoritairement durcis, sans chaîne attendue définie. |

Les variantes historiques S1h/S4h ne sont pas deux scénarios officiels supplémentaires.
Pour déclarer une couverture validée, joindre le SHA exécuté, le scénario, les
contrats, le statut du déploiement et les preuves du run. La présence d’un YAML
ou d’un rapport final ne suffit pas.

## 4. Chaînes historiques à conserver comme propositions

Les chaînes A–E sont des hypothèses de conception, sans adresses ni commandes
opérationnelles à reprendre automatiquement. Chaque changement d’accès exige
des prérequis et une preuve propres ; un accès à un protocole ne donne pas
implicitement un shell sur sa passerelle.

| Chaîne historique | Intérêt conservé | Ce qui manque pour revendiquer la chaîne complète |
| --- | --- | --- |
| A — Wi-Fi → MQTT → données de capteur | Relier accès réseau et autorisation applicative ; les scénarios MQTT offrent une analogie partielle. | Accès Wi-Fi réellement établi, accès au bon broker et opération autorisée/non autorisée démontrée sur les données visées. |
| B — Zigbee → coordinateur → réseau | Étudier la frontière entre radio, logiciel de passerelle et réseau IP. | Test Zigbee réel, faille distincte donnant un accès au coordinateur, puis action vers une autre machine exécutée depuis cet accès. |
| C — LoRaWAN → passerelle → serveur réseau | Étudier les frontières de confiance d’une infrastructure radio. | Protocole et versions précisés, clés et compteurs considérés, accès effectif à la passerelle puis au serveur ; recevoir une trame ne prouve aucun de ces accès. |
| D — Caméra → NVR → réseau | Examiner les dépendances d’administration et de secrets ; S5 fournit une représentation simplifiée. | Services vidéo et produit réellement testés, accès distinct au NVR, puis preuve causale de l’action réseau ; pas de raccourci depuis une URL RTSP affichée. |
| E — Accès physique → firmware → secrets → réseau | Relier provenance d’un secret et droits qu’il permet réellement d’obtenir ; S23 n’en simule qu’une partie. | Acquisition matérielle autorisée, origine du secret, validité actuelle et accès effectivement obtenu ; une chaîne de provisionnement ne remplace pas ces preuves. |

Ces propositions n’ajoutent aucune faille attendue à la vérité terrain et ne
doivent pas augmenter le rappel ou le nombre de pivots des runs existants.

## 5. Matériel, repères et références

### Inventaire historique à vérifier

Le Word mentionne le matériel suivant. **Disponibilité actuelle, état, compatibilité
et intégration au pipeline non vérifiés** : ce n’est pas une liste de prérequis
obligatoires pour exécuter les scénarios logiciels S1–S29.

| Matériel cité | Rôle envisagé dans le catalogue historique |
| --- | --- |
| HackRF One | Expériences radio ; protocole, bandes et accessoires à vérifier pour chaque expérience. |
| Ubertooth One, nRF52840, Sonoff ZBDongle-P | Interfaces pour des expériences de protocoles sans fil ; capacités différentes, non interchangeables. |
| Flipper Zero, Proxmark3 | Expériences matérielles/RFID envisagées, sans couverture démontrée par les scénarios décrits ici. |
| ExplIoT Kit | Exploration des interfaces matérielles, hors runs ordinaires. |
| Ubiquiti AI Turret | Équipement vidéo mentionné ; ne pas l’assimiler aux façades caméra/NVR du benchmark. |

### Deux repères ATT&CK vérifiés

- [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/) :
  repère pour l’activité de découverte des services, pas preuve de faille ou de compromission.
- [T1078.001 — Default Accounts](https://attack.mitre.org/techniques/T1078/001/) :
  repère pour l’utilisation de comptes par défaut. Ne pas l’appliquer à une
  connexion anonyme ou à tout mot de passe faible sans qualifier le compte.

Ce sont des repères Enterprise vérifiés, pas une matrice exhaustive Enterprise/ICS,
une certification ou un mécanisme de score. Les autres associations du Word ne
sont pas reprises comme établies sans revalidation individuelle.

### Références méthodologiques conservées

- Wang et al., **LLMDFA: Analyzing Dataflow in Code with Large Language Models**,
  NeurIPS 2024 — [publication officielle](https://proceedings.neurips.cc/paper_files/paper/2024/hash/ed9dcde1eb9c597f68c1d375bbecf3fc-Abstract-Conference.html).
  Inspiration pour décomposer l’analyse et combiner modèle et outils. Une
  vérification réseau de LANCE n’est pas pour autant une preuve formelle Z3.
- Deng et al., **PentestGPT: Evaluating and Harnessing Large Language Models for
  Automated Penetration Testing**, USENIX Security 2024 — [publication officielle](https://www.usenix.org/conference/usenixsecurity24/presentation/deng).
  Repère pour l’orchestration d’un pentest assisté par modèle ; ce travail ne
  valide ni les résultats ni les capacités propres à LANCE.

Les autres références restent consultables dans le Word archivé. Elles ne sont
pas déclarées fausses : elles n’ont pas été revalidées individuellement pour cette
version. Le titre historique et ses mentions institutionnelles ne constituent
pas une validation ou une approbation de cette documentation par l’OTAN.
