# Proposition de sujet de TFE

## Développement et évaluation d'un agent d'intelligence artificielle pour l'audit automatisé de réseaux IoMT (Internet of Medical Things)

---

## Contexte

Les environnements hospitaliers et de télésanté reposent de plus en plus sur des
équipements médicaux connectés : moniteurs de signes vitaux, pompes à perfusion,
passerelles de télémétrie, serveurs d'imagerie (PACS), objets de suivi patient.
Ces dispositifs communiquent via des protocoles spécifiques (**HL7, DICOM, MQTT,
BLE**) et cohabitent avec l'informatique de gestion, ce qui élargit la surface
d'attaque tout en imposant de fortes contraintes : continuité des soins, sûreté
patient, protection des données de santé (RGPD).

L'audit de sécurité d'un tel réseau consiste à découvrir les équipements et leurs
services, à identifier des vulnérabilités potentielles et à vérifier les résultats
obtenus. Un premier outil d'audit fondé sur des modèles de langage et des outils
d'analyse est déjà disponible ; il réalise ces opérations sur des réseaux virtuels
contrôlés à vocation IoT généraliste.

Le travail consistera à **spécialiser et étendre cet outil au domaine IoMT**, puis
à évaluer les gains obtenus par rapport à la version initiale. L'ensemble des
expérimentations se déroule sur des **réseaux virtuels isolés** (aucun dispositif
médical réel), dans un cadre d'audit strictement défensif.

---

## Objectifs

- Adapter la découverte d'équipements et l'identification de vulnérabilités aux
  spécificités des réseaux médicaux (protocoles, types d'appareils cliniques).
- Intégrer des méthodes de vérification des constats **non intrusives**, compatibles
  avec un contexte où l'on ne peut perturber un dispositif de soin.
- Introduire une priorisation des risques tenant compte de l'**impact clinique**,
  et non uniquement du score CVSS.
- Mesurer objectivement l'apport de ces améliorations face à la version initiale.

---

## Étapes

1. **Prise en main** de l'architecture existante et identification des adaptations
   nécessaires au contexte IoMT (protocoles, équipements, contraintes de sûreté).
2. **Amélioration de la découverte** des équipements médicaux et de l'identification
   des vulnérabilités (support HL7/DICOM/BLE, empreintes d'appareils cliniques,
   mapping CVE spécifiques).
3. **Intégration de méthodes de vérification** des constats et des preuves, adaptées
   à un environnement où la vérification passive / non intrusive est privilégiée.
4. **Expérimentation** sur des scénarios virtuels de réseaux IoMT présentant des
   vulnérabilités connues.
5. **Comparaison** des résultats avec la version initiale de l'outil (rappel,
   précision, F1, score pondéré par gravité).
6. **Analyse des résultats** et recommandations pour un déploiement hospitalier.

---

## Scénario d'évaluation (banc virtuel)

Segment hospitalier simulé, entièrement isolé (VM / conteneurs LXC, aucun dispositif
médical réel), par exemple sur le sous-réseau `192.168.110.0/24` :

| Rôle | Simulé par | Vulnérabilités injectées (exemples) |
|------|-----------|-------------------------------------|
| Passerelle de télémétrie patient | conteneur MQTT | broker sans authentification, topics patients en clair |
| Serveur d'imagerie PACS | serveur DICOM (Orthanc) | DICOM sans authentification, export non chiffré |
| Interface HL7 (admissions / labo) | listener MLLP | messages HL7 non chiffrés, injection de segments |
| Moniteur de chevet / pompe simulée | service HTTP émulé | identifiants par défaut, firmware non signé |
| Poste soignant / EHR | VM web | identifiants faibles, session non expirée |

**Fil rouge de l'audit (chemin multi-hop) :** poste soignant compromis → pivot vers
la passerelle MQTT → accès aux données de télémétrie → atteinte au PACS. L'agent
doit découvrir la topologie, hiérarchiser par risque (pondéré par l'impact patient),
puis vérifier les preuves de façon non intrusive.

---

## Faisabilité technique (infrastructure Proxmox)

Le banc d'essai réutilise l'infrastructure Proxmox existante ; l'essentiel de la
tuyauterie de déploiement est déjà en place :

- **Déploiement automatisé** via playbooks Ansible (création des conteneurs,
  injection des vulnérabilités, population des services, vérification).
- **Format de scénario déclaratif** : topologie YAML (`base_vmid`, routeur,
  services `{ip, rôle}`), paquet de vulnérabilités, et fichier de vérité terrain.
- **Évaluation** automatique par le module de benchmark (Recall / Precision / F1 /
  score pondéré).

**Travail d'extension spécifique au TFE :**

- Ajout des rôles de service médicaux (`pacs_dicom` via Orthanc, `hl7_mllp`,
  `telemetry_gw`, `ehr_web`) sur le modèle des rôles existants.
- Nouvelle topologie `iomt_hospital.yaml`, nouveau paquet de vulnérabilités et
  nouvelle vérité terrain.
- Côté agent : mapping CPE des équipements médicaux et base de connaissances
  dédiée (sécurité DICOM / HL7).

**Limite identifiée :** le Bluetooth Low Energy (BLE) ne dispose pas de couche radio
au sein d'un environnement virtualisé. Deux options seront discutées : émulation du
protocole applicatif sur TCP, ou report de ce volet vers le laboratoire physique.

---

## Livrables attendus

- Outil d'audit étendu au domaine IoMT.
- Jeu de scénarios virtuels reproductibles avec vérité terrain.
- Étude comparative quantifiée par rapport à la version initiale.
- Rapport d'analyse et recommandations de déploiement.
