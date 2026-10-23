# Couverture du corpus par appareil, architecture et faille

<!-- Fichier généré par `python -m src.benchmark.taxonomy` ; ne pas modifier à la main. -->

Page générée depuis les assets publics et `benchmarks/taxonomy.yaml`. Les règles et limites sont décrites dans [la taxonomie](taxonomie.md). Périmètre : les 29 scénarios officiels du catalogue et leurs 288 failles attendues ; S1h/S4h sont exclus des comptes.

## Architecture visée et architecture mesurée

19/29 scénarios ont une topologie qui réalise l'architecture visée.

| Scénario | Topologie | Visée | Mesurée | Segments | Profondeur de relais | Conforme |
| --- | --- | --- | --- | ---: | ---: | :---: |
| S1 | `flat` | flat | flat | 1 | 0 | oui |
| S2 | `gateway` | flat | flat | 1 | 0 | oui |
| S3 | `nato_lab` | gateway | flat | 1 | 0 | **non** |
| S4 | `ics_scada` | segmented | flat | 1 | 0 | **non** |
| S5 | `building` | star | flat | 1 | 0 | **non** |
| S6 | `star` | star | flat | 1 | 0 | **non** |
| S7 | `edge_cloud` | local_cloud | flat | 1 | 0 | **non** |
| S8 | `multizone` | segmented | flat | 1 | 0 | **non** |
| S9 | `mesh_iot` | flat | flat | 1 | 0 | oui |
| S10 | `flat_variants` | flat | flat | 1 | 0 | oui |
| S11 | `smart_city_3zones` | segmented | flat | 1 | 0 | **non** |
| S12 | `smart_city_large` | segmented | flat | 1 | 0 | **non** |
| S13 | `vlan_segmented` | segmented | segmented | 3 | 0 | oui |
| S14 | `sparse_hardened` | flat | flat | 1 | 0 | oui |
| S15 | `api_authorization` | flat | flat | 1 | 0 | oui |
| S16 | `device_pki` | flat | flat | 1 | 0 | oui |
| S17 | `ota_lifecycle` | flat | flat | 1 | 0 | oui |
| S18 | `cloud_iam_ssrf` | local_cloud | flat | 1 | 0 | **non** |
| S19 | `ot_multiprotocol` | flat | flat | 1 | 0 | oui |
| S20 | `true_multihop` | multi_hop | multi_hop | 3 | 2 | oui |
| S21 | `sparse_low_prevalence` | flat | flat | 1 | 0 | oui |
| S22 | `exploit_diversity` | flat | flat | 1 | 0 | oui |
| S23 | `wireless_firmware_chain` | gateway | flat | 1 | 0 | **non** |
| S24 | `heldout_dual_zone_chain` | multi_hop | multi_hop | 4 | 2 | oui |
| S25 | `heldout_segmented_fanout` | gateway | gateway | 3 | 1 | oui |
| S26 | `heldout_asymmetric_paths` | multi_hop | multi_hop | 4 | 2 | oui |
| S27 | `heldout_three_pivot_cascade` | multi_hop | multi_hop | 4 | 3 | oui |
| S28 | `heldout_provisioning_chain` | flat | flat | 1 | 0 | oui |
| S29 | `heldout_large_sparse` | flat | flat | 1 | 0 | oui |

## Failles par appareil et famille de faille

Nombre de failles attendues ; `·` signale une combinaison absente du corpus.

| Appareil | authentication | access_control | data_exposure | injection | crypto | configuration | update | known_vulnerability | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| router | 1 | · | · | · | · | 23 | · | · | 24 |
| gateway | 4 | · | 3 | · | · | 7 | 9 | 9 | 32 |
| broker | 8 | · | 17 | · | · | 16 | · | · | 41 |
| camera | 9 | · | 1 | · | · | 1 | · | · | 11 |
| sensor | 3 | · | 2 | · | 2 | 1 | 3 | · | 11 |
| ot_controller | 12 | · | 1 | · | 1 | · | · | · | 14 |
| ot_supervision | · | · | · | · | · | · | · | · | 0 |
| iot_platform | 6 | 4 | · | 1 | · | · | · | · | 11 |
| cloud_service | · | 1 | 1 | 1 | · | · | · | · | 3 |
| identity_service | · | · | 1 | · | 1 | 1 | · | · | 3 |
| update_service | · | · | 2 | · | · | · | · | · | 2 |
| host | 20 | 2 | 7 | · | 5 | 7 | · | · | 41 |
| web_app | 12 | 1 | 29 | 11 | 1 | 12 | · | · | 66 |
| database | 16 | · | 4 | · | · | · | · | · | 20 |
| file_server | · | · | 1 | · | · | 5 | · | · | 6 |
| network_service | 2 | · | 1 | · | · | · | · | · | 3 |

## Failles par architecture mesurée et famille de faille

| Architecture | authentication | access_control | data_exposure | injection | crypto | configuration | update | known_vulnerability | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| flat | 71 | 8 | 61 | 12 | 9 | 67 | 12 | 9 | 249 |
| segmented | 10 | · | 2 | 1 | 1 | 6 | · | · | 20 |
| gateway | 1 | · | 2 | · | · | · | · | · | 3 |
| multi_hop | 11 | · | 5 | · | · | · | · | · | 16 |
| star | · | · | · | · | · | · | · | · | 0 |
| local_cloud | · | · | · | · | · | · | · | · | 0 |

## Scénarios par architecture visée et mesurée

| Visée \ mesurée | flat | segmented | gateway | multi_hop | star | local_cloud | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| flat | 13 | · | · | · | · | · | 13 |
| segmented | 4 | 1 | · | · | · | · | 5 |
| gateway | 2 | · | 1 | · | · | · | 3 |
| multi_hop | · | · | · | 4 | · | · | 4 |
| star | 2 | · | · | · | · | · | 2 |
| local_cloud | 2 | · | · | · | · | · | 2 |
