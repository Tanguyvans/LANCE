# Scénarios Scenario Lab écrits à la main

Le compositeur manuel permet de créer plusieurs petits scénarios indépendants sans modifier le catalogue officiel benchmarks/scenarios/ ni le Ground Truth officiel.

Les spécifications d’exemple sont dans benchmarks/scenarios_manual/.

## Composition

    python3 benchmarks/tools/compose_custom.py benchmarks/scenarios_manual/flat_logical_chain.yaml

Le compositeur écrit un bundle sous output/generated_scenarios/ :

- scenario.yaml : scénario public et politique d’outils ;
- topology.yaml : topologie concrète avec les noms résolus ;
- ground_truth.yaml : vulnérabilités, contrôles, chemins et scoring ;
- injection_plan.yaml : fixtures attendues par nœud ;
- verification_plan.yaml : probes et outils requis ;
- matching_contracts.yaml : contrats strict-v3 pour le matching des preuves ;
- execution_plan.yaml : adaptateur, profil provider, fixtures et playbooks compatibles.

La même opération est disponible via POST /api/scenario-generator/compose avec { "scenario": <specification> }.

La composition ne produit un bundle exécutable que si l’adaptateur ansible-proxmox sait associer chaque rôle et chaque Ground Truth à un provider réel. Le bundle peut ensuite être lancé directement avec son ID gen-custom-... dans le pipeline. L’export dashboard reste réservé aux variantes historiques ; les scénarios manuels utilisent leur bundle local et leur lease VMID.

## Construction depuis le dashboard

La vue **Scenario Lab** propose désormais un builder interactif :

1. choisir une topologie ;
2. ajouter les nœuds un par un ;
3. afficher uniquement les vulnérabilités compatibles avec chaque nœud (rôle, profil, service, port et protocole) ;
4. ajouter ou retirer les vulnérabilités individuellement ;
5. composer un bundle validé en mode prévisualisation ou déployable si le profil d’exécution le permet.

Le bouton **Générer aléatoirement** utilise une seed et sélectionne un sous-ensemble cohérent de nœuds reliés ainsi que des findings compatibles. Le résultat passe par le même compositeur et les mêmes validations que la composition manuelle.

Les endpoints correspondants sont :

- GET /api/scenario-generator/builder/topologies
- GET /api/scenario-generator/builder/catalog/<topology_id>
- POST /api/scenario-generator/builder/compose
- POST /api/scenario-generator/builder/random

Les sources officielles sous benchmarks/ restent inchangées. Les bundles manuels sont stockés sous output/generated_scenarios/ et les variantes exécutables apparaissent dans le sélecteur de scénarios du dashboard.

## Structure d’une spécification

    schema_version: 3
    scenario_id: flat-logical-chain
    name: Flat logical chain
    difficulty: medium
    posture: vulnerable

    topology: flat
    execution:
      adapter: ansible-proxmox
      profile: flat_roles

    alterations:
      - type: add_decoys
        parameters: {target: web, count: 2}
      - type: add_noise
        parameters: {count: 1}
      - type: restrict_tools
        parameters:
          phase: verification
          tools: [curl_headers, ssh_login, mqtt_listen]

    packs:
      - manual_flat_chain

    tool_policy:
      recon: [nmap_scan, curl_headers, mqtt_listen]
      verification: [curl_headers, ssh_login, mqtt_listen]
      intrusion: [curl_headers, ssh_login, ssh_exec, mqtt_listen]

    attack_paths:
      - id: P-FLAT-CHAIN
        semantics: logical_chain
        network_hop_depth: 0
        steps:
          - {target: web, finding: MANUAL-WEB-BACKUP, action: recover credentials}
          - {target: ssh, finding: MANUAL-SSH-CREDENTIALS, action: login}
          - {target: mqtt, finding: MANUAL-MQTT-EXPORT, action: subscribe}

topology peut être :

- une référence à benchmarks/topologies/<id>.yaml ;
- une référence avec overrides ;
- une topologie inline contenant au minimum un routeur et un service.

Les noms courts utilisés dans attack_paths (web, ssh, mqtt) sont résolus vers les noms concrets de la topologie. Les IDs de findings sont stables : <template_key>@<device>.

## Packs, profils et Ground Truth

Un pack est placé dans benchmarks/packs/definitions/. Il peut déclarer des vulnérabilités et des contrôles par rôle :

    vulnerabilities:
      web_server:
        - key: WEB-BACKUP
          applies_to: {profiles: [vulnerable]}
          accepted_types: [data_exposure]
          services: [http]
          ports: [80]
          required_tools: [curl_headers]
          verification: GET http://{ip}/backup/

security_profile: vulnerable, hardened ou near_miss sélectionne respectivement les findings positifs ou les contrôles négatifs. Les champs services, ports, protocols, accepted_types, required_tools et verification alimentent le Ground Truth et le contrat de matching.

Le registre partagé src/benchmark/tool_registry.py centralise les services par rôle et les outils compatibles. Le registre d’exécution src/benchmark/manual_execution.py fait le lien séparément entre rôle, injector/verifier Ansible, profil de sécurité et Ground Truth ; un rôle non supporté est refusé avant l’allocation VMID. Une tool_policy qui cite un outil inconnu est rejetée avant toute écriture.

La politique est restrictive : elle peut retirer des outils des configurations normales de l’agent pour les phases recon, verification et intrusion, mais ne peut pas ajouter une capacité absente de la configuration ou du profil de sécurité. Les outils de gestion des livrables restent disponibles.

## Catalogue des altérations

Les altérations sont appliquées dans l’ordre déclaré et sont conservées dans alteration_plan.yaml. Elles sont déterministes avec le seed de la composition ou le seed de l’altération.

- Topologie et adressage : rotate_ips, rename_hosts, rotate_subnets, topology_flatten, topology_segment, topology_add_pivot, topology_remove_direct_path.
- Services et échelle : service_add, service_remove, service_configuration, topology_scale, add_decoys, rotate_ports.
- Cycle de vie : state_transition, restart_service, service_window, failure_mode.
- Réseau avancé : network_impairment, firewall_rule, nat_rule, dns_mutation, traffic_noise.
- Posture : swap_profiles, harden_all, vulnerable_all, near_miss_controls.
- Ground Truth : finding_selection, vulnerability_density, vulnerability_parameters, control_mutation, exploit_precondition, finding_outcome, finding_confidence, false_positive.
- Chemins : logical_chain, network_pivot, alternate_paths, remove_prerequisites.
- Reachability : topology_remove_direct_path, deny_direct_access, allow_egress, restrict_egress.
- Données et identité : data_fixture, session_seed, log_mutation, identity_model, trust_relationship, mfa_mutation.
- Détection : detection_rule, detection_noise, adaptive_defense.
- Outils et exécution : restrict_tools, require_tools, tool_budget, phase_timeout, attempt_budget, resource_limit, tool_output_profile.
- Objectifs et composition : scenario_objective, termination_condition, scoring_profile, bonus_condition, variant_constraints, compatibility_requirements.
- Évaluation : add_noise, degrade_evidence, evidence_surface, severity_shift, scoring_weights.

Le catalogue est consultable par GET /api/scenario-generator/alterations. Chaque entrée indique si elle relève d’un provider réel ou du mode preview. Les altérations avancées sont composables avec `execution: {profile: preview}` : elles produisent un bundle Ground Truth complet, mais aucun lease VMID n’est créé. Pour obtenir un bundle réellement exécutable, il faut choisir un provider compatible ou ajouter son adaptateur ; la composition ne masque pas cette incompatibilité.

Les champs lifecycle, environment, identity, detection, evaluation, objectives, constraints, compatibility, data_fixtures et failure_modes sont recopiés dans le scénario et le Ground Truth. Les contraintes peuvent imposer des rôles, un nombre de services/findings ou des sémantiques de chemins ; compatibility peut imposer un profil provider et des clés de findings.

## Topologie plate et multi-hop

Une topologie plate peut quand même décrire une dépendance logique entre plusieurs findings. C’est le cas de flat_logical_chain.yaml : network_hop_depth: 0 et semantics: logical_chain.

Un vrai pivot réseau doit être explicitement marqué comme tel avec des liens et des sous-réseaux distincts. true_multihop_reference.yaml est un cas de référence secondaire :

    attack_paths:
      - id: P-TRUE-MULTIHOP
        semantics: network_pivot
        network_hop_depth: 2
        steps:
          - {target: entry, finding: F16-RELAY-CONFIG}
          - {target: relay, finding: F16-RELAY-CREDS}
          - {target: vault, finding: F16-VAULT-NOAUTH}

Le multi-hop n’est donc pas imposé par le modèle de scénario : il s’agit d’une propriété d’un scénario donné, au même titre qu’un scénario durci, un service unique, une mauvaise configuration HTTP ou une chaîne de dépendances logique. Le profil true_multihop est un provider spécialisé qui réutilise le playbook S20 et vérifie ses adresses VLAN fixes ; les autres scénarios restent sur flat_roles ou nécessitent l’ajout d’un nouveau provider.

## Validation attendue

Avant production du bundle, le compositeur vérifie notamment :

- références de topologie et de packs ;
- noms d’outils ;
- unicité des nœuds et des adresses ;
- existence des devices utilisés par le Ground Truth et les chemins ;
- cohérence entre findings positifs, plan d’injection et contrats ;
- compatibilité entre required_tools et tool_policy.

Pour exécuter un bundle composé, transmettre son ID gen-custom-... à /api/pipeline/start comme scenario_id, puis utiliser /api/pipeline/teardown avec le même ID. Les leases et overlays sont sous output/scenario_deployments/, et les VMID sont alloués hors des plages officielles.

Les fichiers officiels ne sont jamais modifiés par cette voie.
