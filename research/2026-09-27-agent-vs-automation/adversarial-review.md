# Contre-revue de la recherche

**Date : 29 septembre 2026. Statut : contrelecture GPT intégrée ; revue Muse en
attente d'autorisation de transmission.** Cette page consigne les critiques
réelles et les arbitrages ; un accord entre modèles ne valide pas une hypothèse
expérimentale.

## Ce qui a été réalisé

Trois agents GPT ont inspecté séparément benchmark/évaluation, contexte et
apport LLM. L'orchestrateur a relu les sources principales et reproduit les
probes. L'agent chargé de la comparaison LLM a ensuite relu les deux autres
études pour chercher erreurs de portée et recommandations fragiles.

| Critique de la contrelecture GPT | Arbitrage et changement retenu |
| --- | --- |
| La probe OTA ne vérifie aucune signature cryptographique. | Formulation corrigée en « trace déclarant une signature valide ». Le défaut est l'admission d'une observation insuffisante ; son crédit dans le score complet n'est pas reproduit. |
| Le mémo compact local ne caractérise pas A1 dans D1/A1 full. | C6 borné à la phase 3 utilisant `_uses_compact_local_moe()` ; distinction explicite dans l'analyse. |
| Le prompt d'intrusion compact remplace celui du chemin full. | Contradiction de consignes limitée au chemin utilisant le template full. |
| Interdire tout rejeu supprimerait aussi des reprises légitimes. | Critère remplacé par absence de rejeu involontaire et justification/comptabilisation des répétitions autorisées. |
| Le filtre de rédaction à contexte vide peut rejeter une affirmation pourtant soutenue. | Risque de rejet indu ajouté, sans fréquence attribuée. |
| Un nonce réfléchi ne prouve pas une exécution. | Calibration exigeant distinction réflexion/exemple/effet, contrôle différentiel ou attestation d'état. |
| Déplacer un indice ne suffit pas à mesurer l'adaptation. | Strate à observations normalisées et contraste sur révision effective des décisions ajoutés. |
| Un précontrôle comportemental peut altérer l'état initial. | Remise à zéro après précontrôles perturbateurs, puis contrôle final non perturbateur proposés. |

La comparaison de représentations a également été précisée : mêmes capacités
de lecture pour isoler la projection ; retrait des lectures dans une ablation
distincte. Cela évite d'attribuer à la compression l'avantage d'un outil fourni
à un seul bras.

## Muse : état exact

Le skill utilisateur `muse-agent` a été lu. La commande préparée emploie
`muse-spark-1.3`, effort `high`, avec workspace explicitement trusted, écritures
et shell désactivés, aucun journal de session persistant. Muse Code local :
`1.4.0 (1.4.0-R4302.1)`.

Le contrôle automatique a refusé le lancement avant exécution : il a considéré
que l'envoi au service externe d'un résumé issu du dépôt demandait une autorisation
plus explicite malgré la demande d'utiliser Muse. L'utilisateur a été interrogé
sur l'envoi du résumé et la lecture du code, en excluant secrets et inventaire local.
**Aucun résultat Muse disponible à cette étape.** Le refus n'est pas une critique
scientifique des conclusions GPT.

La synthèse à transmettre est concrète : constats, fichiers/lignes, exemples
reproduits, limites de portée et conclusions proposées. La contre-revue devra
noter pour chaque point « confirmé / à nuancer / rejeté / non vérifié », et
fournir ses propres preuves. Les questions restantes sont :

1. Les défauts des diagnostics sont-ils reproduisibles dans le chemin complet, et quels scores affectent-ils réellement ?
2. Quels validateurs ont besoin d'une attestation de cible et lesquels suffisent avec des réponses protocolaires attribuées ?
3. Le niveau de précontrôle proposé est-il proportionné au pilote, sans exiger une refonte entière ?
4. La troncature avant journal est-elle compensée ailleurs pour certains outils ?
5. Une projection déterministe mieux conçue suffit-elle avant d'ajouter des lectures ciblées ?
6. La baseline D1 est-elle suffisamment forte pour la portée revendiquée ? Quelles connaissances doivent être partagées ou gelées ?
7. Les décisions préenregistrées permettraient-elles réellement d'abandonner le LLM comme décideur si le gain est absent ?

Après une revue Muse autorisée et terminée, conserver ici date/version,
périmètre lu, verdicts et arbitrages Codex. Vérifier le code et les contre-exemples
avant de promouvoir une suggestion dans les études ou la documentation.
