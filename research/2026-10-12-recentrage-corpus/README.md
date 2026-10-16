# Plan V2 : questions, scénarios et réalisation

**Cycle de vie : Actif** — étude commencée le **2026-10-12**.
Dernière révision : **2026-10-16 21:43 (Europe/Brussels, UTC+02:00)**.
Statut : **conception V2 consolidée ; qualification SSH native documentée, hors campagne confirmatoire**.

## Question et périmètre

Dans quelles situations un LLM apporte-t-il un gain utile face à une
automatisation conditionnelle compétente, à informations, outils, droits
et budgets comparables ? Le résultat peut être favorable, nul ou défavorable
au LLM. Cette étude prolonge [agent contre automatisation](../2026-09-27-agent-vs-automation/README.md)
et alimente les [objectifs AsiaCCS 2027](../../objectifs/asiaccs-2027/README.md).

## Comment lire le plan

La lecture suit **question → scénario → configurations de test sélectionnées**.

| Élément | Rôle | Où le lire |
| --- | --- | --- |
| Questions de lecture | Comprendre ce que chaque test permet d’examiner | [Carte des six questions](structuration-corpus.pdf#nameddest=sec%3Aquestions) |
| Scénarios `s_...` | Fixer objectif, décision, propriété, preuve et mesure | [Catalogue par question](structuration-corpus.pdf#nameddest=sec%3Ascenarios) |
| Configurations de test (types) | Préciser les traitements sélectionnés ; `T` compte les configurations | [Exemple complet MQTT](structuration-corpus.pdf#nameddest=sec%3Aworked-example) et [plan structuré](coverage-plan.json) |
| Ensembles techniques | Relier parents, variantes et réplications | [Index avec liens vers les fiches](structuration-corpus.pdf#nameddest=sec%3Acomparison-index) ; 25 ensembles conservés |
| Tableau scénario/benchmark | Relier chaque fiche à sa tâche, sa mesure et son hypothèse | [Matrice exhaustive](#scénarios-benchmarks-mesures-et-hypothèses-llm) |
| Ordre de réalisation | Décider quoi construire maintenant et ce qui en dépend | [Feuille de route](structuration-corpus.pdf#nameddest=sec%3Aimplementation-path) et [première comparaison SSH](structuration-corpus.pdf#nameddest=sec%3Afirst-comparison) |

Le **corps principal** présente question/méthode, comparateurs et mesures,
carte des questions, complexité, priorités et limites. Les annexes conservent
les 44 fiches, les liens techniques, les retours IoT, les détails de couverture
et les correspondances historiques. Une fiche possède une seule définition.

## Les six questions de lecture

| Question | Ce que l’on cherche à examiner | Fiches | Exemples |
| --- | --- | ---: | --- |
| **Établir une preuve** | Le LLM distingue-t-il mieux une violation étayée, un témoin protégé et une observation insuffisante ? | 9 | `s_injection_preuves`, `s_ssh_identifiants` |
| **Comprendre le contexte et les droits** | Le LLM relie-t-il mieux identité, objet, opération et règle publique pour choisir et interpréter un contrôle ? | 12 | `s_api_organisations`, `s_mqtt_commande` |
| **Interpréter un nouveau contrat** | Le LLM exploite-t-il mieux un contrat public nouveau pour sélectionner et réaliser les vérifications autorisées ? | 2 | `s_edge_contrat`, `s_ota_contrat` |
| **Suivre un état et une séquence** | Le LLM choisit-il mieux l’ordre des contrôles et attribue-t-il correctement une observation à l’état qui l’a produite ? | 4 | `s_cache_identites`, `s_session_cloturee` |
| **Planifier un parcours sous contrainte** | Le LLM choisit-il mieux les vérifications, prérequis et chemins lorsque l’architecture ou le budget limite la recherche ? | 12 | `s_reseau_distance`, `s_audit_budget` |
| **Réviser une décision après un changement** | Le LLM révisable tire-t-il un avantage utile d’un retour nouveau face à des branches conditionnelles et à un plan initial figé ? | 5 | `s_mqtt_reprise`, `s_reseau_deplacement` |

Ces groupes organisent la lecture ; ils ne sont ni six capacités indépendantes,
ni six scores agrégés. Les unités, dénominateurs et contrastes restent propres
aux tâches : **M-T**, évaluation ciblée ; **M-G**, audit global ; **M-I**, interprétation hors ligne ; **M-E**, diagnostic d’état ; **M-C**, diagnostic de couverture. Un même ensemble
technique peut traverser plusieurs questions : lecture et formats MQTT
concernent la preuve, tandis que la reprise MQTT concerne la révision.

**Limite visible : 35/44 fiches sont uniquement locales (`d=0`) et 36/44 uniquement à carte complète (`K2`).** L’architecture inconnue n’est donc pas couverte par le premier lot local ; la [matrice réseau](structuration-corpus.pdf#nameddest=sec%3Anetwork-matrix) montre les configurations retenues.

Les profils séparent information initiale, nombre de défauts, accès réseau,
état, preuve et budget. Ils ne définissent pas une échelle unique de difficulté.
Les 44 fiches, 25 ensembles, **216 types et 456 bras conditionnels** par
instance/répétition communes sont conservés ; les 24 types avec plan figé
restent identiques. Une qualification native SSH est consignée ci-dessous ; les attestations d’admission confirmatoire du corpus restent à produire.

Une **variante de scénario** est une fiche liée à un parent ; une **configuration de test** est un type sélectionné dans une fiche. Un **bras** est la politique exécutée (D1 sans LLM, A1 avec LLM révisable) ; une **instance** est un monde paramétré et une **répétition** un nouvel essai après reset. Ces objets ne sont pas des familles indépendantes.

## Scénarios, benchmarks, mesures et hypothèses LLM

Les **six groupes de lecture** organisent les questions ; les **cinq tâches de benchmark**
ci-dessous déterminent ce qui est mesuré. Les bénéfices envisagés sont des **hypothèses à tester**.

- **Ciblé (M-T)** : proportion d’essais avec objectif évalué et preuve valide dans le budget.
- **Audit de périmètre (M-G)** : nombre de défauts confirmés par essai au budget fixé, zéros inclus.
- **Interprétation (M-I)** : proportion de conclusions conformes au dossier, abstention correcte incluse.
- **État (M-E)** : proportion de diagnostics corrects de l’état observable.
- **Couverture (M-C)** : proportion de diagnostics de couverture étayés dans le graphe autorisé fini.

Pour M-T, les lignes résument surtout le cas vulnérable ; F0 exige les contrôles réellement
exécutés, un témoin légitime fonctionnel et aucun faux constat. Un essai silencieux ne suffit pas.
Les fiches détaillent les mesures secondaires. Pour toutes les tâches, publier erreurs,
couverture et coûts avec les résultats ; sondes réseau non applicables aux dossiers M-I.

Comparer à une automatisation compétente de mêmes informations/outils/droits/budgets.
Les quatre M-I utilisent **`rules_interpreter` / `llm_interpreter`**, sur les mêmes observations
figées. Les scénarios interactifs utilisent **D1/A1**, avec A0 seulement dans les types déjà retenus.

| Scénario | Type de benchmark | Mesure primaire résumée | Hypothèse de plus-value LLM |
| --- | --- | --- | --- |
| `s_ssh_identifiants` | Ciblé (M-T) | Session faible et lecture privée prouvées | Confirme-t-il l’accès avec moins d’erreurs ou de coût qu’un automate de dictionnaire ? |
| `s_mqtt_lecture` | Ciblé (M-T) | Réception anonyme d’un message privé frais | Distingue-t-il mieux connexion, message public et fuite privée ? |
| `s_ot_ecriture` | Audit de périmètre (M-G) | Nombre de points modifiés sans droit, avec preuve d’état | Choisit-il les points utiles et confirme-t-il davantage d’écritures réelles ? |
| `s_injection_effet` | Ciblé (M-T) | Effet interdit prouvé dans le langage de commande borné | Choisit-il mieux les sondes et témoins qui confirment un effet réel ? |
| `s_injection_preuves` | Interprétation (M-I) | Conclusion conforme au dossier, abstention incluse | Interprète-t-il mieux provenance, contradictions et preuves insuffisantes ? |
| `s_ota_preuves` | Interprétation (M-I) | Diagnostic de version conforme aux preuves disponibles | Distingue-t-il mieux annonce, réception et installation persistante ? |
| `s_mqtt_formats` | Interprétation (M-I) | Conclusion correcte par format et vue brute/normalisée | Reste-t-il plus exact face aux formats, après normalisation commune aussi ? |
| `s_ot_formats` | Interprétation (M-I) | Conclusion correcte par représentation et vue | Interprète-t-il mieux les formats industriels face à un décodeur compétent ? |
| `s_ota_integrite` | Ciblé (M-T) | Altération interdite persistée prouvée | Apporte-t-il un gain face aux contrôles déterministes d’intégrité ? |
| `s_api_organisations` | Ciblé (M-T) | Lecture inter-organisation prouvée | Choisit-il mieux les contrôles quand rôles et propriétaires sont recomposés ? |
| `s_edge_portee` | Ciblé (M-T) | Effet hors portée autorisée démontré | Relie-t-il mieux identité, ressource et droits pour vérifier la portée ? |
| `s_api_conditions` | Ciblé (M-T) | Effet contraire à la politique rôle/état démontré | Choisit-il mieux les contrôles combinant rôle et état métier ? |
| `s_ssh_privileges` | Ciblé (M-T) | Effet administratif interdit attesté | Évite-t-il mieux de déduire un privilège administratif d’une simple session ? |
| `s_tls_revocation` | Ciblé (M-T) | Session sous certificat révoqué attestée | Vérifie-t-il mieux l’accès effectif au-delà de la validité de signature ? |
| `s_jeton_destinataire` | Ciblé (M-T) | Accès au service B avec un jeton destiné à A prouvé | Choisit-il les bonnes paires jeton/service et confirme-t-il leur effet ? |
| `s_certificat_identite` | Ciblé (M-T) | Mauvais principal établi puis effet induit prouvés | Attribue-t-il mieux l’effet au principal réellement établi ? |
| `s_passerelle_identite` | Ciblé (M-T) | Rupture de liaison d’identité et effet canari prouvés | Corrèle-t-il mieux identité et effet à travers passerelle et backend ? |
| `s_mqtt_commande` | Ciblé (M-T) | Commande interdite effectivement appliquée | Distingue-t-il mieux lecture, publication et effet de commande ? |
| `s_firmware_emetteur` | Ciblé (M-T) | Installation hors politique d’émetteur prouvée | Sépare-t-il mieux signature valide et autorisation de l’émetteur ? |
| `s_fichiers_perimetre` | Ciblé (M-T) | Lecture hors espace autorisé attestée | Choisit-il mieux les sondes de frontière entre chemins et propriétaires ? |
| `s_sql_perimetre` | Ciblé (M-T) | Sélection de données hors périmètre causalement attestée | Exploite-t-il mieux le schéma public et les témoins pour vérifier la frontière ? |
| `s_edge_contrat` | Ciblé (M-T) | Destination interdite effectivement atteinte | Exploite-t-il mieux un contrat public nouveau pour choisir les requêtes ? |
| `s_ota_contrat` | Ciblé (M-T) | Violation persistante de la politique de version prouvée | Extrait-il mieux la séquence nécessaire d’un nouveau contrat public ? |
| `s_cache_identites` | Ciblé (M-T) | Réponse privée inter-identités attribuée au cache | Choisit-il mieux l’ordre des requêtes et leur attribution historique ? |
| `s_ota_version` | Ciblé (M-T) | Transition de version interdite persistée | Trouve-t-il mieux les séquences utiles et confirme-t-il l’état persistant ? |
| `s_session_cloturee` | Ciblé (M-T) | Accès privé après clôture attesté | Suit-il mieux clôture, renouvellement et identité de session ? |
| `s_provisioning_rejeu` | Ciblé (M-T) | Second privilège effectivement émis prouvé | Distingue-t-il mieux réponse reçue et émission réelle d’un second droit ? |
| `s_web_sauvegardes` | Audit de périmètre (M-G) | Nombre de sauvegardes privées confirmées au budget fixé | Priorise-t-il mieux les pistes utiles et rejette-t-il les leurres ? |
| `s_audit_budget` | Audit de périmètre (M-G) | Nombre de défauts confirmés à chaque budget fixé | Répartit-il mieux les vérifications pour confirmer davantage au même budget ? |
| `s_chaine_defauts` | Ciblé (M-T) | Objectif terminal prouvé par la chaîne à trois défauts | Enchaîne-t-il mieux les prérequis obtenus grâce aux trois défauts ? |
| `s_prerequis_conjoints` | Ciblé (M-T) | Lecture terminale hors autorisation après prérequis ET | Acquiert-il les prérequis utiles en évitant les tentatives prématurées ? |
| `s_prerequis_alternatifs` | Ciblé (M-T) | Lecture terminale hors autorisation après une voie suffisante | Choisit-il à moindre coût une alternative disponible dès l’entrée ? |
| `s_reseau_distance` | Ciblé (M-T) | Bon actif identifié, atteint et évalué selon K et profondeur | Découvre-t-il un parcours utile avec moins d’essais selon la carte et la distance ? |
| `s_relais_acces` | Ciblé (M-T) | Cible atteinte et évaluée après un ou deux relais | Orchestre-t-il mieux les sessions légitimes nécessaires à la cible ? |
| `s_tls_distant` | Ciblé (M-T) | Cible atteinte et évaluée selon la révocation | Combine-t-il mieux recherche du parcours et vérification de révocation ? |
| `s_reseau_alias` | Ciblé (M-T) | Bon actif identifié, atteint et évalué malgré les alias | Corrobore-t-il mieux l’identité de l’actif face aux alias ambigus ? |
| `s_dns_origine` | Ciblé (M-T) | Bon actif atteint et évalué depuis les origines autorisées | Choisit-il mieux le point de résolution utile pour atteindre le bon actif ? |
| `s_mission_distracteurs` | Ciblé (M-T) | Cible de mission atteinte et évaluée, par F0/F1/F3 | Reste-t-il mieux centré sur la mission malgré les autres indices ? |
| `s_reseau_inaccessible` | Couverture (M-C) | Diagnostic accessible/évalué/non évaluable étayé | Diagnostique-t-il mieux une couverture insuffisante sans inventer de constat ? |
| `s_mqtt_reprise` | Ciblé (M-T) | Évaluation MQTT étayée en mondes stable et perturbé | Améliore-t-il l’évaluation après changement face à D1/A0, branches génériques autorisées ? |
| `s_ot_reprise` | Ciblé (M-T) | Évaluation OT étayée par monde, sur tous les essais | Réagit-il mieux à une nouvelle référence de point que les branches D1/A0 ? |
| `s_reseau_obstacle` | Ciblé (M-T) | Évaluation terminale étayée par bloc budget ou obstacle | Réoriente-t-il mieux le parcours après obstacle, dans le bloc prévu avec A0 ? |
| `s_ota_interruption` | État (M-E) | Diagnostic correct de l’état observable après transaction | Choisit-il mieux les inspections utiles au diagnostic que D1/A0 ? |
| `s_reseau_deplacement` | Ciblé (M-T) | Bon actif retrouvé et évalué en mondes stable et déplacé | Retrouve-t-il mieux le bon actif après réadressage que les branches D1/A0 ? |

La [même matrice dans le PDF](structuration-corpus.pdf#nameddest=sec%3Abenchmark-matrix)
renvoie aux fiches détaillées. Elle est issue de `scenario_plan.benchmark_mapping`,
avec type et comparateurs dérivés des contrats existants.

Les scénarios de reprise/réadressage et d’interruption gardent leurs **24 types A0**.
L’obstacle réseau sépare bloc budget et bloc adaptation B2. Les contrats nouveaux et
les alternatives disponibles dès l’entrée ne prouvent pas une adaptation causale.
M-C ne demande aucune faille cachée inaccessible ; M-E ne demande pas de deviner un
défaut dormant indiscernable. Une réussite réseau exige aussi l’évaluation terminale.

Une D1 ou un interpréteur à règles aussi bon ou meilleur reste une issue utile.
Une égalité sur la mesure primaire peut coexister avec un gain de coût, à analyser
séparément avec marge et procédure appropriées. Les questions « mieux » utilisent
les mesures primaires, secondaires et coûts retenus, sans score cognitif ajouté.
Un écart non significatif ne prouve pas l’équivalence ; les marges et analyses
restent à calibrer puis geler. Aucun nom, configuration, bras ou priorité ajouté.

## Avancement consolidé

Dernière consolidation : **2026-10-16 21:43 (Europe/Brussels, UTC+02:00)**. La conception conserve les **44 scénarios,
25 ensembles, 216 configurations et 456 bras conditionnels**. Les documents
historiques et la revue IoT figée gardent leurs dates et leur portée.

| Élément | État établi | Suite |
| --- | --- | --- |
| Organisation V2 et correspondance scénario/mesure/hypothèse | Conception structurée et contrôlée | Admission expérimentale par scénario |
| `s_ssh_identifiants` | **Qualification native réussie le 15 octobre** : script et Qwen corrects sur les cas protégé/vulnérable | Métriques, effectifs et gel confirmatoire à établir |
| `s_mqtt_lecture` | Contrat défini ; réalisation et qualification à faire | **Prochain scénario à construire après cette consolidation** |
| `s_api_organisations`, `s_mqtt_reprise`, `s_cache_identites` | Contrats définis | Poursuivre dans cet ordre après MQTT |
| `s_injection_preuves` et parcours réseau | Préparation hors ligne et chantier parallèle distincts | Leurs propres contrôles restent requis |

### Qualification SSH déjà obtenue

La [référence technique et le bilan](../../docs/benchmark/agent-vs-automation-cli.md#qualification-native-vérifiée-le-15-octobre-2026)
consignent le [workflow 38769747406](https://github.com/Tanguyvans/LANCE/actions/runs/38769747406),
code exécuté `63203a8dc77ebb9d4afcc1190b902c9da5e29d84`, intégré par `4f29d67`.
Sur pve-nato, un LXC neuf précède chacun des quatre bras. Script D1 et Qwen
3.8 27B donnent chacun le verdict correct en posture protégée et vulnérable,
avec quatre appels SSH par bras. Les durées de politique sont 0,3 s pour le
script, 17,7 s et 17,9 s pour Qwen ; elles excluent la création et les précontrôles.
Les 120 fichiers, le nettoyage et les deux archives SHA-256 sont vérifiés dans
ce bilan. Les références, empreintes et résultats sont repris dans
`coverage-plan.json`, sous `implementation_tracking.ssh_calibration`.

La politique LLM est bornée et distincte du pipeline A1 complet. Une répétition
par posture qualifie l’instrument ; `mt_admissible: false` et
`measurement_status: evidence_only_not_admitted` sont conservés. Aucun gain
général du LLM, coût facturé UMONS ou coût matériel n’est établi. Les limites de
calibration ne deviennent pas rétroactivement le budget B2. Cette consolidation
reprend les sources existantes sans relancer les essais ni réexpertiser les
archives privées sur nato. Les tentatives antérieures restent dans la référence.

## Quoi construire maintenant

Commencer par la préparation des preuves, les contrôles, le reset et la parité ;
`s_injection_preuves` sert à la calibration hors ligne et conserve son travail propre.
La qualification SSH étant acquise dans son périmètre borné, poursuivre par
**`s_mqtt_lecture`, `s_api_organisations`, `s_mqtt_reprise`, `s_cache_identites`**,
dans cet ordre. La campagne confirmatoire SSH reste à préparer séparément.

| Place | Travail | Scénarios prioritaires |
| --- | --- | --- |
| Étape 1 | Comparaison locale | SSH qualifié, puis les quatre scénarios ci-dessus |
| Étape 2 | Séquences IoT | `s_mqtt_commande`, `s_session_cloturee`, `s_provisioning_rejeu` |
| Étape 3 | Nouveaux contrats | `s_edge_contrat`, puis socle `s_ota_version` avant `s_ota_contrat` |
| En parallèle | Parcours réseau | `s_reseau_distance`, après ses propres contrôles |
| Selon une question retenue | Extensions ciblées | Variantes et réplications après qualification |
| Étude distincte | Sécurité de l’auditeur | Résistance aux consignes hostiles lues par l’agent (EC14), séparée du succès de la mission |

Ce sont des priorités de construction. Les étapes 2 et 3 dépendent chacune
techniquement de l’étape 1 ; l’étape 3 ne dépend pas de l’étape 2. Le réseau
peut commencer pendant l’étape 1. Le classement par question ne change aucune
dépendance et ne bloque pas la première comparaison locale.

## Exemple complet et première comparaison

L’[exemple MQTT entièrement déplié](structuration-corpus.pdf#nameddest=sec%3Aworked-example)
montre les deux configurations existantes F0/F1, D1/A1, quatre exécutions par
instance et répétition communes, les entrées publiques, l’oracle privé, les
contrôles, les preuves, les verdicts et l’archive. Il ne contient aucun résultat
observé et n’ajoute aucun type ni bras.

La [première comparaison et sa qualification](structuration-corpus.pdf#nameddest=sec%3Afirst-comparison)
reste **`s_ssh_identifiants`**, K2, `d=0`, configurations `t01` protégée et `t02`
vulnérable, D1/A1. La fixture réelle, la référence D1 et la politique LLM bornée ont déjà été
qualifiées ; la portée exacte et les preuves sont consignées ci-dessus. Le
pipeline A1 complet, l’admission M-T et le gel confirmatoire restent distincts.
Le plan précise ensuite admission, split, gel et règle de gain utile de réussite avec
garde-fous sur contrôles protégés, faux constats et coût.

Les marges utiles, plafonds B2, effectifs et méthode d’incertitude restent
**à calibrer puis geler** ; jusque-là, la portée est une calibration descriptive.
Les faux constats ou coûts manquants ne valent pas zéro ; un garde-fou non établi rend la conclusion inconclusive. Une absence de différence significative ne prouve pas une équivalence ; les gains de coût restent publiés séparément. Le passage
à MQTT, contexte, reprise et état dépend de la qualification technique, sans
exiger une victoire LLM. Les noms et l’ordre de construction restent inchangés.

## Documents et reproduction

- **[Plan V2 — PDF](structuration-corpus.pdf)** · [source LaTeX](structuration-corpus.tex) :
  révision **2026-10-16 21:43 (Europe/Brussels, UTC+02:00)** ; corps principal
  centré sur les décisions, catalogue en annexe selon six questions.
  Exemple MQTT complet, première comparaison SSH et liens internes entre fiches.
  Matrice complète scénario/benchmark/mesure/hypothèse ajoutée.
  Consolidation de la qualification SSH existante et de la suite MQTT.
  La révision précédente du 15 octobre à 14:49 comptait 58 pages relues ;
  la vérification de cette nouvelle version est consignée en fin de README.
- [Plan structuré](coverage-plan.json) : `question_organization` est la vue
  de lecture, `benchmark_mapping` définit la matrice pédagogique,
  `worked_example` et `first_implementation_comparison` précisent les
  deux exemples de conception, `reading_question` rattache chaque fiche et `comparison_sets`
  conserve les relations techniques. `implementation_priority` définit la
  construction ; `scenario_naming` conserve les anciens noms. Les champs
  `cells` et `extension_scenarios` sont uniquement le stockage historique.
  `implementation_tracking` consigne séparément la calibration SSH et le prochain
  scénario. Ce JSON reste une conception avec suivi, pas un manifeste d’exécution.
- [Inventaire statique et empreintes](coverage-snapshot.json), reproduit par
  [coverage_snapshot.py](../../benchmarks/experiments/research-review/coverage_snapshot.py).
  Depuis la racine :
  `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. .venv/bin/python benchmarks/experiments/research-review/coverage_snapshot.py`.
- [Revue IoT et CTF — PDF](revue-iot-ctf.pdf) · [LaTeX](revue-iot-ctf.tex) ·
  [registre](revue-iot-ctf.json) : revue figée au **2026-10-15 11:44
  (Europe/Brussels, UTC+02:00)**, validée indépendamment à 11:48 ; 40 sources,
  dix propositions et quinze cas limites. Leurs dispositions sont conservées.
- [Proposition de recentrage](proposition-conditions.pdf) · [LaTeX](proposition-conditions.tex),
  révision du 12 octobre à 21:25 ; [état des lieux](etat-des-lieux-plateforme.pdf) ·
  [LaTeX](etat-des-lieux-plateforme.tex), révision du 12 octobre à 22:11.

Les noms en `s_...` désignent les propositions V2. Les références qualifiées
« catalogue » restent historiques ; la campagne Muse et ses identifiants
sont inchangés. Aucun run ni déploiement ne résulte de cette révision.

## Historique des révisions et validations

<details>
<summary>Afficher les validations des versions antérieures</summary>

Les journaux ci-dessous décrivent leurs versions respectives. La validation
de la structure courante est consignée à la fin de ce README.

Les versions du 12 octobre ont été relues (source + PDF) ; leurs verdicts
restent dans les journaux de cette date. La révision du rapport de couverture
du 14 octobre fait l'objet d'une nouvelle relecture indépendante ci-dessous.
Ces relectures ne constituent pas une validation expérimentale.

## Validation précédente (rapport du 14 octobre à 22:20)

- Inventaire reproductible, cohérence des 24 cellules et empreintes vérifiés.
- Source compilée avec le compilateur de l'éditeur et exportée en PDF avec LaTeX.
- Relecture indépendante par `coverage_review`, source, plan JSON et **10 pages finales avec noyau V2** : validée le **2026-10-14 22:23 (Europe/Brussels, UTC+02:00)**. Aucun débordement, coupe ou tableau illisible constaté ; corrections de méthode et de rendu vérifiées.
- Version relue : source SHA-256 `da8b2471809fed45e15cc5f2c88585a9db515fc5c8f6cc807f1f7c0830a66459`, PDF SHA-256 `2d446254094dea915451d19db43f164ce9e2686c249736f18bbe4c3137e818cb`. L’inventaire final (96 sources) a été reproduit à l’identique par le relecteur.
- Aucune modification de `src/`, du catalogue, des vérités terrain ou du
  manifeste pilote ; aucun run ni déploiement lancé pour cette étude.

## Validation précédente du noyau (révision du 14 octobre à 22:56)

- Les 24 identifiants et leurs six groupes, les 12 priorités, les témoins
  protégés, les **134 types sélectionnés** et les **284 bras par instance
  et répétition communes** ont été contrôlés. Ce dernier nombre est une
  charge conditionnelle : `268*I*R` pour deux politiques, plus `16*I*R`
  pour A0 ; aucun effectif d'instances ou de répétitions n'est recommandé.
- Le modèle précédent de 92 types est remplacé par cette sélection,
  sans addition des deux plans. Les 108 combinaisons du noyau V2 restent
  un espace de conception, pas une campagne à multiplier par ce plan.
- Compilation dans l'éditeur réussie ; export LaTeX et inspection des
  **19 pages finales** par l'auteur et le relecteur indépendant
  `scenario_plan_review`. Relecture validée le **2026-10-14 22:59
  (Europe/Brussels, UTC+02:00)**, sans réserve bloquante de rendu ou de méthode.
- Version relue : source SHA-256
  `9c70ae8bad02a5dd9472347c888e4899392e3e465df5b9ea7941f4845ce2cd83` ;
  PDF SHA-256
  `62ab7448d3fefa22ec5afb80cb01844a169f9990b3c0a110ae1828f9477b1e8f`.
  L'inventaire de **99 sources** a été reproduit à l'identique par le relecteur.
  Cette validation documentaire n'atteste ni faisabilité runtime ni gain.
- Confirmation à **23:00** après clarification des briefings K0 et séparation
  des sœurs protégées et précontrôles causaux dans le JSON, sans changement
  de source/PDF : plan SHA-256
  `44ccdb879501253ac37d3eaf0c771342e05031b40cffe78238eb9215515cb4b9` ;
  inventaire SHA-256
  `5f24afa7443b794e4306de83b8a7784b2329a6a388162e97a66bded095d13ed8`.
- Aucune modification du code applicatif, du catalogue officiel, des
  vérités terrain ou du manifeste de campagne ; aucun run ni déploiement.

## Validation précédente de l'extension (révision du 15 octobre à 00:09)

- Contrôles du plan : 44 identifiants dans dix groupes, 216 types uniques,
  456 bras conditionnels, 24 types avec A0 ; témoins sans défaut prévus et
  preuves de réalisation non renseignées. Les 12 priorités locales du
  noyau et son prototype V2-S24 conservent leur périmètre.
- Relecture indépendante des ajouts par `expanded_scenario_review` :
  distinction S29 liaison certificat/principal, état indiscernable S37,
  distracteurs S42 et couverture S43 clarifiés avant rendu.
- Compilation dans l'éditeur et export LaTeX réussis. Les **27 pages
  finales** ont été contrôlées par l'auteur et le relecteur indépendant
  `expanded_scenario_review` ; verdict validé le **2026-10-15 00:12
  (Europe/Brussels, UTC+02:00)**, sans réserve bloquante de fond ou de rendu.
- Empreintes finales : source SHA-256
  `d69424af75b689b6dee7daff04e4623da88d049bfb1296996a3b887fbce3f25e` ;
  PDF `851d444c44093c6067134ab136e0defe1355f237461a8ed5e5b506cf0621791c` ;
  plan `2423cdaf8ed6124f9a1a652268bc466656709f09bb303a57a14721bc67d77e17` ;
  inventaire `4984ab7ccace17690ec8c207330faa6017efdc3af40342cedcd9e208443aa828`.
  L'inventaire des **99 sources** a été reproduit à l'identique par le
  relecteur. Cette validation porte sur la conception documentaire,
  sans preuve de déploiement, de puissance ou de gain expérimental.
- Aucun scénario admis par simple héritage d'un pack : fournisseurs,
  références D1, oracles, resets et coûts restent à valider. Aucun
  changement du catalogue officiel ou de la campagne en cours.

## Seconde relecture indépendante (révision du 15 octobre à 10:10)

- `second_scenario_review`, distinct des auteurs et des relecteurs précédents,
  a relu les contrats, les sources et toutes les 27 pages, reproduit les
  rendus et le snapshot des 99 sources. Aucun défaut de décompte ou de
  rendu n'a été relevé ; aucun doublon certain n'impose une suppression.
- Corrections intégrées : sœur protégée F0 de S22 séparée des impasses et
  précontrôles ; S36 justifié contre S29 par l'oracle de délégation, avec
  regroupement/reclassement prévu ; interruption S37 située après validation
  et avant commit. Le plan initial et son SHA sont maintenant communs aux
  quatre exécutions A0/A1 × stable/perturbé d'un même bloc ; coût normalisé
  et consommation réelle du préfixe restent séparés.
- Le [plan de soumission](../../objectifs/asiaccs-2027/plan-soumission.md)
  conserve désormais explicitement les faux positifs valides et réserve
  l'invalidation aux défauts d'intégrité du laboratoire, du reset ou de
  l'oracle. Les critères de décision ne confondent plus ces deux causes.
- Le choix de mesure principale par tâche, son dénominateur, le seuil utile
  et la correction des comparaisons restent des décisions à geler avant
  l'évaluation. Les diagnostics S37/S43 ne reprennent pas automatiquement
  le critère en TP de la soumission.
- Source compilée et PDF exporté : 27 pages ; les cinq pages modifiées
  (1, 15, 16, 22, 23) sont vérifiées, les 22 autres rendus sont identiques
  à ceux déjà inspectés. Confirmation indépendante finale validée et
  consignée le **2026-10-15 10:13 (Europe/Brussels, UTC+02:00)**, sans réserve
  bloquante sur la conception documentaire.
- Empreintes finales de cette relecture : source SHA-256
  `49f44eb603401a50e72d00c52a562450f56c93eafd9221ec1f8f7291fc9746a0` ;
  PDF `787805b2af6636f4b6af534dbaf494bb01ac4cc6ee843ee45c394715932d9145` ;
  plan `2b60d2831c5f85c90ddc465dd3f58ccafa35b5446debc59cc5eaa2d7e76c225a` ;
  inventaire `e631c6c7d25ed1004f81fa1206cdfcb1812084ca6ebce4a655bab96ac7ab6907`.
  Snapshot reproduit à l’identique par le second relecteur ; aucune campagne
  ni expérience exécutée pour cette relecture.

## Validation précédente du plan regroupé (révision du 15 octobre à 10:46)

Version **2026-10-15 10:46 (Europe/Brussels, UTC+02:00)**, relue par
`grouped_v2_review`, distinct de l'auteur ; validation documentaire finale le
**2026-10-15 10:53 (Europe/Brussels, UTC+02:00)**, sans réserve bloquante.
Les validations historiques ci-dessus restent attachées à leurs versions.

- Source et JSON : partition exacte des 44 fiches dans 25 ensembles, rôles et
  parents sans cycle, propriétés terminales, profils et mesures des 44 fiches
  vérifiés. Les 216 types uniques, 456 bras conditionnels et 24 types A0
  sont conservés ; les attestations de calibration et de réalisation sont nulles.
- Compilation dans l'éditeur et export LaTeX réussis. L'auteur a inspecté
  toutes les **39 pages finales**. Le relecteur a contrôlé p1 et p8–39 du
  dernier rendu ; p2–7 sont identiques par SHA-256 aux pages déjà inspectées.
  Pages presque vides et amorces orphelines corrigées ; sommaire cohérent,
  dont références p38. Aucun débordement ni référence indéfinie ; deux
  avertissements de justification et l'avertissement de césure babel restent
  sans défaut visuel constaté.
- Snapshot des **106 sources reproduit à l'identique**, par l'auteur et
  indépendamment par le relecteur. Contrôles des empreintes et
  `git diff --check` réussis. Les ajouts du script d'inventaire décrivent la
  conception ; aucune suite applicative n'est revendiquée pour ce travail.
- Clarifications de relecture intégrées : invariant de lecture terminale
  S40/S41 distinct du graphe ET/OU, contraste ET–OU encore non sélectionné,
  session SSH terminale exclue du nombre de relais, sortie absente distincte
  d'une perte indépendante de collecte, formules binaires séparées des comptes
  M-G. Les sigles et comparateurs sont définis avant les fiches.
- Empreintes de la version finale :
  - source : `926a2bc8e33f06f430370f9aa8b625dcc61494129db30b441e1d0a4c02439653` ;
  - PDF : `e965f59fa6e465f7781b5838e528ab8a33c6db1ee0a7f24055aa031c7ced353b` ;
  - plan : `ba012abdaba9b40efa3ee3a3d2a4dbc12d55853dc8cf51a54b77a942bd2ecaf0` ;
  - snapshot : `f9e9348e5000a21097d0dfeecb08b4a774655358fee3f233517f4ff862b9d8cf`.

Cette validation porte sur la cohérence et le rendu de la proposition, sans
attester faisabilité runtime, indépendance, puissance, coût total ou gain LLM.
Aucun changement du moteur, du catalogue, des vérités terrain ou de la campagne
Muse ; aucun audit, run ni déploiement lancé pour cette révision.

## Suite et points ouverts

1. Poursuivre avec `s_mqtt_lecture` après la qualification native SSH déjà obtenue,
   puis `s_api_organisations`, `s_mqtt_reprise` et `s_cache_identites`. Préparer
   séparément l’admission et le gel confirmatoire SSH ; utiliser `s_injection_preuves`
   pour éprouver les conclusions démontrables et l'abstention hors ligne.
2. Renseigner les attestations de profils : candidats, branches, états,
   chemin témoin, coûts, contrôles causaux et reset. Aucun minimum d'actions
   sans certificat, aucune difficulté définie par le gagnant.
3. Pour `s_reseau_distance`, attester depuis le runner accès direct/routé, un relais,
   découverte K0/K2 et absence de raccourci ; K1 et trois relais ensuite.
   Les nouveaux précontrôles ne sont pas des types scorés supplémentaires.
4. Geler par tâche mesure primaire, dénominateur, marge FP, seuil utile,
   effectifs et analyses confirmatoires ; aligner explicitement le nouveau
   protocole avec les objectifs, sans modifier le pilote historique.
5. Auditer la parenté des fournisseurs et variantes pour le split et
   l'incertitude ; aucun effectif indépendant déduit des 25 ensembles.
6. Admettre chaque variante/réplication selon sa question. Tout nouveau
   contraste scoré ou dédoublonnage exige un amendement et un recalcul de
   charge avant le test. Les profils décrits ne valent pas validation runtime.

## Validation précédente de la revue IoT et CTF (révision du 15 octobre à 11:18)

Recherche documentaire révisée le **2026-10-15 11:18 (Europe/Brussels, UTC+02:00)**,
validée sans réserve documentaire bloquante par l'agent indépendant
`iot_ctf_independent_review` le **2026-10-15 à 11:22 (Europe/Brussels, UTC+02:00)**.
La source et le registre ont été relus, les 13 pages finales inspectées
visuellement ; 19 sources primaires et 24 empreintes locales ont été vérifiées.
Compilation native et export PDF réussis ; aucun débordement ou référence
indéfinie signalé dans le journal d'export.

Les dix propositions IG01–IG10 précisent leur contrôle protégé, leur oracle,
leur automatisation compétente, leurs mesures et leur faisabilité relative.
Elles complètent l'analyse du plan V2 sans modifier ses 44 fiches, 25 ensembles
ou 216 types. Priorité : validité des verdicts CoAP et effets des commandes,
puis état MQTT et bridge entre brokers ; cycle de vie ou firmware ensuite.

Cette validation porte sur la conception, les sources et le rendu. Elle
n'atteste ni le déploiement NATO, ni une propriété observée en campagne, ni
un gain LLM. Aucun run, changement de code ou échange avec Muse effectué.

Empreintes de l'artefact relu :

- LaTeX : `35a9221a9843fecf27804ebbeedb95fd1056521d8ceebae9c3242cdf41042b37`.
- PDF : `8674488dc521ae40deece6a9789af46a4bf9f719a69fa25f03978234b1f594ea`.
- Registre après ajout des métadonnées de validation : `9bd6c74d0a5c80382fdf3d773d5584dbb53374f7bd80b48ad5b40a23409ee5b5`.

## Seconde revue IoT : cas limites

Révision **2026-10-15 11:44 (Europe/Brussels, UTC+02:00)**. Quatre agents ont relu la couverture et recherché
des cas atypiques : protocoles, réseau, cycle de vie et firmware, puis
sécurité de l’auditeur et CTF. La synthèse conserve dix IG et propose
quinze contrastes EC ; 40 sources primaires et 32 fichiers locaux sont
référencés. Relecture indépendante finale par `iot_edge_independent_review`,
validée sans réserve bloquante le **2026-10-15 à 11:48 (Europe/Brussels, UTC+02:00)**.

- Les sources, les 32 empreintes et les références ont été contrôlées ;
  le snapshot des 106 sources V2 est reproduit strictement à l’identique
  (44 fiches, 25 ensembles, 216 types, 456 bras conditionnels, 24 types A0).
- Compilation native et export LaTeX réussis. Les 23 pages finales sont
  inspectées par l’auteur et le relecteur ; après une dernière correction
  d’espace p12, les 22 autres pages restent identiques par SHA-256.
  Sommaire et destinations vérifiés ; aucun débordement ni référence indéfinie.
- Clarifications D1 : observer la déduplication de la cible sans supprimer
  la retransmission du test ; éprouver le fetcher cible sans le réparer.
  Titres isolés de la table et d’EC07 corrigés avant validation.
- Priorités d’admission : persistance après reprise (EC01), identité par
  contexte réseau (EC09), isolement et validité des preuves courantes (EC15).
  EC14 traite la sécurité de l’auditeur dans une étude séparée ; utilité
  de mission et succès adversarial restent deux mesures distinctes.
- Le plan V2, son inventaire et leurs sources/PDF sont inchangés.
  Aucun changement applicatif, run, firmware exécuté, déploiement,
  consultation d’historique ou échange avec Muse.

Cette validation documentaire n’atteste ni faisabilité runtime, conformité,
gain LLM ou exhaustivité. Les dix IG et quinze EC restent des propositions
regroupées, sans admission automatique dans le corpus.

Empreintes finales :
- LaTeX : `a8dce474eed93a1dff87b6fe0cd0915cfc05249d3e14905eedb744b3d0ee6f48`.
- PDF : `0bc474553152b984e2edf80610d3db1f7fc813062f68393093adbb911d2649bc`.
- Registre après métadonnées de validation : `5b2a96e41dce8a8f61787ba562b6c528254fe7ad2cb3f54256e05b32f77a7359`.

## Validation précédente de l’intégration IoT (révision du 15 octobre à 12:04)

Révision **2026-10-15 12:04 (Europe/Brussels, UTC+02:00)**. Les dix IG et quinze EC de la revue
figée à 11:44 sont rattachés par une table unique : admission, support,
contraste candidat ou étude de l’auditeur. Les 44 fiches portent leurs liens,
admissions conditionnelles et lots de construction ; aucune nouvelle
propriété ou type scoré n’est admis par voisinage. Relecture indépendante
par `v2_iot_integration_review`, distinct de l’auteur, validée sans réserve
documentaire bloquante le **2026-10-15 à 12:05 (Europe/Brussels, UTC+02:00)**.

- Ordre de construction : **L0**, preuves et calibration hors ligne S05 ;
  **L1**, S01/S02, S11, S19 puis S33 ; **L2**, S25/S26/S16 ; **L3**, S09,
  socle S15 qualifié avant S10. **LN/S24** peut avancer en parallèle après
  qualification des origines et des accès. L4 est guidé par les questions
  restantes ; LX/EC14 étudie séparément la sécurité de l’auditeur.
- Les 25 rattachements distinguent quatre admissions, cinq supports,
  quinze contrastes candidats et une étude séparée. Chaque fiche précise
  ses liens, admissions conditionnelles et priorité ; chaque lot indique
  la question, un résultat défavorable à l’hypothèse LLM et sa condition
  de sortie technique. Les références sans LLM restent compétitives,
  avec les mêmes informations, outils, droits et budgets.
- Les **44 fiches, 25 ensembles éditoriaux, 216 types, 456 bras conditionnels
  et 24 types A0** sont conservés exactement. Aucun nouveau type n’est
  ajouté ; aucun champ de preuve runtime n’est renseigné. L’inventaire des
  20 packs référencés est inchangé ; les trois artefacts de la revue IoT
  figée portent le snapshot à **109 sources**.
- Compilation native et export PDF réussis. L’auteur et le relecteur ont
  inspecté les **45 pages finales**, le sommaire et les tableaux. Aucun
  débordement, coupe ou référence indéfinie ; six avertissements de
  justification et celui de césure babel sans défaut visuel constaté.
- Snapshot reproduit strictement à l’identique par l’auteur et le
  relecteur ; empreintes et `git diff --check` contrôlés. Le script
  d’inventaire vérifie les rattachements, les priorités, les admissions
  et la conservation de la sélection. Aucune suite applicative n’est
  revendiquée pour cette révision documentaire.

Cette validation porte sur la conception, le rendu et la reproduction
statique. La faisabilité des fournisseurs, les coûts et la plus-value des
LLM restent à mesurer. Aucun changement du moteur, du catalogue ou de la
campagne Muse ; aucun run, déploiement ou message à Muse pour cette révision.

Empreintes de la version intégrée validée :

- LaTeX : `c91380d669d0c669227c99a32f057de345a065d99db978aae5e44dfbba99d0c3`.
- PDF : `4074a91a4267805cc472b6a401aa16de6857fcc4a508b8a2921b5a36d8e2d85a`.
- Plan : `a0a37a4a395fa1e699cd30037e79d6366f1d8b96e627b51229cce1c64b4c252c`.
- Snapshot : `f2694b53468df520c5aaea33119d7c01a5201e9e1d0f9b72e4ccb00ac9ce2e49`.

## Validation précédente de l’organisation (révision du 15 octobre à 12:18)

Révision **2026-10-15 12:18 (Europe/Brussels, UTC+02:00)**. Les anciens lots
sont remplacés par des noms explicites et des rôles distincts. Les identifiants
S01–S44, leurs regroupements, contrats, mesures et types sont conservés.

La table de lecture figure au début du rapport ; la feuille de route sépare
préparation, parcours principal, chantier parallèle et travaux à décider.
Les fiches et la table IoT utilisent les mêmes noms. Le JSON conserve des
identifiants sémantiques et un registre unique des libellés/rôles/numéros.

Relecture indépendante par `v2_iot_integration_review`, distinct de l’auteur,
validée sans réserve documentaire bloquante le **2026-10-15 à 12:23
(Europe/Brussels, UTC+02:00)**.

- Source et JSON relus ; **44 fiches, 25 ensembles, 216 types, 456 bras
  conditionnels et 24 types A0** conservés exactement. Les ordres internes
  et dépendances techniques sont inchangés ; seuls noms, organisation
  éditoriale et métadonnées de construction évoluent.
- Compilation native et export PDF réussis. Les **46 pages finales** sont
  vérifiées par l’auteur et le relecteur : p2–41 identiques par SHA-256 au
  candidat inspecté, puis p1 et p42–46 revues sur le rendu final. Sommaire,
  tableaux, amorces et renvois contrôlés. La page presque vide du candidat
  est corrigée ; aucun débordement, texte coupé ou référence indéfinie.
  Six avertissements de justification et celui de césure babel restent
  sans défaut visuel constaté.
- Snapshot des **109 sources** reproduit strictement à l’identique par
  l’auteur et le relecteur ; empreintes valides, inventaire officiel
  inchangé et `git diff --check` réussi. Le script contrôle le rôle
  unique de chaque travail et les libellés/numéros des fiches.
- Vérifications limitées à la conception, au rendu et à la reproduction
  statique ; aucune suite applicative, faisabilité runtime ou plus-value
  LLM n’est revendiquée. Aucun run, déploiement ou échange avec Muse.

Empreintes de la réorganisation validée :

- LaTeX : `88ebde03cff25e836c286bce70c20c79bb7b8076fea4499df663ad5bfbd51ce8`.
- PDF : `4552fd94e955a8449f88912f02a90d9acbcf2974a0b1a56be45ad2b64f8dc3e8`.
- Plan : `86fd3653529185bf63b02f58f693ca7b049939105569b270050d595819da346b`.
- Snapshot : `74dc0f7eff740eceb96b6096984949b9371eb915fe3b2df63028e875b631e192`.

## Validation précédente des noms descriptifs (révision du 15 octobre à 12:30)

Révision **2026-10-15 12:30 (Europe/Brussels, UTC+02:00)**. Les 44 propositions
portent désormais un nom principal en `s_...` ; les types conservent leurs
suffixes de traitement sous ce même nom. Les 44 et 216 correspondances
sont bijectives ; une traduction inverse vérifie que la sélection de tests
et tous ses paramètres sont conservés. Les anciennes références du catalogue
restent explicitement qualifiées et la revue IoT figée n’est pas réécrite.

Une annexe et le registre JSON assurent la correspondance historique. Le
corps du rapport, les fiches et les priorités utilisent les nouveaux noms ;
les ensembles de comparaison sont affichés par leur thème. La campagne
Muse et ses identifiants restent inchangés.

Relecture indépendante par `v2_iot_integration_review`, distinct de l’auteur,
validée sans réserve documentaire bloquante le **2026-10-15 à 12:36
(Europe/Brussels, UTC+02:00)**.

- Les **49 pages finales** ont été inspectées par l’auteur et le relecteur :
  fiches, table d’aperçu, étapes, tableaux, sommaire et annexe p47–49.
  Compilation native et export PDF réussis ; aucun débordement, coupe,
  titre orphelin ou référence indéfinie constaté. Dix avertissements de
  justification et celui de césure babel restent sans défaut visuel.
- **44 alias de scénarios et 216 alias de types bijectifs**. Les parents,
  regroupements, priorités, admissions et 25 retours IoT ont été contrôlés.
  Les références du catalogue sont qualifiées ; la revue IoT figée conserve
  ses empreintes. Les ensembles sont affichés par leur thème.
- Les contrats scientifiques restent identiques après traduction des
  références. La sélection après traduction inverse retrouve exactement
  l’empreinte `da770d4406c4c2478baf6f6fff0d67d1b919e79338c13656acc2b8c44e2064fe` :
  **216 types, 456 bras conditionnels, 24 types A0 et 25 ensembles** conservés.
- Snapshot des **109 sources** reproduit strictement à l’identique par
  l’auteur et le relecteur ; inventaire officiel et 20 packs référencés
  inchangés, empreintes valides, `git diff --check` réussi. Le validateur
  contrôle aussi la bijection et l’égalité de sélection après traduction.
- Cette validation reste documentaire et statique ; aucune suite applicative,
  faisabilité ou plus-value runtime n’est revendiquée. Aucun changement du
  moteur, du catalogue, du manifeste ou de la campagne Muse ; aucun run,
  déploiement ou message à Muse.

Empreintes de la nomenclature validée :


- LaTeX : `e3061e9cf7f8ecd53a253f073e574ebd3bc41ace31f1fcfb645f1896edb4b629`.
- PDF : `4f61c6292d67369fe8a70bd3ff23da37d6f7d3de0a98d28fed891c9d87baab64`.
- Plan : `3ce32196c51bfc94bbe068cbffb4da4f96dc10398c573eb018572d3db708383f`.
- Snapshot : `eee6102c4ae1295d12cec91302a8c84921361e873a5f5b1ed7b35836ce25ac53`.

## Structure par question et catalogue en annexe

Révision **2026-10-15 12:44 (Europe/Brussels, UTC+02:00)**. Le corps principal
présente les décisions scientifiques et de construction ; les 44 fiches sont
classées en annexe selon six questions de lecture. Les 25 ensembles restent
un index technique secondaire, avec les mêmes parents, variantes et contrats.
Les noms, sélection, mesures et priorités sont conservés.

Relecture indépendante par `v2_iot_integration_review`, distinct de l’auteur,
validée sans réserve documentaire bloquante le **2026-10-15 à 12:52
(Europe/Brussels, UTC+02:00)**.

- **50 pages finales couvertes visuellement** par l’auteur et le relecteur :
  candidat intégral inspecté, puis p3/4/5/7/8/9/10/11/12 finales réinspectées ;
  les 41 autres pages sont identiques par SHA-256. Sommaire, tableaux,
  liens de navigation et six annexes vérifiés. Le catalogue commence p12.
- Compilation native et export PDF réussis. Aucun débordement, coupe,
  tableau illisible, titre isolé ou référence indéfinie ; dix avertissements
  de justification et celui de césure babel sans défaut visuel constaté.
  Les registres sont définis avant leurs formules ; F et K/d sont définis
  avant leur utilisation.
- Les six groupes de lecture répartissent les **44 fiches en 9/12/2/4/12/5**.
  Leurs exemples, rattachements et quatre relations interquestions sont
  contrôlés. L’ordre des fiches du PDF correspond exactement au registre.
  Aucun score, dénominateur ou effectif indépendant par groupe n’est ajouté.
- **Tous les champs préexistants des 44 fiches, leurs 25 ensembles, noms,
  priorités, dépendances et dispositions IoT restent strictement identiques**
  à la révision du 15 octobre à 12:30. Les 44 blocs LaTeX originaux sont
  intégralement conservés, avec ajout du seul renvoi à la comparaison
  technique. Les 216 types, 456 bras conditionnels et 24 types A0 sont inchangés.
- Snapshot des **109 sources reproduit strictement à l’identique** par
  l’auteur et le relecteur ; 20 packs référencés et inventaire officiel
  inchangés, empreintes valides et `git diff --check` réussi. Le validateur
  contrôle aussi la partition des questions et les relations transversales.
- Validation limitée à la structure, au rendu et à la conception. Aucune
  suite applicative, faisabilité ou plus-value expérimentale revendiquée ;
  aucun changement de catalogue, campagne ou moteur, aucun run, déploiement
  ou message à Muse.

Empreintes de la structure validée :


- LaTeX : `2e819f1d1959c116b721e6ac6c20edb5125118d1b69f759ee4b28d61b6c9c330`.
- PDF : `58d02abff28ba925f686147b0fff239c75d4cc37cdc6ca6da922e88342918b3b`.
- Plan : `c7bea6bd94b5a899500ff130c615e2007b5c8d8d63f930b3650e973c3851be19`.
- Snapshot : `1bf4d187da6d9361244d4dd819441144e06193f9fcbfbf1e07a323787f48b56e`.

## Validation précédente : retours avant/après

- Révision : **2026-10-15 14:31 (Europe/Brussels, UTC+02:00)**. Noms, relations, priorités, types et bras sélectionnés conservés.
- Quatre avis de lecture intégrés : cyber IoT, réseau, évaluation LLM et clarté.
- Ajouts : vocabulaire explicite ; exemple MQTT complet (deux configurations,
  quatre exécutions D1/A1 par instance/répétition) ; premier contraste SSH
  spécifié ; visibilité K/d et matrice réseau ; liens parents/variantes/ensembles.
- Relecture indépendante achevée le **2026-10-15 à 14:33 (Europe/Brussels,
  UTC+02:00)** par `avant_apres_clarte` : source, JSON et **54 pages finales**.
  Le candidat a été inspecté, puis les 19 pages modifiées et les 12 dernières
  pages finales vérifiées ; les 23 autres pages inspectées sont identiques
  par empreinte PNG. Aucun défaut bloquant de clarté ou de rendu relevé.
- `avant_apres_evaluation` a relu les ajouts source/JSON et confirmé les
  corrections de méthode : FP/coût manquants jamais codés zéro ; règle de gain
  de réussite sous contraintes ; gain de coût distinct ; fraîcheur MQTT observable.
  Cette seconde relecture ne revendique pas une inspection graphique complète.
- Conservation stricte des champs préexistants des 44 fiches vérifiée contre
  la révision 12:44 : **216 configurations, 456 bras conditionnels et 24 types
  A0**. Les fiches LaTeX sont conservées, hormis liens et clarification des
  trois jalons MQTT publication/délivrance/effet, sans changement de prédicat.
- Compilation native et export LaTeX réussis ; aucun débordement ni renvoi
  indéfini. **465 liens internes** résolus, 44 fiches ciblées sur leur page,
  25 destinations techniques et sept destinations de lecture du README vérifiées.
  Snapshot des **109 sources reproduit à l’identique** par le relecteur ;
  `git diff --check` réussi. Les journaux et dates historiques sont conservés.
- Restent à réaliser : fixtures, qualification D1, canaux publics, calibration
  et gel des marges/budgets/effectifs/analyses, manifeste expérimental et archives.
  Aucune suite applicative ou validation runtime n’est revendiquée ; aucune
  campagne, configuration de laboratoire, exécution ou interaction Muse modifiée.

Empreintes de la version relue :

- LaTeX : `2a1db140d95e7493c5903babecb82b0a44320f177ec6fb62e9352614ed1631ae`.
- PDF : `957a06f0b424519660f799653ad24611f51d2090f189616b1ee8a7fcb3765924`.
- Plan : `aa0ceab3a9ae9f605b213bab574cb859591aaeeff61068ef4b201431f4134858`.
- Snapshot : `3c2b609576e58275feb7aa59ceabb2bab7a5ec9cda6ac4a08f415b4029019694`.

</details>

## Révision précédente : correspondance des benchmarks

- Révision : **2026-10-15 14:49 (Europe/Brussels, UTC+02:00)**. Matrice des **44 scénarios**, avec types,
  mesures primaires résumées et hypothèses LLM dérivés des contrats existants.
- Répartition : **35 M-T, 3 M-G, 4 M-I, 1 M-E et 1 M-C** ; six questions
  éditoriales distinctes. Hors ligne, interpréteurs à règles/LLM compétents ;
  en interaction D1/A1, A0 seulement dans les 24 configurations déjà retenues.
- Trois relecteurs distincts de l’auteur : `benchmark_map_method` (44 lignes,
  mesures, comparateurs et portée statistique), `benchmark_map_cyber_network`
  (44 lignes, preuves, effets, identité et parcours), `benchmark_map_clarity_pdf`
  (source/JSON/README et inspection visuelle des **58 pages finales**).
  Validation sans réserve bloquante, consignée le **2026-10-15 à 14:52
  (Europe/Brussels, UTC+02:00)**. Matrice lisible aux pages **43–46**,
  conditions et limites aux pages 43 et 46–47.
- Corrections issues de la revue : réussite comparable et gain de coût distingués ;
  marges/procédures à geler ; hypothèses reliées aux mesures retenues sans score
  cognitif ajouté ; branches génériques D1/A0 explicitement autorisées pour MQTT.
- **44 lignes identiques** dans le registre JSON, le tableau README et le LaTeX.
  Tous les champs des 44 fiches et contrats antérieurs sont strictement conservés :
  **216 configurations, 456 bras conditionnels et 24 types A0**, noms et priorités
  inchangés. Aucun traitement, score ou effectif indépendant ajouté.
- Compilation native et export LaTeX réussis, sans Overfull ni référence indéfinie.
  Les **520 liens internes** du PDF et huit destinations nommées du README sont
  résolus. Le relecteur a vérifié les destinations principales ; l’auteur a
  contrôlé l’ensemble et reproduit le snapshot des **109 sources** à l’identique.
  `git diff --check` réussi. Les validations et horodatages antérieurs sont conservés.
- Limites : hypothèses non évaluées ; calibration et gel des seuils, budgets,
  effectifs et analyses restent requis. Aucune suite applicative ni faisabilité
  runtime validée, aucun run, déploiement ou changement de campagne Muse.

Empreintes de la version relue :

- LaTeX : `dc238fa4d6f647ded53fa129be73ca759a8ab440fe93978543a6b127e780b2dc`.
- PDF : `a7c3d7aeef9d826139ba75dce53533833e1f463c9e7b108d352726773f28de5a`.
- Plan : `f34e5f68e60b401490a9bbad4ecb345eb6112a41a166fbf45e6fbfd1ca495bdf`.
- Snapshot : `d9587b64c44f7f7dba362866567916b54188b949aa3f8b0453672f7ce817f7b3`.

## Validation de la consolidation du 16 octobre 2026
+
+- Rapport livré : **révision 2026-10-16 21:43 (Europe/Brussels, UTC+02:00)**,
+  **59 pages** ; source LaTeX éditable et PDF synchronisés.
+- Relecture indépendante : agent `v2_review`, clôturée le **2026-10-16 21:47
+  (Europe/Brussels, UTC+02:00)**, sans réserve documentaire bloquante.
+  Les 59 pages du candidat ont été inspectées ; après les quatre retouches,
+  les pages finales 1, 7, 11 et 13–22 ont été réinspectées. Les 46 autres PNG
+  sont identiques octet pour octet. Aucun débordement, texte coupé,
+  chevauchement ni tableau illisible constaté.
+- Compilation réussie avec le compilateur desktop et `latexmk -pdf` ; aucun
+  renvoi/citation indéfini ni boîte débordante dans le journal final.
+- Sélection conservée : **44 fiches, 25 ensembles, 216 configurations,
+  456 bras conditionnels et 24 types A0** ; matrice de mesure et groupes de
+  lecture inchangés. Seuls les statuts de suivi SSH sont actualisés.
+- Snapshot reproduit avec les empreintes de **115 sources** ; `--check`
+  confirme les octets et décomptes, puis refuse un snapshot altéré.
+  Les liens relatifs et destinations PDF ont été contrôlés.
+- **81 tests SSH ciblés réussis** : `test_ssh_reference.py`,
+  `test_ssh_reference_live.py`, `test_ssh_reference_proxmox.py` et
+  `test_ssh_reference_diagnostics.py`. Ces tests sont logiciels ; ils ne
+  constituent pas de nouveaux essais SSH sur nato.
+- Les trois fichiers de la revue IoT figée et les fichiers V2 de la copie
+  locale d’origine sont préservés. La réconciliation du pilote historique,
+  ses manifestes, tentatives et résultats ne sont pas remplacés.
+- Limite : rattachement des résultats SSH déjà publiés, sans nouvelle
+  expertise des archives privées sur nato, nouveau run ou gain LLM revendiqué.
+  MQTT demeure la prochaine réalisation ; aucun résultat MQTT n’est admis.
+
+Empreintes de la version relue :
+
+- LaTeX : `6c4616f8778d38988bcbb1639529008219741fec504d8ed603ac55b34442dead`.
+- PDF : `a6668f4c4abb3e4a47b8f56f26574d0ea807ee0e286344be062f32821525b5a9`.
+- Plan : `c1de3ef484ba120c61c6751a7649a859b31b81d1a20c56711a1657663e4e8a91`.
+- Snapshot : `5ef0bd90a74bda821d5092583ac6730c513e78b63510b9c9ee6a0495c8a2116d`.
+