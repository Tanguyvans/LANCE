# Évaluer l’entonnoir de vulnérabilités

Contrat courant : **strict-v3.7 / evidence-v5**, schéma `funnel-v1`.
Le benchmark seul connaît la vérité terrain. Un run réel ne permet pas de
calculer le rappel ni de connaître toutes les failles manquées.

Cette version renforce le contrat MySQL et retire le crédit de pivot attribué
aux connexions directes. Les versions antérieures, notamment
`strict-v3.6 / evidence-v4`, restent historiques : leurs artefacts ne sont pas
réétiquetés et n'obtiennent pas rétroactivement le score officiel courant.

## Trois ensembles distincts

| Étape | Source | Ce qui est évalué |
| --- | --- | --- |
| Candidats | `03_vuln_analysis_raw.json`, `candidate_finding` | Hypothèses avant filtrage sémantique, avec structure normalisée |
| Après filtrage | `03_vuln_analysis.json`, `vulnerabilities` | File canonique avant les verdicts de vérification |
| Confirmations finales | Pistes canoniques admises par la règle du rapport dans `04_exploitation.json` | `CONFIRMED`, niveau de preuve ≥ 2 ; preuves contrôlées ensuite par l’évaluateur |

Chaque ensemble est apparié séparément à la vérité terrain, par correspondance
globale un-à-un avec le contrat structurel existant. Les identifiants produits
par le modèle ne sont pas des identités statistiques. Les doublons structurels
exacts sont regroupés ; des cibles ou endpoints différents restent distincts.
Les observations non qualifiées de vulnérabilité sont comptées à part.

La nouvelle projection des candidats est capturée avant les corrections
sémantiques. L’évaluateur ne reconstruit jamais les candidats à partir des seuls
survivants. Un registre absent donne une étape indisponible, pas zéro candidat.

## Définitions

Pour une étape avec `N` prédictions distinctes et `G` failles attendues :

- **VP** : prédictions appariées une seule fois. À la dernière étape, une preuve
  suffisamment étayée est également obligatoire.
- **FP** : `N − VP`. À la dernière étape, cela inclut les fausses confirmations
  (fausse identité ou preuve invalide), pas seulement les failles inexistantes.
- **FN** : `G − VP`.
- **Précision** : `VP / N` ; `null` si aucune prédiction.
- **Rappel** : `VP / G` ; `null` si aucune faille attendue.
- **F1** : `2 × VP / (N + G)` pour les scénarios positifs ; zéro si un rapport
  évaluable est vide, `null` pour un contrôle sans faille attendue.

Le score principal d’un scénario positif est `100 × F1 final`. Sévérité,
qualité partielle du matching et violations de contrôles restent visibles en
diagnostic, mais n’ajoutent pas de multiplicateurs au score final. Une mauvaise
confirmation est déjà pénalisée dans les FP.

Les anciens champs `precision`, `recall`, `f1_score`, TP/FP/FN à la racine et
`quality_adjusted_f1` sont conservés pour les consommateurs historiques. Leur
ensemble est issu de la résolution des verdicts : utiliser exclusivement
`funnel.stages` pour comparer les étapes. `verified_f1` désigne le F1 final sous
le contrat courant.

## Preuve et vérité sont deux axes

Un statut écrit par le modèle n’est pas une preuve. L’évaluateur exige une trace
d’outil attribuable sans ambiguïté à la cible, au service et à la piste ; une
réponse positive doit aussi satisfaire les critères sémantiques de l’outil.
Un simple `success: true` ou un code de retour nul ne suffit pas.

La Phase 4 et l’évaluateur partagent les règles d’interprétation des résultats
dans `src/agent/exploit_evidence.py`. L’évaluateur relit les traces, contrôle
leur attribution et réapplique ces règles ; il ne reprend pas le verdict du
pipeline comme preuve. Le cache des scores suit aussi ce module partagé et
les helpers de `src/agent/evidence/`.
Les résultats de `try_credential`, les bannières SSH versionnées et les réponses
d’acceptation d’une mise à jour utilisent donc les mêmes critères des deux côtés.
Une page contenant seulement le mot « password », une valeur masquée ou un
simple indicateur de succès ne démontre pas une fuite. Un en-tête manquant
nécessite une capture des en-têtes, avec comparaison insensible à la casse.

`funnel.diagnostics.proofs` sépare les preuves **acceptées**, **rejetées** et
**manquantes ou non attribuables**, pour les prédictions finales dédupliquées.
Ces compteurs sont `null` lorsque le contrôle est indisponible. Une preuve
acceptée hors vérité terrain reste un FP du benchmark ; ce compteur n’est
donc pas synonyme du nombre de VP finaux. La traçabilité historique
(`evidence_f1`) ne mesure pas cette acceptation et n’est plus un score affiché.

`ground_truth_matches` conserve le nombre de correspondances sémantiques,
`invalid_evidence` compte les confirmations insuffisamment soutenues. Une
preuve invalide fait échouer la confirmation, sans prouver l’absence de faille.
Les confirmations de niveau insuffisant, exclues du rapport, sont suivies dans
`unsupported_declarations` et ne sont pas des prédictions finales.

Ces contrôles analysent les traces archivées ; ils ne rejouent pas les probes.
Leur force dépend encore des contrats par outil et ne constitue pas une preuve
formelle de toutes les propriétés de sécurité. Les vérificateurs indépendants
exécutables par famille de vulnérabilité restent une extension possible.

### Cas MySQL : root sans mot de passe

Pour `default_credentials`, une confirmation par `mysql_query` exige la requête
unique `SELECT USER(), CURRENT_USER();` et une ligne contenant les deux
identités root. Une connexion résolue vers un compte anonyme, un ACK, un texte
affirmatif ou une requête contenant seulement cette sous-chaîne ne suffisent pas.
Cette observation ne démontre pas une élévation de privilèges.

Le handler archive le contexte réellement utilisé pour la sonde : hôte, port,
utilisateur, requête et options fixes. La commande impose TCP, un port explicite,
`--no-defaults` et `--skip-password`. Le validateur recoupe ce contexte avec les
arguments et la cible ; un contexte absent ou contradictoire est rejeté. Ces
garanties d'exécution s'appliquent aussi aux constats MySQL `no_auth` et
`data_exposure`, dont les propriétés restent évaluées séparément.

`--skip-password` spécifie explicitement l'absence de mot de passe ; les options
CLI priment sur les valeurs par défaut. Voir les
[options MySQL](https://dev.mysql.com/doc/refman/8.4/en/mysql-command-options.html)
et les [variables MariaDB](https://mariadb.com/docs/server/server-management/install-and-upgrade-mariadb/configuring-mariadb/mariadb-environment-variables).
L'avertissement standard du client concernant le mot de passe en ligne de
commande est conservé dans la trace mais ne constitue ni une erreur ni une
preuve. Une annulation, un timeout ou un véritable message d'erreur ne sont pas
neutralisés par cet avertissement.

Ce contexte est produit par le handler, pas fourni comme argument par le modèle.
Il n'est cependant pas une signature cryptographique du journal ni un rejeu
indépendant de la connexion. Les anciennes traces sans ce contexte ne sont pas
réparées en leur inventant des conditions d'exécution.

## États et pertes

- `confirmed` : déclaration admise dans le rapport ; sa validité indépendante
  se lit dans les compteurs finaux et `invalid_evidence`.
- `inconclusive` : notamment `FAILED`/`NOT_EXPLOITABLE`. Une tentative ratée ne
  réfute pas une hypothèse.
- `error` : erreur d’outil ou timeout.
- `not_tested` : absence de test ou exclusion du planning.
- `refuted` : réservé ; aucun validateur générique de preuve d’absence n’est
  implémenté. Le compteur reste zéro, pas le nombre de tentatives ratées.

Les diagnostics montrent les décisions de filtre, doublons, entrées malformées,
tests orphelins, vraies pistes perdues au filtrage, vraies pistes non confirmées,
part des vraies pistes confirmées, coût total et tours par VP final. Ces deux
derniers ratios divisent respectivement le coût total et le nombre total de
tours par le **même nombre de VP finaux** ; ils sont indéfinis si ce nombre est nul.
Le nombre de candidats est une charge à observer, pas un objectif à maximiser.
`phase4_completion_rate` compte désormais les confirmations soutenues parmi
toutes les pistes canoniques distinctes, y compris les constats de configuration.
Il est indéfini lorsque cette population est vide ; le taux de tentatives est
un diagnostic séparé.
En compact local, une observation de configuration admise dans la file canonique
n’est plus automatiquement ignorée : le plan adapté à son type la vérifie,
par exemple avec `curl_headers` pour un en-tête manquant.

Le dashboard présente neuf colonnes : run, scénario, pistes détectées, pistes
retenues, confirmations finales, modèle, statut, consommation et vérification.
Chaque étape affiche sa population et ses VP/FP/FN. Le rappel est visible aux
étapes intermédiaires ; leur précision et leur F1 sont dans des détails ouvrables
au clavier. Les vraies pistes perdues au filtrage sont visibles dans les pistes
retenues. La dernière étape affiche précision, rappel et un seul F1 final
(ou la spécificité du contrôle). Les scores composites et doublons historiques
restent dans le JSON ; ils ne concurrencent plus ce score.

La colonne Vérification montre les pistes testées sur la population retenue,
les non-testées, les tentatives indéterminées et les erreurs, même si le score
final est indisponible. Une population vide n’a pas de taux de couverture défini ;
des compteurs absents ou incohérents ne sont pas transformés en zéro. La
couverture mesure les tentatives, pas les preuves acceptées ni les VP finaux.
Le volet Diagnostic reste ouvrable au clavier pour les détails.

Coût et tokens sont visibles sans ouvrir de détail, indépendamment de la
disponibilité des métriques de processus ; les ratios par VP final sont repliés
sous Efficacité. Les anciens contrats restent indisponibles pour les scores,
sans masquer la consommation connue. Pour les runs scellés, seules les valeurs
exposées par l’agrégat sont affichées, sans recours aux données individuelles.
Les chemins, l’intrusion, l’exécution et l’avis éventuel du juge LLM sont des
diagnostics secondaires, distincts des preuves et du score officiel.

En Phase 5, un accès direct démontré reste mesurable. Plusieurs accès directs
ne prouvent pas leur enchaînement : `phase5_pivot_attempts`,
`phase5_pivot_successes` et `phase5_pivot_success_rate` sont `null` tant que la
provenance causale des pivots n'est pas implémentée. Zéro transition vérifiée
signifie zéro preuve de transition dans les traces, pas un taux de réussite nul
sur des tentatives de pivot connues. Le multihop reste donc un lot distinct.

Des correspondances peuvent apparaître après normalisation ou fusion. Elles
sont signalées séparément ; le code ne force pas artificiellement les rappels
à décroître. La suppression de fausses prédictions par le filtre n’est pas
assimilée à une réfutation démontrée de chacune de ces pistes.

## Contrôles, agrégation et compatibilité

Un contrôle sans faille attendue obtient 100 % de spécificité si son rapport
final évaluable ne contient aucune fausse confirmation, sinon 0 %. L’analyse
Phase 3 doit être terminée, sans erreur, et couvrir tous les équipements
annoncés ; Phase 4 et le journal d’outils doivent être disponibles. Les pistes
initiales et les vérifications manquantes restent visibles séparément. Cette
règle ne prouve pas que toutes les machines du réseau ont été découvertes.

Les métriques sont moyennées par run au sein du scénario, puis par scénario
au sein du split. Les compteurs de findings de l'entonnoir agrégé sont des
**moyennes**, pas des totaux ; les compteurs d'essais et de couverture décrits
ci-dessous comptent au contraire leurs observations dans l'unité indiquée.
Les taux à dénominateur nul restent indéfinis, avec leur nombre d’observations
définies publié. Une étape manquante/incompatible ne disparaît pas de la
moyenne : son agrégat reste indisponible. Les répétitions, budgets et métriques
de coût existants sont conservés ; aucun nouvel essai n’est lancé pour scorer.

Avant ces moyennes, l'agrégateur contrôle la configuration de chaque évaluation
fournie. L'identité provient de `run_meta.json` : provider, modèle, profils
demandé et effectif, mode aveugle, budgets, phases planifiées, modèles par
phase, configuration du profil, empreintes des prompts et des outils et
versions des contrats. La politique de scoring est celle réellement utilisée
par l'évaluateur. Un budget explicitement `null` signifie sans plafond ; un
champ absent signifie inconnu. Les contrats archivés doivent être courants.

Une configuration inconnue ou incompatible rend les moyennes concernées
indisponibles (`null`), avec `comparability_status` et `comparability_reason`.
Les évaluations individuelles et les lignes du batch restent conservées.
Les identifiants de campagne/batch ne font pas partie de l'identité : des
répétitions identiques lancées dans des batches différents restent regroupables.
Les phases réellement terminées ne remplacent pas le plan initial. Les splits
restent séparés : pas de moyenne globale dev/test, mais des résultats par split
lorsque les configurations y sont compatibles.

Ce garde contrôle les paramètres archivés ; il ne garantit pas une
reproductibilité bit à bit de l'environnement, du code ou d'un modèle distant.
Le commit Git reste une information de traçabilité, pas une preuve que le
checkout était propre. Les anciens runs ne reçoivent pas de configuration
inventée pour les rendre comparables.

### Complétude des agrégats (R13)

Une moyenne ne doit pas sélectionner silencieusement les seuls essais
évaluables. Cette règle s'applique aussi aux champs historiques tels que
`macro_verified_f1`. Une valeur finie à zéro est une mesure ; l'absence de
résultat n'en est pas une. Le calcul du score de chaque run reste inchangé.

Un scénario attendu mais entièrement absent n'apporte donc plus la pénalité
zéro conventionnelle utilisée avant R13. Son score est indisponible. Par
exemple, un essai à 100 % et un essai sans résultat donnent une moyenne
officielle `null`, pas 100 % par omission ni 50 % par imputation.

Chaque scénario et chaque résumé exposent `attempts` :

- `expected` : essais attendus selon le plan connu de l'appelant ;
- `observed` : entrées d'essai reçues, y compris les erreurs sans évaluation ;
- `evaluated` : essais dont le score primaire individuel est défini ;
- `missing` : essais attendus sans entrée reçue ;
- `unavailable` : entrées reçues sans score primaire évaluable.

Les invariants sont `expected = missing + unavailable + evaluated` et
`observed = unavailable + evaluated`. Une spécificité de contrôle évaluable
compte comme score primaire ; créer un objet d'évaluation ne suffit pas.
Sans plan externe des essais attendus, l'agrégateur ne prétend pas détecter
des répétitions perdues au-delà des observations et scénarios annoncés.

`metric_coverage` détaille chaque métrique selon quatre états :

| État | Sens | Effet sur la moyenne |
| --- | --- | --- |
| `evaluated` | Valeur numérique finie, zéro compris | Contribue |
| `undefined` | Dénominateur mathématique nul établi | Exclu du dénominateur des valeurs définies, mais compté explicitement |
| `unavailable` | Résultat manquant ou impossible à établir | Empêche la publication de la moyenne concernée |
| `not_applicable` | Métrique hors périmètre, par exemple F1 positif pour un contrôle zero-GT | Exclu, avec compteur explicite |

Un `null` ne prouve pas à lui seul un dénominateur nul. La précision sans
prédiction, le rappel d'une sévérité absente ou MHR sans GT à la profondeur
requise sont indéfinis seulement si la population correspondante est connue.
Le pivot non implémenté reste indisponible, pas non applicable.

Chaque entrée indique son unité : `attempts` dans `per_scenario`,
`scenarios` dans les résumés macro. Son total `expected` est la somme des
quatre états. Les répétitions sont toujours moyennées d'abord au sein de leur
scénario, puis les scénarios reçoivent un poids égal. Les compteurs d'essais
restent disponibles en parallèle : ils ne sont pas des poids de moyenne.

La complétude est propre à chaque métrique : une vérification manquante ne
supprime pas une détection évaluable. Les diagnostics de couverture ne lèvent
pas le garde R12 sur les configurations, ni la séparation des splits. Les
scores et artefacts individuels historiques ne sont pas réécrits ; les anciens
résumés de batch archivés ne sont pas recalculés implicitement.

Les totaux partiels de consommation, les coûts des lignes sans évaluation et
leur affichage restent un lot distinct. R13 ne refond pas leurs calculs ni ne
supprime les données de coût/tokens existantes.

Les findings hors vérité terrain sont des non-correspondances dans l’entonnoir
fermé du benchmark, sans exemption automatique « bonus ». Une vraie découverte
hors corpus exige une adjudication séparée et une nouvelle version du corpus,
pas une modification opportuniste du score publié.

Les runs antérieurs ne sont ni réécrits ni promus au nouveau contrat. La présence
du registre brut, des métadonnées et des traces détermine les étapes disponibles.

## Inspiration méthodologique

- [LLMDFA, NeurIPS 2024, §4.2](https://papers.nips.cc/paper_files/paper/2024/file/ed9dcde1eb9c597f68c1d375bbecf3fc-Paper-Conference.pdf) : évaluation séparée des phases.
- [RepoAudit, ICML 2025, annexe C](https://arxiv.org/html/2501.18160v3) : mesurer l’effet du validateur sur VP et FP.
- [AutoPenBench, EMNLP 2025](https://aclanthology.org/2025.emnlp-industry.114.pdf) : progression par étapes.
- [CyberGym-E2E, 2026, §3.4](https://arxiv.org/html/2606.04460v1) : validation observable et taux cumulatifs.

Les unités et dénominateurs ci-dessus sont propres à notre inventaire de failles
IoT ; ils ne prétendent pas reproduire les scores de ces papiers.
