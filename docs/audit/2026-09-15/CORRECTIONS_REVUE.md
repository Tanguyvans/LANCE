# Corrections de la revue Astra du 15 septembre

Travail séquentiel sur le pipeline existant. Aucun changement de modèle, de
profil `full`, de vérité terrain ou de formule de score n'est prévu ici.
Les fichiers historiques ne sont pas réécrits.

## 1. Neutralité du diagnostic — implémentée et vérifiée

La politique commune dans `src/agent/artifacts.py` masque la vérité terrain
et `provider_events.jsonl`, y compris les liens symboliques vers ces fichiers.
Le runner l'applique à la liste des livrables annoncés ; les outils l'appliquent
aux lectures et écritures. Les exclusions supplémentaires propres au prompt
restent en place. L'API opérateur n'est pas modifiée.

Les tests comparent les prompts réellement transmis par `_run_agent` avec et
sans journal/alias, et vérifient que les livrables ordinaires restent visibles.
Revue indépendante et 131 tests ciblés réussis ; `git diff --check` réussi.

## 2. Continuation bornée — implémentée et vérifiée

`core/completion_policy.py` isole l'état de continuation de l'invocation : une
chance par incident, deux au total, uniquement avant le verrou de clôture.
Une réponse textuelle, vide ou signalée comme interrompue peut être suivie
d'un tour ordinaire avec les outils et la sauvegarde. L'historique est conservé.
Les refus de périmètre et les erreurs sans observation ne réarment pas l'incident.
Une tentative observée infructueuse n'a pas besoin de prouver un accès pour
permettre de continuer.

La réserve des deux derniers tours, les plafonds d'actions et de coût, les
délais, le stop et le verrou des sauvegardes rejetées restent en vigueur.
Les trois requêtes maximales de clôture restent incluses dans le plafond de
tours initial. Les reprises HTTP et le mode non opt-in ne sont pas modifiés.

Le journal ajoute `continuation_requested`, distinct de `finalization_entered`,
sans contenu sensible. Le cas de parité avec/sans observation compte maintenant
14 requêtes (9 actions, une chance de continuation, puis clôture bornée), contre
13 avant ce changement de comportement volontaire. Les tokens correspondants
ne sont pas cachés ; aucune baisse de consommation n'est garantie.

Revue indépendante : 105 tests ciblés réussis, plus 58 tests de non-régression
sur délais, reprises fournisseur et profils. Les reproductions texte puis
action puis sauvegarde, répétitions sans action et troisième incident ont
aussi été exécutées indépendamment.

## 3. Observations et affichage — implémentés et vérifiés

`phases/intrusion/observations.py` prépare la vue `intrusion-observations-v1`
depuis les enregistrements Phase 5 du journal, en utilisant `access_supported`
et `observed_targets`, déjà utilisés par l'évaluation. Aucun accès ne vient
des affirmations du modèle ; ce dernier contribue uniquement des nombres de
déclarations. Son absence ou son JSON invalide n'efface pas le journal.

La vue exige un contrat de preuve courant, une intégrité non invalidée, des
fichiers réguliers et des références d'exécution attribuables. Un journal
corrompu ou des références dupliquées donnent une vue indisponible. Les erreurs
d'intégrité connues en mémoire sont prises en compte avant l'écriture finale
des métadonnées. Les références sont des identifiants bornés ; les mots de
passe, commandes et sorties brutes ne sont pas renvoyés dans cette vue.

Le nouvel endpoint `GET /api/runs/{run_id}/intrusion-observations` et le flux
`intrusion_observations` utilisent la même fonction. Les runs scellés restent
interdits à cet endpoint. La lecture ne réécrit ni les fichiers ni les scores.
Les anciens contrats restent consultables, mais sans promotion implicite de
leurs affirmations en preuves actuelles.

L'interface n'utilise plus `05_intrusion.json` pour colorer les machines ou
tracer des pivots. Elle affiche « accès corroboré » avec du texte, pas uniquement
une couleur. Les événements historiques de compromission/pivot sont signalés
comme déclaratifs. Les réponses asynchrones périmées ne doivent pas remplacer
une vue plus récente. L'état de campagne et les observations restent distincts.

Les transitions sont toujours vides avec `transition_evidence_available=false` :
l'exécuteur actuel ne fournit pas de preuve causale de transition réseau. Deux
connexions directes et une chaîne déclarée ne changent pas cette limite. Une
authentification à un service n'est pas présentée comme un contrôle du système.

Revue indépendante : 122 tests ciblés backend/UI/runs/finalisation réussis,
plus 4 tests HTTP sur la priorité de routage, l'immuabilité, les liens symboliques
et la confidentialité des runs scellés. Un test traverse le journal réel, la
projection Python et le véritable gestionnaire JavaScript du tableau de bord.

## Structure et périmètre

La visibilité des artefacts, la politique de continuation et la projection
d'observations ont chacune une responsabilité séparée. Le pipeline et les
dossiers par phase sont conservés. La suppression générale des mixins/globaux,
le déplacement de tous les validateurs et une nouvelle preuve de pivot réseau
ne font pas partie de ces trois corrections. Les reprises HTTP existantes ne
sont pas réécrites non plus.

## Validation globale

Suite complète locale sous Python 3.12 : **2 414 réussis, 1 ignoré, 3
avertissements de dépréciation**, aucun échec (154,77 secondes). Les permissions
nécessaires aux sockets localhost des tests Ansible et protocolaires ont été
accordées ; aucun scénario d'intrusion n'a été lancé. Une sélection exploratoire
de fichiers avait rencontré des fixtures introuvables ; les tests concernés
relancés séparément puis la suite complète standard passent.

Les 31 vérités terrain, la syntaxe JavaScript et `git diff --check` ont été
validés. Ces validations précèdent la publication des changements.

## Revue avant publication

Une seconde revue indépendante Astra a identifié deux défauts, reproduits par
des tests en échec avant correction :

- Le rechargement de l'interface attendait encore `05_intrusion.json` avant de
  consulter les observations. `viewRun()` consulte désormais la projection pour
  tout run non scellé, même sans déclaration du modèle. Les tests traversent ce
  gestionnaire réel, avec et sans fichier modèle, et vérifient qu'un run scellé
  ne demande jamais cet endpoint.
- Un rejet d'arguments MQTT avant exécution pouvait réarmer la continuation à
  cause des champs de sortie présents dans sa réponse. `invalid_tool_arguments`
  est désormais un refus explicite pour la politique de continuation ; le rejet
  préexécution SSH reçoit le même marqueur. Les tests passent par les véritables
  fonctions d'outils, vérifient l'absence de subprocess et le passage à la clôture
  seule. Une authentification réellement tentée mais échouée reste une observation
  autorisant une nouvelle continuation, dans la limite globale existante.

Après correction : 18 tests UI et 142 tests fournisseur/chargeur/diagnostic
réussis. Aucun changement de modèle, profil, budget ou formule d'évaluation.
La relecture Astra a confirmé les deux corrections, rejoué 57 tests ciblés et
ne relève plus de problème bloquant dans le périmètre revu.
La suite complète relancée après ces corrections donne **2 420 réussis,
1 ignoré, 3 avertissements de dépréciation**, aucun échec (152,91 secondes).

La réussite des tests hors ligne ne constitue pas une validation d'un nouveau
run S1 avec le fournisseur réel. Un essai contrôlé reste nécessaire après
publication et déploiement autorisés.
