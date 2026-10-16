# Pilote D1/A1

## Campagne active et reprise

Le manifeste actif est [pilot-2026-10.json](pilot-2026-10.json), avec S1,
S14, S15 et S1h. Le [journal de précontrôle](pilot-2026-10-preflight.md)
conserve les essais de calibration et les changements de gel des 13–14 octobre.
Le modèle générique ci-dessous ne décrit pas l'avancement de cette campagne.

Recalcul local du 2026-10-15 : configuration complète, 12 paires prévues,
24 bras sans référence de run, zéro paire admissible. L'empreinte courante
correspond au gel `b636f0a5…`. L'absence de références dans ce checkout
n'exclut pas des artefacts présents sur nato.

`next-trial.txt` désigne `s14-r1` ; consulter l'historique Actions, les archives
sur nato et le verrou avant tout lancement. Les essais de calibration sous
une ancienne empreinte ne doivent pas être réintégrés dans le gel courant.
La lecture distante était bloquée le 2026-10-15. Le 2026-10-16, l'API GitHub
est accessible : des workflows en succès existent pour S1 r1–r3, S14 r1–r3
et S15 r1. Le pointeur `s14-r1` est donc à réconcilier avec ces exécutions.
Le téléchargement des artefacts reste refusé par la politique réseau du cloud ;
leur comparabilité n'est pas encore vérifiée. Voir le
[relevé des runs](../../../objectifs/asiaccs-2027/README.md#reprise-distante-du-16-octobre-2026).
Aucun essai n'a été lancé lors de cette reprise.

## Modèle générique

Ce dossier contient les **entrées de préparation** de l'expérience, pas ses
résultats ni un lanceur de laboratoire.

- [pilot.example.json](pilot.example.json) : 12 paires, soit 24 exécutions prévues
  (S1, S14, S15 et contrôle sain, trois répétitions). L'ordre est alterné et
  équilibré sur l'ensemble ; il n'est pas randomisé.
- [review.csv](review.csv) : grille vide pour la revue indépendante des preuves,
  sans colonne révélant la politique.

Le manifeste est un **modèle non gelé** : `configuration` est vide, les contrôles
préalables sont `pending` et les dossiers d'exécution sont `null`. Le contrôle
sain reste à préparer et sa vérité terrain est explicitement absente. Les quatre
groupes sont des situations de calibration, pas quatre familles indépendantes
permettant à elles seules une conclusion de généralisation.

Copier le modèle sous un nom de campagne dans ce même dossier, puis fixer modèle,
budgets et ressources avant exécution. Tous les chemins sont relatifs au fichier
manifeste ; un déplacement exige de les recalculer. Conserver le plan initial,
puis renseigner les références d'artefacts sans supprimer les essais échoués.
Les inventaires publics transmis à l'agent sont distincts de ce manifeste, qui
contient des chemins vers les vérités terrain privées de l'évaluateur.

Les sorties vont sous `output/`, déjà ignoré par Git. Les contrôles, remises à
zéro, audits et revues humaines ne sont pas exécutés par le calcul du bilan.
Voir le [guide de campagne](../../../docs/benchmark/agent-vs-automation-campaign.md)
pour les commandes, la matrice D1 et le protocole de revue.


## Artefacts récupérés le 16 octobre

Le blocage de téléchargement est levé après enregistrement des paramètres.
Les comparaisons publiées donnent trois paires S1 comparables et quatre paires
incomparables (S14 r1–r3, S15 r1 ; bras LLM à 200 appels). Les archives complètes
et les précontrôles restent à réconcilier avant de remplir le manifeste.
Voir le [journal détaillé](pilot-2026-10-preflight.md#récupération-des-artefacts-actions--2026-10-16).
