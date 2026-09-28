# Pilote D1/A1

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
