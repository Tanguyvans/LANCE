# Famille pilote `s_registres_constructeur` : cahier des charges

**Cycle de vie : Actif — cahier des charges** — étude ouverte le **2026-10-30**.
Dernière révision : **2026-10-30 13:35 (Europe/Brussels, UTC+01:00)**.
Statut : **spécification à exécuter en session dédiée ; aucune fixture, aucun run.**

## Question et périmètre

Peut-on construire **une famille de scénarios réellement indépendante**, dont le
test de clôture est exécutable, et qui permette de comparer une automatisation à
règles et un modèle sur une base défendable ?

Le périmètre est volontairement étroit : **une seule famille, menée de bout en
bout jusqu'à la conclusion**. Elle sert de gabarit pour les suivantes. Ce n'est
pas une campagne, c'est la preuve que le mécanisme fonctionne.

## Pourquoi cette famille

Trois raisons convergentes, vérifiées dans le dépôt.

1. **Elle n'existe pas.** Le registre d'hypothèses H4 note que
   `s_registres_constructeur` « n'existe pas dans le corpus ; non ouverte ».
   Construire neuf évite de réutiliser des templates déjà vus, ce qui est
   précisément ce qui invalide les familles existantes.
2. **La matière existe déjà.** Le pack `f15_ot_protocols` fournit un serveur
   Modbus/TCP avec un registre jetable (port 502, holding register 100
   restaurable) et un simulateur OPC UA. Le substrat est là ; la sémantique est à
   ajouter.
3. **C'est la seule zone où le gain du modèle n'est pas absorbable par une
   convention.** L'analyse de H2 a montré qu'un script qui lit par convention
   couvre les formats déclarés. La sémantique d'un registre constructeur ne se
   déduit pas d'un nom de champ : elle est dans le nommage, la documentation ou
   le comportement observé.

## Condition d'ouverture : le test de clôture doit être exécutable

C'est la partie que les familles existantes n'ont jamais satisfaite, et qui a
fait rejeter C2.

**Définition retenue.** D1+ désigne D1 augmenté de toutes les règles dérivables
des **entrées publiques** : routes documentées, champs déclarés, texte public,
comportement observable par sondage autorisé.

**Exigence.** Le test de clôture doit être **du code exécutable et hashé**, pas
une doctrine. Il est lancé sur chaque famille avant toute mesure :

| Résultat du test de clôture | Conséquence |
| --- | --- |
| D1+ réussit | La famille ne mesure rien : consignée comme omission de couverture, rejetée |
| D1+ échoue, un script devineur réussit | La famille mesure une devinette : rejetée |
| D1+ échoue, le script devinette échoue, l'échec survit à un budget non contraignant | La famille est **qualifiée** |

Contrôle positif obligatoire : le test de clôture est d'abord lancé sur
`s_api_organisations`, dont on **sait** que D1+ réussit. S'il n'y réussit pas, le
test est cassé, pas la famille.

## Ce qui rend la famille indépendante

Une famille n'est pas indépendante parce qu'elle porte un identifiant
différent. Elle l'est si les trois conditions suivantes sont vérifiées et
**écrites avant la fixture** :

| Condition | Vérification |
| --- | --- |
| **Simulateur propre** | Le serveur de registres n'est utilisé par aucune autre famille ; son code est distinct |
| **Vocabulaire propre** | Aucun nom d'appareil, identité, format ou identifiant n'est réutilisé d'une autre famille |
| **Template de vérité terrain discret** | Aucune entrée de vérité terrain ne partage de `template_key` avec une autre famille |

Une quatrième condition, plus difficile : **la non-corrélation des résidus** ne
se vérifie que sur au moins trois familles. Elle est hors de portée pour une
famille pilote et doit être déclarée comme telle.

## Conception de la famille

**Mécanisme.** Un appareil expose des registres dont la signification n'est
donnée par aucun champ public. Elle est portée par une convention de nommage
constructeur : par exemple, une unité de mesure nommée par configuration plutôt
que par nature. La règle de sécurité n'est vraie que si l'on interprète
correctement ce que le registre contient.

**Trois classes de sémantique**, à traiter séparément car elles n'ont pas le
même sort :

| Classe | Exemple | Statut |
| --- | --- | --- |
| (a) Décodage | Échelle 0,1, offsets, boutisme | **N'appartient pas à cette famille** : une table suffit. C'est H2 |
| (b) Comportement observable | Le bit 3 reste à zéro après écriture | **Mort par construction** : le protocole est public, un script actif le dérive |
| (c) Sémantique projetée | Un registre nommé par son rôle configuré | **Zone où la famille vit** |

Seule la classe (c) est mesurée. Les classes (a) et (b) servent de témoins :
une erreur de classification sur elles invalide la famille.

**Fixture.** Huit dossiers, croisant `{référence, variante}` et `{sans, avec
défaut}`, comme H2. Le générateur tire à chaque essai l'adresse, l'identifiant
d'unité et l'ordre de configuration d'une graine non publiée.

**Oracle privé.** Une table `(appareil, registre, classe a/b/c, propriété
attendue, preuve admissible)`. Le dénominateur est ce jeu de propriétés, commun
aux deux bras.

**Bras.** Trois, comme H2 :

| Bras | Ce qu'il fait |
| --- | --- |
| D1+ | Les règles, augmentées de tout ce qui dérive des entrées publiques |
| Convention élargie | Un script qui devine le nommage, sans aucune clé du corpus |
| LLM | Le modèle, sans table de correspondance ni parseur |

Le bras par convention est **obligatoire dès la conception** : c'est lui qui a
révélé que le gain de H2 était absorbé.

## Prédicats de succès

| # | Prédicat | Réfutation |
| --- | --- | --- |
| P1 | A1 > D1+ sur la justesse attestée, classe (c) seulement | Égalité, ou gain absorbé par la convention |
| P2 | Égalité sur les classes (a) et (b) | Un gain sur (a) ou (b) signifie que la famille déborde sur H2 |
| P3 | Faux positifs « sémantique inventée » sous un seuil préenregistré | Un constat attesté par un artefact qui ne le soutient pas |
| P4 | L'écart ne dépend pas du budget | Il disparaît quand le budget n'est plus une contrainte |

**Justesse attestée** : un champ n'est correct que si le constat cite un
artefact recalculable (identifiant d'observation, adresse, octets écrits et lus,
réponse) reproduit par le témoin. C'est ce qui distingue « le modèle connaît
Modbus » de « le modèle a lu ce registre ».

## Témoin sain (F0)

Une variante où la fixture est intacte et où **aucune projection n'existe**. Les
deux bras doivent déclarer « pas de projection », et non seulement « rien
trouvé ». Sans ce témoin, un modèle qui invente serait félicité.

## Ce que la famille ne prouvera pas

- Rien sur les autres mécanismes : une famille ne fait pas une carte.
- Rien sur l'indépendance statistique, qui exige au moins trois familles.
- Rien si le test de clôture n'est pas exécutable : la famille resterait une
  intention.

## Plan de travail pour la session dédiée

Dans l'ordre des dépendances. Chaque étape laisse un artefact vérifiable.

1. **Écrire D1+.** Le code des règles dérivables des entrées publiques, avec sa
   version et son empreinte. Sans lui, aucun test de clôture n'existe.
2. **Écrire le test de clôture.** Exécutable, hashé, avec son contrôle positif
   sur `s_api_organisations`.
3. **Construire le simulateur de registres.** Distinct de `f15`, vocabulaire
   propre.
4. **Construire les huit fixtures et l'oracle privé.**
5. **Passer le test de clôture.** Si D1+ réussit, arrêter et consigner.
6. **Mesurer.** Trois bras, répétitions, budget non contraignant.
7. **Conclure** selon P1 à P4, ou déclarer la famille non qualifiée.

## Points à trancher en début de session

1. **Décimale de déclaration** : sur quel vocabulaire le nommage constructeur
   s'appuie-t-il ? Une unité nommée, un rôle configuré, un identifiant
   d'enregistrement ?
2. **Où vit le test de clôture** : dans `src/benchmark/` avec les autres règles,
   ou à côté de la famille ?
3. **Faut-il modifier l'inférence** pour admettre une famille unique, ou
   assumer que la famille pilote reste descriptive ?

## Documents liés

- [Registre d'hypothèses](../2026-10-21-hypotheses-benchmark/README.md), H4.
- [Leçon de H2](../2026-10-21-hypotheses-benchmark/h2-protocole.md) : le gain
  absorbé par la convention.
- [Rejet de C2](../2026-10-21-c2-couverture/README.md) : ce qui arrive quand le
  test de clôture n'est pas exécutable.
- [État courant](../../objectifs/ETAT-COURANT.md) : blocage D1+.
