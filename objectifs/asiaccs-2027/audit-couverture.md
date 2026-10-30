# Audit de couverture des scénarios (étape 0, avant gel du pilote)

Date : 2026-10-12. Source : calcul sur `benchmarks/ground_truth/dev/` et
`benchmarks/ground_truth/test/` (31 vérités terrain, dont 2 durcies à zéro
faille), `benchmarks/catalog.yaml`, `benchmarks/packs/definitions/`.
Aucun run exécuté pour cet audit.

**Correction du 2026-10-23 (Europe/Brussels, UTC+02:00).** Le constat 1 annonçait
215/288 (75 %) alors que son propre tableau somme 243/288 (84,4 %) : trois lignes
étiquetées « Signature » (`info_disclosure`, `cve`, `missing_header`) étaient
omises du total. Le constat 2 attribuait la strate logique à S15 seul ; elle
couvre S15, S22 et S28. Aucun chiffre du tableau n'a changé, seuls les totaux.

**Deux comptages coexistent dans ce document, et ils ne mesurent pas la même
chose.** Le premier est **interprétatif** : la colonne « Lecture » du constat 1
juge si une règle bien conçue peut conclure seule, et range chaque catégorie en
signature, mixte, chaînage ou logique. Le second est **mécanique** : le champ
`type` de `benchmarks/labels/derived_index.json` est binaire et ne connaît que
`logique` (catégories `broken_access_control` et `auth_bypass`) et `signature`
(tout le reste). Les deux sont légitimes ; ils ne doivent jamais être cités
l'un pour l'autre. Ce document emploie le comptage interprétatif ; l'index
dérivé donne, lui, 282/288 `signature` et 6/288 `logique`.

## Constat 1 — Le corpus est massivement « routine »

Répartition des 288 vulnérabilités attendues par catégorie :

| Catégorie | Nombre | Lecture |
| --- | ---: | --- |
| misconfiguration | 70 | Signature, favorable aux règles |
| data_exposure | 54 | Signature |
| no_authentication | 50 | Signature |
| default_credentials | 41 | Signature |
| info_disclosure | 16 | Signature |
| code_injection | 13 | Mixte |
| insecure_update | 12 | Mixte |
| weak_crypto | 10 | Mixte |
| cve | 9 | Signature |
| privilege_escalation | 4 | Chaînage |
| broken_access_control | 4 | Logique — voir constat 2 |
| auth_bypass | 2 | Logique |
| missing_header | 3 | Signature |

**243 vulnérabilités sur 288 (84,4 %) relèvent de catégories à signature**
qu'une automatisation à règles bien conçue détecte par construction ; 35
(12,2 %) sont mixtes, 4 relèvent du chaînage et 6 de la logique d'autorisation.
Le total des quatre lectures fait bien 288.
Un duel global sur ce corpus mesurerait donc surtout la qualité des
règles, pas l'apport du modèle. C'est le biais que la proposition de
recentrage cherche à isoler par conditions.

## Constat 2 — Les familles « adaptatives » sont quasi absentes

| Condition visée | Couverture réelle | Détail |
| --- | --- | --- |
| Faille logique / autorisation | 3 scénarios, 6 entrées | S15 (3 `broken_access_control`), S22 (1 `auth_bypass`), S28 (1 `broken_access_control` + 1 `auth_bypass`) |
| Chaînage multi-saut (hop ≥ 2) | Concentrée | S11, S12, S13 (gros dev) et S20, S24-S27 (test) |
| Faible prévalence | 2 scénarios | S14 (4 failles), S21 (2 failles) |
| Protocole inconnu | Aucune en tant que telle | Aucune catégorie ne l'encode |
| Variation de surface | Non encodée | Aucun champ des vérités terrain |
| Bruit / leurres | Non encodée | Aucun champ des vérités terrain |
| Edge cases temporels/état | Absents | Voir liste ci-dessous |

Profondeur de saut : la majorité des scénarios dev sont à hop 0 uniquement
(S1, S2, S3, S9, S10, S14). Le chaînage existe mais dans les plus gros
scénarios, confondu avec la taille.

## Constat 3 — Edge cases manquants (à générer, pas à trouver)

Aucune vérité terrain n'encode aujourd'hui :

- service intermittent ou lent (échec à la première sonde) ;
- bannière mensongère ou port non standard à sémantique constante ;
- identifiants presque valides (expirés, valides sur un service seulement) ;
- faille présente mais non confirmable dans le budget (abstention correcte) ;
- hôte partiellement cohérent (scan OK, exploitation impossible) ;
- leurre plausible (contenu anodin formaté comme un secret, réponse 200).

Ce sont précisément les cas où le comportement (réviser, s'abstenir,
distinguer) sépare une politique adaptative d'un script. Ils relèvent de
la génération de variantes (proposition, condition b/c/d), pas du corpus
existant.

## Constat 4 — Le contrôle sain du pilote existe déjà

Le manifeste pilote utilise un contrôle sain fictif (`healthy`,
`ground_truth: null`, « reste à préparer »). Or `S1h.yaml` (réseau plat
durci, 0 faille, même topologie que S1) et `S4h.yaml` existent dans
`benchmarks/scenarios/dev/`, avec vérités terrain
`scenario_1h.yaml` / `scenario_4h.yaml`. **S1h est le contrôle apparié
naturel de S1** : même forme, zéro faille — il mesure la spécificité
sans changer de topologie.

## Verdict sur le set pilote actuel

| Élément du set | Verdict | Motif |
| --- | --- | --- |
| S1 (plat, routine) | Garder | Référence routine, apparié à S1h |
| S14 (épars, faible prévalence) | Garder | Seule strate basse prévalence du dev avec S21 |
| S15 (API multi-tenant) | Garder | Plus grosse part de la strate logique, qui couvre aussi S22 et S28 (6 entrées au total) |
| Contrôle `healthy` fictif | **Remplacer par S1h** | Existe, déployable, apparié à S1 |
| 3 répétitions, ordre alterné | Garder pour le pilote | Calibration de mesure, pas conclusion |

Le set pilote ainsi corrigé (S1, S14, S15, S1h) reste un set de
**calibration** : 4 situations, aucune variation de surface, aucun bruit,
aucun protocole inconnu. Il valide la mesure ; il ne préfigure pas la
campagne, dont le set devra couvrir les conditions de la proposition
(familles tenues à l'écart, edge cases générés ci-dessus).

## Suite

1. Geler le pilote sur S1 / S14 / S15 / S1h (manifeste réel, modèle figé).
2. Concevoir le set de campagne à partir des cases vides (constats 2-3),
   pas en prolongeant le corpus existant.

Propositions détaillées et relues (grille dérivée, edge cases EC1-EC4,
séquençage) : rapport de recherche
[structuration du corpus (PDF)](../../research/2026-10-12-recentrage-corpus/structuration-corpus.pdf)
([LaTeX](../../research/2026-10-12-recentrage-corpus/structuration-corpus.tex)),
révision 2026-10-12 23:05.
