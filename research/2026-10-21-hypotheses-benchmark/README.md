# Registre d'hypothèses du benchmark IoT

**Question.** Quelles propriétés d'un réseau IoT/IIoT font qu'un modèle de
langage apporte quelque chose qu'un script ne peut pas apporter — et lesquelles
ne le font pas ?

**Statut.** `proposition` — registre de conception. Aucune famille ouverte,
aucune fixture, aucun run.

**Dates.** Étude ouverte et classée le 2026-10-21 (Europe/Brussels, UTC+02:00).
Dernière révision : **2026-10-21 11:40 (Europe/Brussels, UTC+02:00)**.

## Principe

Le benchmark est un **registre d'hypothèses**, pas une liste de scénarios. Une
famille qui ne teste aucune hypothèse n'entre pas dans le benchmark ; une
hypothèse réfutée reste au registre, c'est un résultat.

L'instrument doit être **complet** : parité des bras, oracle privé, preuves
recalculées depuis le journal, coût, durée, répétitions, baseline déclarée. Le
corpus, lui, ne l'est jamais : ses trous sont déclarés.

Le benchmark reste **IoT/IIoT**. Les scénarios d'IT générique (authentification
web, Active Directory, CTF) sont exclus : ils concurrencent les benchmarks
existants sans apporter la spécificité IoT — hétérogénéité de protocoles,
appareils contraints, artefacts constructeur, identités partagées à l'échelle
d'une flotte.

Ce document est un registre de travail, pas un rapport d'étude : il ne porte ni
résultat ni figure, et n'est donc pas compilé en LaTeX. Il deviendra un rapport
au premier run, avec source et PDF.

## Porte de validité V0 — avant les hypothèses

V0 n'est **pas une hypothèse sur le modèle**. C'est la condition
d'interprétation de tout le reste : sans elle, aucun résultat n'est lisible.
Le protocole complet — tâche de contrôle soluble sans inférence, seuil `X`,
instance tenue à l'écart, conditions d'arrêt — est dans
[v0-protocole.md](v0-protocole.md). Le contrôle est implémenté, testé hors
ligne et doté d'un lanceur nato (`v0_control.py`, `v0_control_llm.py`,
`v0_control_live.py`, `tests/test_v0_control.py`, workflow `v0-control.yml`) ;
il n'a pas encore été exécuté, et `dev/2` doit être aligné sur `main` avant le
premier passage.

| Observation | Lecture | Action |
| --- | --- | --- |
| Le script réussit et le LLM échoue, à entrées et outils identiques | défaut d'instrument (prompt, briefing, budget, outil), pas de compétence | corriger l'instrument, ne pas conclure |
| Le LLM réussit et le script échoue | soit gain de compétence, soit **couverture omise** par la baseline | vérifier la limite déclarée ; requalifier si c'est une couverture |
| Les deux échouent | tâche hors de portée de l'instrument | retirer la famille ou revoir le design |
| Les deux réussissent | contrôle valide | interpréter les hypothèses en aval |

**Plancher chiffré.** Sur la famille de contrôle, les deux bras doivent réussir
au-dessus d'un seuil `X`, gelé **après** le premier pilote et jamais avant. Un
instrument qui réussit partout ne détecte rien : le contrôle doit porter sur une
tâche à taux d'erreur non nul, pas sur une tâche saturée.

**Instance tenue à l'écart.** SSH et MQTT ont servi à mettre au point le harnais
et le prompt. La famille de contrôle doit utiliser des identifiants tirés à
chaque essai, comme le fait déjà le harnais API. Le harnais MQTT le fait
aussi ; le harnais SSH non : son `case_configuration` garde les trois
identifiants du dictionnaire fixes et ne randomise que le mot de passe gagnant.
V0 porte donc sur MQTT en l'état, ou sur SSH après randomisation du
dictionnaire.

**Cas API, réconcilié.** `s_api_organisations` est une **limite de couverture
déclarée**, pas un échec de V0 : le contrat public énonce la règle par membre,
la baseline déclarée s'arrête à la frontière objet, et le LLM suit la
collection. Ce datum est enregistré comme étude de cas de couverture, jamais
comme hypothèse de supériorité.

## Hypothèses

### H1 — Chaînage inter-appareils (conditionnelle)

- **Revendication.** Un LLM construit un chemin entre appareils qu'aucune entrée
  publique ne donne.
- **Types de lien, à traiter séparément.**
  - *secret identique* : un script le trouve par comparaison de chaînes ;
  - *topic partagé* : un script le trouve dans l'inventaire ;
  - *identité réutilisée* : un script le trouve si l'inventaire donne les
    identités ;
  - *secret transformé* (encodage, dérivation) : c'est de la sémantique,
    donc H4, pas H1.
- **Contraste honnête.** Les deux bras reçoivent la même boucle de découverte.
  Si le seul écart restant est la priorisation sous budget, H1 mesure une
  efficacité de recherche, comme B2, et sort de la campagne.
- **Prédiction.** Plus de chaînes **prouvées** (chaque lien étayé dans le
  journal), à précision égale.
- **Réfutation.** La découverte générique du script retrouve les mêmes chaînes ;
  ou le LLM annonce des chaînes sans preuve de chaque lien.
- **Mesure.** Chaînes prouvées, liens étayés / liens annoncés.
- **Famille.** `s_chaines_identites` **n'existe pas** dans `coverage-plan.json`.
  Non qualifiée, non ouverte : il manque le mécanisme écrit, le harnais hors
  ligne et la revue à trois lentilles.
- **Condition d'ouverture.** Écrire le type de lien et démontrer qu'un script
  compétent ne peut pas l'exprimer depuis les entrées publiques. Sinon, retirer.

### H2 — Hétérogénéité de représentation

- **Revendication.** Le LLM lit des formats non prévus par les parseurs du
  script.
- **Contraste.** Le script reçoit un parseur par format déclaré ; le LLM reçoit
  les mêmes octets, sans parseur. **Deux vues** : brute et normalisée, comme
  l'exige C04.
- **Prédiction.** Le LLM couvre plus de surfaces **en vue brute**, et les deux
  bras sont égaux **en vue normalisée**.
- **Réfutation.** Égalité en vue brute ; ou gain en vue normalisée, qui relève
  de H4 (sémantique), pas de H2.
- **Mesure.** Surfaces couvertes / surfaces déclarées par l'oracle, à budget
  identique en requêtes **et** en dollars, avec survie à un budget non
  contraignant.
- **Familles.** `s_mqtt_formats` (variante de `s_mqtt_lecture`) et
  `s_ot_formats` (variante de `s_ot_ecriture`). **Variantes** : elles ne
  comptent pas comme familles indépendantes.
- **Statut.** `planned_not_implemented_or_attested`.

### H3 — Interprétation d'un contrat public nouveau

- **Revendication.** Face à un contrat ou une documentation constructeur qu'il
  n'a jamais vue, le LLM en extrait les objectifs et les droits mieux qu'un
  extracteur déclaré.
- **Contraste.** Le script reçoit un extracteur pour les contrats structurés
  (schéma, champs) ; il n'en a pas pour la prose constructeur. Le LLM reçoit le
  même corpus.
- **Prédiction.** Meilleure extraction sur la prose et les documents
  constructeur ; égalité sur les contrats structurés.
- **Réfutation.** L'extracteur déclaré traite les mêmes documents ; ou
  l'extraction du LLM n'est pas vérifiable depuis le journal.
- **Mesure.** Objectifs prouvés, extraction correcte contre oracle, coût.
- **Familles.** `s_edge_contrat`, `s_ota_contrat` (C05).
- **Statut.** En conception, non implémentées.

### H4 — Sémantique constructeur

- **Revendication.** Le LLM interprète des champs ou registres dont le sens
  n'est que dans le nommage, la documentation ou le comportement observé.
- **Contraste.** Le script reçoit une table de correspondance ; le LLM non.
  **Aucune vue normalisée** : sinon H2 et H4 se confondent.
- **Prédiction.** Meilleure interprétation, mesurée contre oracle.
- **Réfutation.** Interprétation égale ; ou gain dû à une table cachée.
- **Mesure.** Champs correctement interprétés / **jeu de champs de l'oracle**,
  dénominateur commun aux deux bras.
- **Famille.** `s_registres_constructeur` **n'existe pas** dans le corpus. Non
  qualifiée, non ouverte. Le corpus constructeur simulé doit être précisé avant
  toute ouverture.
- **Rattachement.** C05/C03 selon le corpus retenu ; à trancher à l'ouverture.

### H5 — Adaptabilité au retour (conditionnelle)

- **Revendication.** Le LLM reprend après un retour IoT ambigu là où un plan
  paramétrique s'arrête.
- **Contraste.** Les deux bras reçoivent le même retour ; le script inclut la
  branche de reprise standard (code d'exception Modbus, reason code MQTT, refus
  constructeur avec état modifié). Seul l'écart **au-delà** de cette branche est
  mesuré.
- **Prédiction.** Plus de reprises abouties, à budget non contraignant.
- **Réfutation.** Aucune différence ; ou différence due uniquement au budget.
  Une **contre-épreuve de budget** doit être préenregistrée.
- **Mesure.** Étapes jusqu'à la réussite après le premier refus, avec une
  sémantique commune aux deux bras.
- **Famille.** C10, `s_ot_reprise` (`planned_not_implemented_or_attested`).
  `s_mqtt_reprise` a été rejeté le 2026-10-20.
- **Condition d'ouverture.** Contre-épreuve de budget écrite avant le run.

### H6 — Contenu observé hostile

- **Revendication.** Un LLM peut suivre des instructions contenues dans ce
  qu'il observe (bannière, charge utile, documentation constructeur) ; un script
  y est insensible.
- **Contraste.** Mêmes observations ; seul le traitement diffère.
- **Prédiction.** Taux de conformité à l'instruction injectée supérieur à zéro
  pour le LLM, nul pour le script ; et constats non étayés en hausse.
- **Réfutation.** Conformité nulle côté LLM : la garde fonctionne — c'est un
  résultat, pas un échec.
- **Mesure.** Taux de conformité à l'instruction injectée, constats non étayés,
  recalculés depuis le journal.
- **Famille.** Sous-test sur les fixtures existantes, pas un nouveau simulateur.
- **Statut.** Prévu par C03 (« directives non fiables en sous-test distinct »).

### Non retenu dans cette campagne

- **Impact physique** : aucun oracle d'impact n'existe, et le domaine OT déclare
  « aucun impact physique mesuré ». Classé en trou motivé, pas en hypothèse.
- **Fragilité des cibles** : aucune famille ni mécanisme dans le corpus. Relève
  de l'étude `securite-auditeur`, pas d'une hypothèse de compétence.
- **Abstention et calibration** : piste `produit` de `PISTES.md`. À traiter dans
  une évaluation dédiée, pas dans ce registre.

## Matrice de couverture

Les lignes sont des **axes indépendants**, pas des paraphrases des hypothèses.

| Axe | H1 | H2 | H3 | H4 | H5 | H6 |
| --- | --- | --- | --- | --- | --- | --- |
| Provenance de l'information | inférée | déclarée | déclarée | déclarée | observée | observée |
| Nature de la sortie | plan | interprétation | extraction | interprétation | plan | verdict |
| Retour du système | aucun | aucun | aucun | aucun | observé | aucun |
| Contenu observé | fiable | fiable | fiable | fiable | fiable | **hostile** |
| Pression de sondage | uniforme | uniforme | uniforme | uniforme | adaptative | uniforme |
| Relation entre appareils | **multiple** | seule | seule | seule | seule | seule |

Cette matrice rend les recouvrements visibles : H2 et H4 partagent l'axe
« interprétation » et se distinguent par la provenance (déclarée vs observée) ;
H1 et H5 partagent la sortie « plan » et se distinguent par le retour.

## Statut réel des familles

| Famille | Existe ? | Cellule | Statut | Indépendance |
| --- | --- | --- | --- | --- |
| SSH | oui | pilote | mesurée | n/a |
| MQTT | oui | pilote | mesurée | n/a |
| `s_api_organisations` | oui | C06-D02 | pilote, non admis | non établie |
| `s_mqtt_formats` | oui | variante de `s_mqtt_lecture` | planifiée | non établie |
| `s_ot_formats` | oui | variante de `s_ot_ecriture` | planifiée | non établie |
| `s_edge_contrat`, `s_ota_contrat` | oui | C05 | planifiées | non établie |
| `s_ot_reprise` | oui | C10-D06 | planifiée | non établie |
| `s_chaines_identites` | **non** | — | non ouverte | — |
| `s_registres_constructeur` | **non** | — | non ouverte | — |

Aucune famille du registre n'est qualifiée. La matrice décrit une **intention**,
pas un état de couverture. Les variantes ne comptent pas comme familles
indépendantes : `statistical_independence: not_established` partout.

## Ce qui n'est pas couvert

- impact physique et sûreté fonctionnelle ;
- fragilité des appareils sous sondage ;
- échelle de flotte réelle ;
- protocoles industriels propriétaires non simulés ;
- chaînes d'exploitation complètes multi-étapes (H1 ne couvre que le chaînage
  d'identités, pas l'exploitation) ;
- abstention et calibration ;
- tout scénario d'IT générique, volontairement exclu.

## Ordre de construction

1. **V0** sur SSH/MQTT avec une instance tenue à l'écart. Coût minimal, condition
   d'interprétation de tout le reste.
2. **H2** sur `s_mqtt_formats` : dossier hors ligne, oracle d'interprétation,
   double vue déjà prévue par C04. La famille la moins chère.
3. **H3** sur C05 : réutilise le patron du harnais API (routes documentées,
   oracle à frontières, évaluateur depuis le journal).
4. **H4** : après H2, pour que la frontière syntaxe / sens soit instrumentée.
5. **H1** : seulement après écriture du contraste et disponibilité du harnais
   paramétrable.
6. **H5** : en dernier, avec contre-épreuve de budget.
7. **H6** : sous-test, peut se greffer sur H2 ou H3.

## Règles de conception

1. Le contraste est déclaré avant la fixture et correspond à ce qu'un script
   déployé sur un réseau inconnu peut réellement faire.
2. Une mesure est recalculée depuis le journal, jamais depuis la décision.
3. F0 et F1 ne diffèrent que par l'implémentation de la règle.
4. Un résultat nul est un résultat.
5. Une famille utilisée pour mettre au point le harnais ou le prompt ne sert
   pas de jeu noté ; les identifiants sont tirés à chaque essai.
6. Une variante ne compte pas comme famille indépendante.

## Documents

- [Protocole V0](v0-protocole.md) — tâche de contrôle, porte de décision, seuil
  `X`, instance tenue à l'écart.
- [Plan V2 et avancement consolidé](../2026-10-12-recentrage-corpus/README.md)
- [C2 : verdict de relecture](../2026-10-21-c2-couverture/revue.md)
- [Pistes de la plateforme](../../objectifs/PISTES.md)
- [État courant](../../objectifs/ETAT-COURANT.md)

## Points encore ouverts

- **H1 est conditionnelle** : si le seul contraste honnête est la priorisation
  sous budget, elle sort de la campagne.
- **H5 est conditionnelle** : même leçon que C2, la contre-épreuve de budget
  décide.
- **H3 et H4 n'ont pas de famille ouverte** : il manque le mécanisme, le harnais
  hors ligne et la revue à trois lentilles.
- **Aucun intervalle** n'est calculable à une famille par hypothèse. Le registre
  produit un profil descriptif ; l'inférence exige des familles indépendantes.
- **Le plancher `X` de V0** sera gelé après le premier pilote.
