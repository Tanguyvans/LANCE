# Pistes de la plateforme

**Dernière mise à jour : 2026-10-21 10:38 (Europe/Brussels, UTC+02:00).**

Registre d'idées pour la plateforme, hors du chemin critique de la soumission
AsiaCCS. Une piste n'est ni un plan ni une promesse : c'est une hypothèse de
valeur, avec son mécanisme, sa mesure honnête et son risque. Elle ne devient un
scénario qu'après qualification. Voir
[l'état courant](ETAT-COURANT.md), le
[plan V2](../research/2026-10-12-recentrage-corpus/README.md) et le
[plan de soumission](asiaccs-2027/plan-soumission.md).

## Statuts

| Statut | Sens |
| --- | --- |
| `idée` | Formulée, pas encore instruite |
| `à qualifier` | Mécanisme plausible ; il manque un harnais minimal ou un oracle |
| `qualifiée` | Passe les critères ci-dessous sur papier ; peut devenir un scénario |
| `en cours` | Un harnais ou une campagne l'exerce |
| `rejetée` | Instruite et écartée ; le motif reste écrit pour ne pas la reproposer |

## La barre à passer

Toute piste qui prétend démontrer une supériorité de **découverte** doit passer
le **test de clôture** : D1+ = D1 + toutes les règles dérivables des entrées
publiques (routes documentées, champs déclarés, texte public). Si D1+ réussit
encore, la piste ne mesure pas une compétence d'audit.

Les critères complets et les anti-patrons issus de la recherche du 20 octobre
sont résumés ici ; la source est le workflow de recherche en lecture seule
`api-script-vs-llm-research` (run `wf_bdcfffed-f35`) :

- **classe de politique bornée** publiée avant le test ;
- **parité stricte** des entrées, droits, outils, découverte et budgets ;
- **test de clôture** (ci-dessus) ;
- **dérivabilité publique** : la bonne conclusion se reconstruit depuis le
  briefing et le journal, sans oracle ;
- **sous-détermination résolue par une observation**, pas par deviner un état
  caché ;
- **familles tenues à l'écart** et compositions non énumérables ;
- **témoin exécutable** et sœur protégée F0 ;
- **mécanisme d'échec préenregistré** et reproduit ;
- **ablation A0** : le gain vient de la révision, pas d'un plan déjà écrit ;
- **évaluation depuis le journal**, jamais depuis la décision ;
- **l'échec survit à un budget non contraignant** ;
- **reset et contrebalancement** attestés ;
- **prédicat de succès propre à la tâche** (atteinte, évaluation, couverture).

Les pistes qui ne mesurent pas la découverte (rapport, copilote, mémoire,
monitoring) ont leur propre évaluation et ne passent pas ce test : elles sont
marquées `produit` et ne doivent jamais être présentées comme un résultat de
compétence.

## Axes retenus

| Piste | Statut | Type | Mécanisme | Mesure honnête | Risque principal |
| --- | --- | --- | --- | --- | --- |
| **Réutilisation d'identités entre objets** | `à qualifier` | recherche | Un secret, topic ou jeton découvert sur un appareil ouvre un autre appareil ; le LLM corrèle des indices hétérogènes | Chaînes inter-appareils prouvées, pas des constats isolés | C'est du multi-hop : test de clôture à passer |
| **Abstention et qualité de preuve** | `à qualifier` | recherche | « Preuve insuffisante » devient une sortie de première classe avec un niveau de confiance | Calibration, faux positifs, constats non étayés | Oracle humain nécessaire |
| **Audit continu et mémoire** | `idée` | produit | Réutilise empreintes et sondes gagnantes entre audits ; relance au changement de configuration | Temps jusqu'à la première preuve, dérives détectées | Fuite de solution entre essais ; hors harnais noté |
| **Graphe d'environnement vivant** | `idée` | recherche | Modèle des actifs, identités et relations de confiance, révisé à chaque observation | Précision du graphe, coût jusqu'à la première preuve | Recoupe largement les identités croisées |
| **Sémantique de protocoles ouverts** | `idée` | recherche | Arbres de topics, registres, descriptions UPnP, docs HTTP, chaînes de firmware | Couverture à budget égal, familles de schémas découvertes | Confondre compréhension de texte et compétence d'audit |
| **Synthèse d'outils à la volée** | `idée` | recherche + sécurité | Le LLM écrit et exécute de petites sondes dans un bac à sable | Couverture à coût égal, sûreté du code généré | Code généré hors périmètre ; allowlist obligatoire |
| **Architecture multi-agents** | `idée` | recherche | Planificateur, sondeur, vérificateur, critique ; le vérificateur rattrape les faux positifs | Même budget, mono-agent contre multi-agent | Coût multiplié sans métrique propre |
| **Rapport, remédiation, conformité** | `idée` | produit | Narration d'exploitation, priorisation, correspondance IEC 62443 / ETSI 303 645 | Revue d'experts, exactitude du mapping, temps gagné | Hors mesure de découverte |
| **Copilote d'auditeur** | `idée` | produit | Propose la prochaine expérience, explique, répond aux questions | Tâche complétée avec un humain, temps gagné, confiance | Difficile à reproduire ; évaluation séparée |

## Trois paris recommandés

1. **Réutilisation d'identités entre objets** — le plus proche de la valeur
   réelle d'un audit IoT, mécanisme observable (la chaîne marche ou non), et le
   scénario n'est pas saturé.
2. **Abstention et qualité de preuve** — en S1 les règles ont une meilleure
   précision que le LLM ; valoriser l'abstention transforme cette faiblesse en
   axe de recherche et rend un rapport utilisable.
3. **Audit continu et mémoire** — différenciation produit ; la métrique ne
   dépend plus d'un benchmark saturé.

## Candidats instruits et rejetés

Rejetés par les vérifications adverses (honnêteté, mesurabilité, faisabilité)
des 2026-10-20 et 2026-10-21. Le motif décisif reste écrit ; le détail du C2
est dans [le verdict](../research/2026-10-21-c2-couverture/revue.md).

| Candidat | Motif décisif |
| --- | --- |
| API composition B (note de délégation en prose) | Angle mort artificiel sur un champ public ; l'oracle F0 entre en conflit avec la divulgation |
| MQTT reprise (`s_mqtt_reprise`) | Le plan autorise déjà une branche générique de découverte ; la proposition affaiblit la baseline |
| Edge contrat B (précondition en prose) | Contredit la définition C05 (« à partir du contrat public ») et le test de clôture |
| Chaîne de prérequis | Mauvais scénario (C09 exige trois défauts) et oracle contradictoire |
| Cache et attribution | La faille se contredit (« la clé inclut l'identité ») ; la preuve est un format de journal, pas une observation |
| Jeton de service à portée confuse (C2, candidat A) | Trilemme : services publics → D1+ réussit ; refus nommant le service → D1+ parse ; refus muet → devinette de noms. Le plan se contredit entre son D1+ et son hypothèse de survie |
| Prérequis d'état non documenté (C2, candidat B) | Mauvais rattachement (C09/C10, pas C06) et trois issues toutes non conformes : route documentée → D1+ la trouve ; route cachée → devinette ; échec par budget → critère violé |
| Variante B2 : coût de recherche d'état (C09/C10) | Seule survivante technique, mais elle mesure l'efficacité de recherche sous budget, pas la clôture informationnelle ; exige un amendement du critère de budget, une borne inférieure prouvée et une famille supplémentaire. N'est pas poursuivie dans la campagne en cours |

## Ce qu'il ne faut pas reproposer

- Une faille qui dépend d'un **format de journal ou de trace** : c'est un
  instrument, pas une faille.
- Une **règle retirée** de la baseline pour créer l'écart.
- Une information publique en prose **sans** sous-détermination résolue par
  une observation : un D1+ compétent la parse.
- Une variation de **nom d'endpoint** : mesurer la devinette de chemins n'est
  pas mesurer l'audit (leçon des deux premiers lancements API).
- Une conclusion tirée de **n = 1** comme si elle était générale.

## Passer d'une piste à un scénario

1. Écrire le mécanisme, la limite déclarée de D1 et le prédicat exact que D1+
   ne peut exprimer.
2. Construire un harnais minimal hors ligne (fixture paramétrique, évaluateur
   depuis le journal, oracle privé).
3. Soumettre le design à trois lentilles adverses : honnêteté de la baseline,
   mesurabilité, faisabilité.
4. Si `qualifiée`, ouvrir le scénario dans
   `research/2026-10-12-recentrage-corpus/coverage-plan.json` et suivre les
   conventions de recherche du dépôt.

Aucun run de laboratoire n'est nécessaire pour les étapes 1 à 3.
