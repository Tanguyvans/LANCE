# Recherches LANCE

Ce dossier conserve les questions étudiées, les sources, les hypothèses, les
protocoles proposés et les analyses. La [documentation de référence](../docs/README.md)
présente les comportements implémentés, les contrats retenus et les procédures.

## Sujets

| Date du dossier | Étude | Question | Statut |
| --- | --- | --- | --- |
| 2026-09-27 | [Agent / automatisation](2026-09-27-agent-vs-automation/README.md) | Quel apport mesurable du LLM face à une automatisation à règles ? | Protocole proposé ; outils D1/A1 documentés ; résultats expérimentaux à établir |
| 2026-09-29 | [Couverture du benchmark](2026-09-29-benchmark-coverage/README.md) | Que couvrent le corpus, les exécutions et les preuves admises ? | Diagnostic reproduit ; campagne réelle Qwen UMONS S1–S12 en cours depuis le 4 octobre 2026 |
| 2026-09-29 | [Scalabilité du contexte](2026-09-29-context-scalability/README.md) | Comment conserver les preuves utiles dans le contexte des six phases ? | Nouvelle revue du pipeline ; plan historique du rapport conservé comme archive |
| 2026-09-29 (classement) | [Spécialisation IoMT](2026-09-29-iomt/README.md) | Comment adapter et évaluer LANCE sur des réseaux médicaux simulés ? | Proposition de sujet de TFE ; début inconnu |
| 2026-10-05 | [Validation Qwen UMONS S1–S12](2026-10-05-benchmark-coverage/README.md) | Quels résultats et défauts les runs réels démontrent-ils ? | Rapport intermédiaire des premiers runs ; validations correctives en cours |

## Lire les rapports

Commencer par le [rapport principal en PDF](2026-09-27-agent-vs-automation/report.pdf)
([source LaTeX](2026-09-27-agent-vs-automation/report.tex)) : il relie couverture du
benchmark, contexte et apport LLM, puis propose les comparaisons à réaliser.
Les deux rapports spécialisés développent les constats et les protocoles :

- [Couverture et validité de l'évaluation — PDF](2026-09-29-benchmark-coverage/report.pdf) · [LaTeX](2026-09-29-benchmark-coverage/report.tex).
- [Campagne Qwen UMONS S1–S12 — rapport intermédiaire PDF](2026-10-05-benchmark-coverage/validation-qwen-umons.pdf) · [LaTeX](2026-10-05-benchmark-coverage/validation-qwen-umons.tex). Révision : **2026-10-05 11:48 (Europe/Brussels, UTC+02:00)** ; gel à 11:32 : deux diagnostics S1 séparés, S1 commun et rapports S2–S11, échec S12 sans score ; 14 archives, 1 582 empreintes. Premier lot terminé, validations des 14 corrections lancées sur S12 puis S1–S11 après CI et déploiement vérifiés. Rédaction Muse, corrections et contrôle Codex ; campagne en développement.
- [Conservation des preuves et contexte — PDF](2026-09-29-context-scalability/report.pdf) · [LaTeX](2026-09-29-context-scalability/report.tex).

Dernière révision des trois rapports : **2026-09-30 21:55
(Europe/Brussels, UTC+02:00)**. L'heure apparaît sur leur première page et dans
leur README. Les constats, sources et reproductions restent ceux du 29 septembre
2026 ; cette révision ajoute leur horodatage de présentation.
Les rapports ont un titre centré, un résumé, une table des matières,
des sections numérotées et des figures vectorielles modifiables dans les sources.
Ces rapports contiennent un diagnostic logiciel et des expériences
proposées ; ils ne rapportent pas de performance terrain ni de gain LLM démontré.

## Ouvrir ou poursuivre une recherche

Réutiliser le dossier de l'étude lorsqu'il couvre déjà la question. Pour une
nouvelle étude, créer `research/AAAA-MM-JJ-nom-etude/` : la date au format ISO
correspond au début de l'étude, suivie d'un nom descriptif en minuscules et tirets,
indépendant du modèle ou de l'outil ayant aidé à la recherche. Cette date et ce
dossier restent fixes lors des révisions ; Git conserve l'historique et le README
indique la dernière mise à jour. Une étude distincte reçoit son propre dossier,
avec un lien vers les travaux antérieurs pertinents.

Pour une étude historique dont le début n'est pas connu, utiliser la date de
classement et signaler cette convention dans l'index et le README ; ne pas
inventer une date de recherche. Le dossier agent / automatisation reprend ainsi
la première date documentée, le 27 septembre 2026 ; la nouvelle revue du contexte
commence le 29 septembre, tandis que le dossier IoMT utilise sa date de classement.

Créer d'abord un `README.md` ; séparer les documents seulement lorsqu'ils ont
assez de contenu pour le justifier. Les conventions générales restent dans cet
index, et chaque dossier contient les documents propres à son étude.

Structure possible, à adapter au sujet :

```text
research/AAAA-MM-JJ-nom-etude/
  README.md                 question, statut, synthèse et navigation
  report.tex                source éditable du document de recherche
  report.pdf                version de lecture compilée depuis cette source
  figures/                  figures exportées et sources graphiques si nécessaires
  state-of-the-art.md        notes bibliographiques complémentaires, si utiles
  protocol.md               détails de protocole complémentaires, si utiles
  implementation-plan.md    suivi logiciel, si utile
  results.md                observations détaillées réellement obtenues, si utiles
```

Ne pas créer de fichiers de résultats vides ni de conclusions anticipées. Les
scripts et manifestes exécutables restent dans leur module propriétaire, par
exemple `benchmarks/experiments/` ; la recherche les référence. Les artefacts
volumineux restent dans le stockage prévu pour les runs, avec un identifiant ou
une empreinte permettant de retrouver les preuves, pas une copie dans ce dossier.

## Format de lecture : LaTeX et PDF

Toute nouvelle étude ou révision de fond doit fournir un **document LaTeX éditable
et son PDF compilé**, dans le dossier du sujet. Utiliser par défaut les noms
stables `report.tex` et `report.pdf`, puis modifier ces mêmes fichiers au fil des
itérations. Le README du sujet lie les deux et précise leur statut ainsi que la
date et l'heure de dernière révision du rapport, avec son fuseau horaire.
Le PDF est le support de lecture et de discussion ; le LaTeX est sa source de
référence. Les notes Markdown servent à la navigation, aux preuves détaillées
ou au suivi, sans entretenir une seconde copie complète du rapport.

Le document doit pouvoir se lire seul : question, périmètre, statut, date,
synthèse, méthode, faits et sources, hypothèses, résultats disponibles, limites
et prochaines étapes. Un protocole proposé ou un résultat synthétique garde
ce statut dans le PDF ; la mise en page ne le transforme pas en résultat terrain.
Les références restent consultables depuis le document, avec les dates/versions
et limites de lecture prévues ci-dessous.

### Structure scientifique classique

Adopter un article ou rapport LaTeX sobre : A4, corps de 11 ou 12 points,
typographie avec empattements, titres noirs, marges régulières et pagination.
Utiliser les mécanismes LaTeX (`\maketitle`, `abstract`, `\tableofcontents`,
`\section`, `\label` et `\ref`) pour garder une structure cohérente. Le titre
est centré, suivi d'un sous-titre éventuel, de l'auteur ou de l'équipe réellement
responsable, de la date et l'heure de dernière révision et du statut.
Une couverture séparée n'est pas nécessaire.

Sur la première page, afficher **« Dernière révision »** avec la date, l'heure
sur 24 heures (précision à la minute), le fuseau `Europe/Brussels` et son décalage
UTC effectif à cette date, par exemple `2026-09-30 21:55 (Europe/Brussels,
UTC+02:00)`. La date peut être écrite en français dans le PDF. Consigner le même
instant dans la source LaTeX et le README ; le recopier dans l'index lorsqu'il
annonce une version. Fixer cette valeur lors de la révision plutôt qu'utiliser
une date dynamique à chaque compilation. Un simple export ne constitue pas une
nouvelle révision. Pour une ancienne version dont l'heure est inconnue, le préciser
sans l'inventer.

Cet horodatage identifie la version du document. Les dates de début de l'étude,
de consultation des sources et d'exécution des expériences restent distinctes ;
ne pas les actualiser lors d'une retouche de présentation. Les dossiers gardent
leur nom `AAAA-MM-JJ-nom-etude` lors de ces révisions.

Ordre attendu, à adapter à la question scientifique :

1. **Titre et métadonnées**, avec le statut explicite : exploration, protocole
   proposé, résultats obtenus ou étude conclue.
2. **Résumé**, en un paragraphe bref : question, méthode, constats principaux,
   limites essentielles et implication. Ne pas y annoncer de gain non mesuré.
3. **Table des matières automatique et cliquable**, incluant les références.
   Ajouter les sous-sections si elles aident la navigation ; une note de deux
   pages ou moins peut s'en passer si ce choix est expliqué dans son README.
4. **Objectif et périmètre**, puis **méthode** : code et données inspectés,
   sources lues, protocole, mesures et conditions de reproduction.
5. **Constats ou résultats**, avec figures et tableaux introduits dans le texte.
   Distinguer faits du code, observations synthétiques, résultats terrain et
   hypothèses ; nommer « protocole proposé » les expériences non exécutées.
6. **Discussion et limites**, avec les explications alternatives et les
   conditions nécessaires avant de généraliser.
7. **Conclusion et prochaines étapes**, reliées aux preuves disponibles.
   Une conclusion négative ou indéterminée est un résultat admissible.
8. **Références**, puis des **annexes** seulement si elles sont utiles.

Les titres précis peuvent varier selon le sujet ; ces rôles doivent rester
identifiables. Garder un corps de texte continu et des sections numérotées.
Laisser LaTeX gérer les sauts de page, puis corriger les titres orphelins et les
figures mal placées après inspection. Ne pas imposer une nouvelle page à chaque
section ni ajouter de panneaux décoratifs. Une liste des figures/tableaux est
facultative et ne remplace pas la table des matières.

Ces règles sont maintenues **ici comme référence unique**. `AGENTS.md` contient
un rappel et un lien ; les README des sujets servent à la navigation et au statut,
sans recopier les conventions. Les trois `report.tex` liés dans l'index illustrent
le format et restent autonomes pour l'éditeur LaTeX intégré.

### Compilation et vérification

Pour travailler dans Codex, ouvrir par défaut le `.tex` dans l'éditeur LaTeX
intégré et garder ce fichier pour les retouches. Privilégier un document autonome,
avec schémas et bibliographie intégrés lorsque possible. Compiler après les
modifications, exporter le PDF correspondant, puis vérifier visuellement les
pages : débordements, lisibilité des figures et tableaux, légendes et références.
Compiler autant que nécessaire pour stabiliser la table des matières, la
pagination et les renvois ; vérifier que les destinations du sommaire existent
et que les numéros correspondent au PDF final.
Conserver la source et le PDF livrable ; ne pas ajouter les fichiers temporaires
de compilation au dossier de recherche. Si compilation ou export indisponible,
signaler précisément la limite et ne pas présenter un ancien PDF comme actualisé.

### Figures modifiables

- Utiliser des figures lorsqu'elles clarifient une architecture, un protocole,
  une comparaison ou un résultat ; éviter les illustrations décoratives.
- Privilégier des schémas vectoriels éditables, notamment TikZ dans le `.tex`.
  Pour les graphiques de données, conserver les données et le code de génération
  dans leur module propriétaire et les référencer depuis l'étude ; placer les
  exports nécessaires au document dans `figures/`.
- Conserver la source de chaque figure, pas seulement une capture ou une image
  aplatie. Numéroter, légender et citer les figures dans le texte ; indiquer unités,
  populations, provenance des données et incertitude lorsque pertinentes.
- Distinguer visuellement et dans la légende l'architecture implémentée d'une
  proposition, les mesures observées d'un exemple synthétique. Ne pas dessiner
  de courbe de performance sans données correspondantes.
- Vérifier la lisibilité à la taille réelle du PDF et retoucher la source lors
  des discussions, puis régénérer le document.

Les études Markdown existantes restent consultables. Lorsqu'un sujet est repris
sur le fond, intégrer sa synthèse au document LaTeX/PDF, conserver les preuves
utiles et mettre à jour les liens et le statut des documents remplacés. Ne pas
supprimer les anciennes notes avant vérification de la reprise de leur contenu.

## Contenu minimal du README d'un sujet

- **Question et périmètre** : ce que l'étude cherche à établir.
- **Statut** : exploration, protocole proposé, expérimentation, conclu ou archivé.
  Une étude conclue peut aboutir à un résultat négatif ou indéterminé.
- **Dates** : début si connu, dernière mise à jour et horodatage de dernière
  révision du rapport (date, heure et fuseau). Distinguer le classement d'une
  ancienne note de sa recherche ou de sa validation ; ne pas inventer une heure
  historique inconnue.
- **Synthèse** : faits établis, propositions et incertitudes, sans les confondre.
- **Documents et sources** : liens vers les analyses, références et preuves.
- **Suite et documentation liée** : points ouverts, décision retenue si elle
  existe, liens vers les pages de référence alimentées par la recherche.

## Sources et preuves

Privilégier les articles d'origine, dépôts des auteurs et documentations
officielles. Noter le titre, les auteurs ou l'organisme, le lien, la date/version
et la date de consultation. Indiquer ce qui a effectivement été lu : un résumé,
un article complet ou une section. Distinguer les résultats rapportés par une
source de ceux reproduits dans LANCE, et expliciter les limites de comparaison.

Pour chaque expérience réalisée, consigner la révision du code et les changements
locaux pertinents, les versions des modèles/outils, les données ou scénarios,
la configuration, les budgets, les commandes, les identifiants des runs et les
artefacts de preuve. Rapporter aussi les échecs, exclusions et données manquantes.
Une expérience proposée reste présentée comme telle jusqu'à son exécution.
Les [règles d'autorisation et de ciblage](../AGENTS.md) s'appliquent également ici.

## Alimenter la documentation

Lorsqu'une conclusion est retenue, préciser ce qui la soutient : vérification
du code, tests logiciels ou expérience, selon la nature de l'affirmation. Mettre
à jour la page concernée de `docs/` avec le comportement ou le contrat retenu,
son périmètre, ses limites et un lien vers l'étude. Ajouter le lien retour dans
le dossier de recherche et mettre à jour les deux index.

Conserver ici les alternatives, sources et résultats détaillés. Une étude close
reste consultable ; marquer une étude remplacée comme archivée et pointer vers
la référence qui lui succède. Le déplacement d'un fichier ne valide pas son contenu.
