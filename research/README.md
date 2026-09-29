# Recherches LANCE

Ce dossier conserve les questions étudiées, les sources, les hypothèses, les
protocoles proposés et les analyses. La [documentation de référence](../docs/README.md)
présente les comportements implémentés, les contrats retenus et les procédures.

## Sujets

| Dossier | Question | Statut |
| --- | --- | --- |
| [Agent / automatisation](agent-vs-automation/README.md) | Quel apport mesurable du LLM face à une automatisation à règles ? | Protocole proposé ; outils D1/A1 documentés ; résultats expérimentaux à établir |
| [Couverture du benchmark](benchmark-coverage/README.md) | Que couvrent le corpus, les exécutions et les preuves admises ? | Diagnostic et contre-exemples locaux reproduits ; corrections proposées |
| [Scalabilité du contexte](context-scalability/README.md) | Comment conserver les preuves utiles dans le contexte des six phases ? | Nouvelle revue du pipeline ; plan historique du rapport conservé comme archive |
| [Spécialisation IoMT](iomt/README.md) | Comment adapter et évaluer LANCE sur des réseaux médicaux simulés ? | Proposition de sujet de TFE |

## Lire les rapports

Commencer par le [rapport principal en PDF](agent-vs-automation/report.pdf)
([source LaTeX](agent-vs-automation/report.tex)) : il relie couverture du
benchmark, contexte et apport LLM, puis propose les comparaisons à réaliser.
Les deux rapports spécialisés développent les constats et les protocoles :

- [Couverture et validité de l'évaluation — PDF](benchmark-coverage/report.pdf) · [LaTeX](benchmark-coverage/report.tex).
- [Conservation des preuves et contexte — PDF](context-scalability/report.pdf) · [LaTeX](context-scalability/report.tex).

Version du 29 septembre 2026, avec figures vectorielles modifiables dans les
sources. Ces rapports contiennent un diagnostic logiciel et des expériences
proposées ; ils ne rapportent pas de performance terrain ni de gain LLM démontré.

## Ouvrir ou poursuivre une recherche

Réutiliser le dossier du sujet lorsqu'il existe. Pour un nouveau sujet, choisir
un nom descriptif en minuscules et tirets, indépendant du modèle ou de l'outil
ayant aidé à la recherche. Créer d'abord un `README.md` ; séparer les documents
seulement lorsqu'ils ont assez de contenu pour le justifier.

Structure possible, à adapter au sujet :

```text
research/<sujet>/
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
itérations. Le README du sujet lie les deux et précise leur date et leur statut.
Le PDF est le support de lecture et de discussion ; le LaTeX est sa source de
référence. Les notes Markdown servent à la navigation, aux preuves détaillées
ou au suivi, sans entretenir une seconde copie complète du rapport.

Le document doit pouvoir se lire seul : question, périmètre, statut, date,
synthèse, méthode, faits et sources, hypothèses, résultats disponibles, limites
et prochaines étapes. Un protocole proposé ou un résultat synthétique garde
ce statut dans le PDF ; la mise en page ne le transforme pas en résultat terrain.
Les références restent consultables depuis le document, avec les dates/versions
et limites de lecture prévues ci-dessous.

Pour travailler dans Codex, ouvrir par défaut le `.tex` dans l'éditeur LaTeX
intégré et garder ce fichier pour les retouches. Privilégier un document autonome,
avec schémas et bibliographie intégrés lorsque possible. Compiler après les
modifications, exporter le PDF correspondant, puis vérifier visuellement les
pages : débordements, lisibilité des figures et tableaux, légendes et références.
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
- **Dates** : début si connu et dernière mise à jour ; distinguer la date de
  classement d'une ancienne note de celle de sa recherche ou de sa validation.
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
