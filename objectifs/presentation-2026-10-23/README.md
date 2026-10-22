# Présentation d'avancement — 2026-10-23

> **Version courante (2026-10-22).** Le deck présenté est un deck « Slides »
> de Claude (9 diapositives, lien privé :
> <https://claude.ai/artifact/2mgiuTXaC6HxhSas8xw39v>). Son code source est dans
> [slides-artifact/](slides-artifact/) : `deck.json` (ordre et sections),
> `slides/*.html` (une diapositive par fichier, 1920 × 1080) et `assets/`
> (logo et captures de topologie S1 et S12 prises sur la plateforme le
> 2026-10-22). Les images y sont référencées par l'identifiant d'actif de l'outil
> (`/_blob/…`) : pour reconstruire le deck ailleurs, remplacer ces références par
> les fichiers de `assets/`.
>
> Les anciens `slides.pptx` et `slides.pdf` (13 diapositives, gabarit
> PowerPoint) ont été retirés. Le reste de cette page décrit cette version
> précédente et n'est conservé que pour l'historique.

**Question.** Comment rendre compte de l'avancement du projet à des partenaires
du programme NATO SPS G6259 et à des collègues, sans surdéclarer ce qui n'est
pas mesuré ?

**Statut.** Diapositives prêtes à relire. Aucun run exécuté pour ce document.

**Dates.** Créé et rédigé le 2026-10-21 (Europe/Brussels, UTC+02:00).
Composition revue le **2026-10-22** (Europe/Brussels, UTC+02:00).
Présentation prévue le **2026-10-23**.

## Nature

Ce n'est pas un argumentaire de vente : c'est un **compte rendu d'avancement**
de 10 à 15 minutes, en anglais, destiné à un public mixte (partenaires
institutionnels et collègues techniques).

## Documents

- [slides-artifact/](slides-artifact/) — source du deck courant (voir la note en
  tête de page).
- [build.py](build.py) et [build_pdf.py](build_pdf.py) — générateurs de
  l'ancienne version PowerPoint (13 diapositives). Les fichiers `slides.pptx` et
  `slides.pdf` qu'ils produisaient ont été retirés ; ils restent dans
  l'historique git.
- [design-notes.md](design-notes.md) — grille, règles de composition et
  journal des relectures. À lire avant de modifier `build.py`.
- [archive-beamer/](archive-beamer/) — première version beamer
  ([slides.tex](archive-beamer/slides.tex), [slides.pdf](archive-beamer/slides.pdf)),
  conservée comme archive. Le contenu factuel y est identique ; la version PPTX
  la remplace et ajoute les schémas.

## Grammaire visuelle

Reprise du modèle de comité de thèse
(`~/Documents/thèse/output/presentation/Comite_these_medical.pdf`) : fond blanc,
onglets de section en haut, logo SMart ILIA / UMONS, filet cramoisi sous le
titre, encadrés rose (`FCF0F4`) et bleu (`EFF6FC`), boîtes grises à filet fin.
Palette : cramoisi `B60036`, bleu `1D5C96`, encre `20252D`, gris `5C626C`.

## Structure

Onglets : Objective · Instrument · Control · Hypotheses · Outlook.

| # | Diapositive | Onglet | Rôle | Visuel |
| --- | --- | --- | --- | --- |
| 1 | Titre | — | Statut « work in progress » affiché d'emblée | — |
| 2 | The objective | Objective | Une phrase, trois engagements | Trois lignes |
| 3 | The platform in brief | Objective | Ce que fait la plateforme | Capture du dashboard |
| 4 | The instrument | Instrument | Laboratoire, plateforme, benchmark | Trois bandes |
| 5 | Script, LLM agent and harness | Instrument | Ce qui varie entre les approches, ce qui reste fixe | Schéma harness |
| 6 | How a run is judged against the goal | Instrument | But → laboratoire → plateforme → preuves → benchmark | Chaîne + boucle de retour |
| 7 | What constitutes a finding | Instrument | Preuve recalculée ; saine contre vulnérable | Deux panneaux opposés |
| 8 | A control task before testing the model | Control | Porte V0 à deux bras | Matrice 2 × 2 |
| 9 | Current status | Control | Les deux bras réussissent partout | Barres saturées, 6/6 |
| 10 | The objective restated as hypotheses | Hypotheses | Registre H1–H6 ; H6 est un risque | Six cartes, H6 détachée |
| 11 | What we cannot claim | Outlook | Trois limites explicites | Trois lignes |
| 12 | Next steps | Outlook | Quatre étapes ; demande de soutien | Liste numérotée + encadré |
| R | Reserve — declared coverage gaps | Outlook | Trous de couverture assumés | Liste |

Une seule idée par diapositive, une phrase de titre par idée. Les chiffres du
pilote (coûts, variabilité, cas discriminant) ne figurent plus dans le corps :
ils ne répondent pas à la question posée. Ils sont archivés dans les versions
antérieures de `build.py` (commit `9951ded`) et dans `docs/benchmark/`.

## Vérification

Source unique du plan de départ : `/tmp/lance-vendredi-plan.md` (hors dépôt).
Trois relectures indépendantes ont été menées avant rédaction, sur trois angles
distincts — adéquation au public, vérification factuelle contre les sources
primaires, faisabilité orale. Les corrections retenues sont consignées dans la
section suivante.

**Rendu vérifié** : `officecli validate` sans erreur, `officecli view issues` à
zéro problème (ni débordement de texte, ni chevauchement), inspection visuelle
des 13 diapositives. Le dimensionnement du texte est calculé à partir des
métriques Arial avec une marge de sécurité, parce que le moteur de rendu
substitue une police de repli plus large et ignore le rétrécissement
automatique stocké dans le fichier.

La composition a fait l'objet de cinq relectures adversariales successives
(grille tenue, lisibilité, fidélité au contenu, sobriété, vocabulaire visuel),
notées selon une grille pondérée : 6,5 → 7,5 → 8,5 → 8,8 → **9,0**. Le détail et
les réserves sont dans [design-notes.md](design-notes.md).

**Limites.** Aucune relecture indépendante du rendu final n'a été menée depuis
le portage PPTX. Le minutage n'est pas vérifié en répétition réelle : le budget
de conception est de 11 min 30, avec un plan de repli à 10 minutes. Le rendu de
contrôle est celui d'`officecli` (moteur HTML), pas celui de PowerPoint : une
ouverture dans PowerPoint avant la séance reste souhaitable.

## Corrections factuelles appliquées

Ces corrections viennent de la relecture factuelle et remplacent des
formulations du premier plan qui n'étaient pas soutenues par les sources.

1. **H6 était inversée.** Le registre prédit une conformité **supérieure à
   zéro** côté modèle ; H6 mesure donc une vulnérabilité, pas une résistance.
2. **« 12/12 » était un agrégat.** SSH et MQTT sont deux configurations
   distinctes, jamais regroupées. La diapositive 5 énonce désormais la
   saturation par famille.
3. **« On rejoue les actions » était faux.** L'évaluateur relit le journal et
   recalcule la preuve ; il ne ré-exécute pas les sondes.
4. **F0/F1 remplacés** par « configuration où la faiblesse testée est absente
   ou présente ». F1 entre en collision avec le F1-score.
5. **Le benchmark n'était pas « trop facile ».** Le pilote qualifiait
   l'instrument ; il n'était pas calibré pour départager les bras.
6. **V0 est une porte à deux bras.** Le défaut d'instrument se conclut quand le
   script réussit et le modèle échoue, pas dès qu'un bras échoue.
7. **Le cas API relève de la couverture**, pas de V0 : le registre le range
   comme limite de couverture déclarée.
8. **V0 porte sur MQTT en l'état** ; SSH exige d'abord la randomisation du
   dictionnaire.

## Suite

- Parcourir le deck courant en mode présentation pour confirmer le rendu réel.
- Relire le deck du point de vue d'un lecteur qui n'a pas suivi les échanges.
- Répéter au moins une fois à voix haute pour vérifier le budget de temps.
- Si le temps manque en séance : sauter la diapositive 3 (son contenu est
  énonçable en une phrase), puis la diapositive 7.
