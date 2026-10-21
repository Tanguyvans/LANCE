# Présentation d'avancement — 2026-10-23

**Question.** Comment rendre compte de l'avancement du projet à des partenaires
du programme NATO SPS G6259 et à des collègues, sans surdéclarer ce qui n'est
pas mesuré ?

**Statut.** Diapositives prêtes à relire. Aucun run exécuté pour ce document.

**Dates.** Créé et rédigé le 2026-10-21 (Europe/Brussels, UTC+02:00).
Présentation prévue le **2026-10-23**.

## Nature

Ce n'est pas un argumentaire de vente : c'est un **compte rendu d'avancement**
de 10 à 15 minutes, en anglais, destiné à un public mixte (partenaires
institutionnels et collègues techniques).

## Documents

- [slides.pptx](slides.pptx) — rendu principal, 13 diapositives : 10 de corps et
  3 de réserve. Ouvre directement dans PowerPoint ou Keynote.
- [build.py](build.py) — générateur du `.pptx` (`python3 build.py`, via
  `officecli`). Source unique : modifier ici, pas dans le fichier PowerPoint.
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

| # | Diapositive | Rôle | Visuel |
| --- | --- | --- | --- |
| 1 | Titre | Statut « work in progress » affiché d'emblée | — |
| 2 | The objective, and what it implies | Objectif, trois engagements, priorités ; entraînement hors priorité | Bus de distribution vers trois branches |
| 3 | How we answer it | Laboratoire, plateforme, benchmark ; les six phases du pipeline | Deux schémas de flux |
| 4 | What counts as ``found'' | Preuve recalculée ; saine contre vulnérable | Deux colonnes comparées |
| 5 | What the first campaign showed | Les deux bras réussissent partout | Barres saturées, 6/6 |
| 6 | So the objective is restated as hypotheses | Registre H1–H6 ; H6 est un risque, pas un gain | Six cartes, H6 détachée |
| 7 | Before testing the model, test the test | Porte V0 à deux bras | Quatre issues de la porte |
| 8 | What we can measure today | Trois mesures descriptives | Tuiles + jauge de dispersion |
| 9 | What we cannot claim | Quatre limites explicites | Quatre cartes |
| 10 | Next steps, and what would help | Ordre par conditions ; deux demandes | Liste numérotée + encadrés |
| 11 | Reserve — model panel | Coûts et succès par approche | Tableau |
| 12 | Reserve — variability | Coefficient de variation | Tableau |
| 13 | Reserve — declared coverage gaps | Trous de couverture assumés | Liste |

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

- Ouvrir `slides.pptx` dans PowerPoint pour confirmer le rendu réel.
- Relire le deck du point de vue d'un lecteur qui n'a pas suivi les échanges.
- Répéter au moins une fois à voix haute pour vérifier le budget de temps.
- Si le temps manque en séance : supprimer la diapositive 3 (fondue dans la 4),
  puis réduire la diapositive 8 à un seul résultat.
