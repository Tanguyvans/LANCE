# Méthodologie d'évaluation pour le papier : registre de décisions

**Cycle de vie : Ouvert** — note ouverte le **2026-11-09 (Europe/Brussels,
UTC+01:00)**. Statut : **registre de décisions, aucune implémentation ; squelette
de la section « évaluation » du papier.**

> Cette note synthétise une revue à quatre angles (métrique, inférence
> statistique, validité de construction, standards externes) menée le
> 2026-11-09. Elle ne décide rien seule : chaque décision ci-dessous attend une
> validation avant implémentation. Les références `fichier:ligne` datent du
> 2026-11-09 (tip `dev/1` à ce jour) — vérifier qu'elles n'ont pas bougé.

## Thèse centrale

**La contribution publiable n'est pas « l'agent LLM fait mieux ».** Aucun
avantage général du LLM n'est démontré (`objectifs/ETAT-COURANT.md`, « Limites à
ne pas oublier »). La contribution défendable est **méthodologique** :

1. le **protocole de comparaison à observations identiques** (harnais) qui
   empêche la plomberie de favoriser une approche ;
2. le **test de clôture exécutable et hashé** (D1+), et la démonstration qu'il
   est nécessaire — le rejet de l'épreuve pilote `s_registres_constructeur`
   (six relectures de conception validaient un mécanisme qu'un run d'une heure a
   réfuté) est un *résultat* ;
3. une **étude de cas comparative honnête**, résultat négatif inclus, bien
   cadrée.

Pour ce profil (peu d'épreuves, forte variance de génération, petit corpus), le
premier risque de rejet n'est pas la métrique mais **N petit + variance non
quantifiée + survente d'une supériorité générale**. Le cadrage prime.

## Registre de décisions

Les décisions sont groupées par pilier. Chacune : l'état actuel (avec code), la
recommandation, et ce qu'elle exige encore.

### A. Métrique

- **A1 — Headline gradué, pas binaire.** Le code calcule un crédit continu
  (`_strict_v3_match`, `evaluator.py:709,746-750` : `type_credit` 1.0/0.5,
  structure `0.75+0.25·ratio`) puis le **jette** : `scenario_score_pct` lit le
  F1 **binaire** du funnel (`evaluator.py:2883` ; `funnel.py:66-86` où
  `tp = len(valid)` en entier). Les `credited_f1` / `severity_adjusted_f1` /
  `quality_adjusted_f1` (`evaluator.py:2678-2712`) ne nourrissent que des champs
  legacy jamais exposés.
  → **Reco :** reconnecter le crédit gradué au headline (faire remonter
  `match_credit` dans `funnel.py:stage_metrics`, ou faire lire un F1 crédité à
  `evaluator.py:2883`). *Correctif le plus rentable : il clôt le next-step #3
  d'ETAT-COURANT.*

- **A2 — P/R/F1 par étage, headline = détection (`candidates`).** Le headline ne
  vit qu'à l'étage `confirmed`, dont l'admission exige une sonde validée
  (`is_verified_report_finding`, `report_evidence.py:16-21` : status CONFIRMED +
  evidence_level≥2 ; `_derive_evidence_level`, `evaluator.py:1544-1556`). Une
  approche qui interprète sans sonder y est **0 par construction** → c'est le
  « detection-only tier » symétrique signalé : un constat de détection correct
  mais non sondé n'est ni TP ni FP, il disparaît.
  → **Reco :** headline = étage **détection**, seul atteignable par les trois
  approches ; `confirmed` = secondaire conditionnel à la capacité de sonder.
  Découpler la détection du sondage est le second correctif prioritaire.

- **A3 — NOISE_TYPES et seuils pré-enregistrés.** `NOISE_TYPES`
  (`vuln_taxonomy.py:31-121`) est une denylist manuscrite de ~122 chaînes dont
  les commentaires avouent le sur-apprentissage (« Over-eager LLM reporting »).
  Appliquée symétriquement (`funnel.py`), mais réglée sur un modèle précis.
  → **Reco :** figer/versionner **avant** de voir les sorties de test ; fonder
  sur une règle (« hors `CANONICAL_TYPES` ∪ alias → écarté ») plutôt qu'une
  liste d'hallucinations ; publier une **analyse de sensibilité**.

### B. Inférence statistique

- **B1 — Unité d'observation = l'épreuve indépendante.** `family_id` usurpe
  l'unité à deux endroits opposés, tous deux faux : `v2_campaign.py:71`
  (`family_id = scenario_id` → chaque scénario = une obs → **pseudo-réplication**,
  p anti-conservatrice) et `policy_pair_runner.py:225`
  (`"family_id": "ui-public-scenario"` en dur → tout s'effondre en une famille →
  refus `MIN_FAMILIES`). L'indépendance se garantit par le **test de clôture**,
  pas par un champ codé en dur.

- **B2 — Test magnitude-sensible, pas le signe.** `sign_test_greater`
  (`inference.py:48-72`) ne dépend que du **nombre** de signes positifs, jamais
  de la magnitude → quatre panels d'effets radicalement différents donnent la
  **même p-value** (c'est la plainte du relecteur : une limite de design, pas un
  bug). En régime réel n=3-7, `paired_difference_inference` est **toujours** sur
  le signe (`inference.py:133-136`) ; le bootstrap magnitude-sensible ne
  s'active qu'à n≥8.
  → **Reco :** **bootstrap apparié hiérarchique** (rééchantillonner épreuves
  PUIS répétitions) dès n=3 comme test primaire, avec **propagation de la
  variance de génération** (aujourd'hui moyennée puis jetée, `inference.py:219-221`) ;
  test du signe relégué en contrôle de robustesse.

- **B3 — Pouvoir dire « non » (équivalence).** `decide()`
  (`inference.py:153-199`) n'implémente qu'un test de supériorité ; « échec à
  rejeter » n'est pas « pas d'avantage ». Aucun bras d'équivalence.
  → **Reco :** ajouter **TOST / non-infériorité**, figer **δ = MCID** (plus
  petite différence qui compte ; aujourd'hui `delta_threshold` par défaut
  `None`/0 — jamais figé) et **définir la puissance** au δ pré-enregistré. Un
  design sous-puissancé → « descriptif seul, aucune conclusion » = un « non »
  défendable.

- **B4 — Claim par épreuve, pas global.** Avec ≤5 épreuves défendables (Blocage
  0), **pas de p globale** : estimation par épreuve, **panel rapporté**. Claim
  populationnel seulement à **≥8 épreuves indépendantes**. `MIN_DECIDABLE_FAMILIES=5`
  (`inference.py:34`) est un plancher d'existence, pas un design (5 épreuves
  concordantes → p=0,03125 sans aucune marge).

- **B5 — Garder `mt_admissible=false`.** `campaign_admission`
  (`v2_campaign.py:161-196`) refuse honnêtement ; il **reflète fidèlement**
  l'absence d'épreuves indépendantes. À présenter comme un **refus
  méthodologique volontaire**, pas un blocage technique à forcer.

### C. Validité de construction

- **C1 — « Règle d'une ligne » → « test de clôture D1+ exécutable et hashé ».**
  « Une ligne » n'a pas de définition formelle et a déjà piégé le projet (le
  rejet pilote : une règle générique en une phrase est un script 3/3). Le
  prédicat est la **séparabilité par la clôture déductive des entrées
  publiques**, démontrée par du code exécutable+hashé, pas une heuristique de
  longueur.

- **C2 — Neutraliser les 4 mécanismes qui avantagent `rules`.** (1) `confirmed`
  exige une provenance de sonde que seul `rules` produit (phase 4) ; (2)
  `supplemental.py` réécrit les observations figées en y injectant des sondes ;
  (3) `add_scanner_candidates` ajoute les constats des règles aux constats du
  modèle (gonfle le score modèle même quand il n'a rien trouvé) ; (4) le score
  n'existe qu'en mode `lance`.
  → **Reco :** comparer à l'étage **`candidates`** ; **snapshot scanner
  canonique figé + hashé** commun aux trois approches (vérifié avant/après chaque
  run), `supplemental` désactivé sur le chemin partagé ; `add_scanner_candidates`
  désactivé pour `llm_on_evidence` ; **ouvrir le calcul de score aux trois
  `runner_kind`**.

- **C3 — Budget de sondes égal (ou nul).** La vérification par sonde est une
  **expérience séparée** : mêmes outils des deux côtés + attestation d'égalité de
  budget, sinon on mesure « qui peut sonder », pas l'interprétation. Pour
  l'épreuve pilote : **zéro sonde partout** (journal figé, aucun outil).

- **C4 — Corpus : mesurer et déclarer le biais, ajouter S1h.** Le corpus est
  construit autour de ce que les règles trouvent (**243/288 = 84,4 %** à
  signature en lecture interprétative ; **282/288** en index binaire dérivé — ne
  jamais citer l'un pour l'autre ; **24/29** topologies mono-sous-réseau). Un
  écart nul y est attendu par construction. Le contrôle sain **S1h** existe mais
  n'est **pas au catalogue** → l'ajouter comme témoin négatif de spécificité.
  Toute épreuve future doit **démontrer avant construction** qu'aucune règle
  générique ne la franchit ; ne jamais prolonger le corpus existant.

### D. Standards externes (reporting)

- **D1 — Répétitions multiples + incertitude.** Plusieurs runs indépendants par
  épreuve même à T=0 (la variance persiste ; cf. *On Randomness in Agentic
  Evals*) ; rapporter moyenne + IC/écart-type, et **pass@k vs pass^k** (au mieux
  vs fiable). Dimensionner le nombre de runs par **analyse de puissance**.
- **D2 — Coût à côté de l'accuracy.** Courbe de **Pareto accuracy/coût**
  (tokens, \$, temps par épreuve). Transforme « l'agent n'égale pas les règles »
  en contribution nette (*Holistic Agent Leaderboard*).
- **D3 — Contrat de métrique explicite.** P, R **et** F1 ensemble (jamais F1
  seule) ; déclarer **micro vs macro** ; **règle de matching prédiction↔vérité
  terrain** spécifiée noir sur blanc (le point le plus scruté) ; justifier F1 ou
  passer à **F-beta** (coût FP/FN asymétrique en sécurité) ; crédit gradué
  légitime s'il est **publié et pré-enregistré** (cf. *Partial-Credit CTF*,
  MITRE ATT&CK Evaluations).
- **D4 — Pré-enregistrement + artefact.** Geler métrique, matching, nb de
  répétitions, seuils, δ et critère de clôture **avant les runs finaux**
  (template ICML 2026) ; correction des comparaisons multiples (Holm/BH) ;
  rapporter les effets négatifs ; **artefact reproductible** (politique
  open-science USENIX/AsiaCCS) — les replays à partir des bytes bruts sont un
  atout.
- **D5 — Prudence des claims.** Validité interne seulement ; un null dû au petit
  N se formule « **pas d'effet détectable à cette taille d'échantillon** »
  (+ tailles d'effet et IC), **jamais** « ça ne marche pas ».

## Chemin critique

**Le livrable n°1 n'est pas un score — c'est ≥1 épreuve indépendante qui survit
au test de clôture exécutable** (`objectifs/ETAT-COURANT.md`, « Ce qui compte
comme résultat » + Blocage 0 ; prochaine étape #1). Tant qu'elle n'existe pas,
aucune statistique n'est présentable comme conclusion. Les correctifs de code
(A1 reconnecter le crédit, A2 découpler la détection du sondage, C2 ouvrir le
score aux trois modes) sont utiles et rentables, **mais ils servent cette
épreuve-là**, pas l'inverse.

Ordre suggéré : (1) construire et hasher une épreuve indépendante ;
(2) A1 + A2 (métrique détection graduée, découplée du sondage) ; (3) C2 + C3
(observations figées, score ouvert aux trois approches, budgets égaux) ;
(4) B1–B4 (unité, test magnitude-sensible, équivalence, panel par épreuve) ;
(5) pré-enregistrer (D4) avant les runs finaux.

## Sources externes

- Cybench (`arxiv.org/abs/2408.08926`) ; AutoPenBench (`arxiv.org/pdf/2410.03225`) ;
  HackSynth (`arxiv.org/abs/2412.01778`).
- *On Randomness in Agentic Evals* (`arxiv.org/pdf/2602.07150`).
- *Holistic Agent Leaderboard* / Pareto coût-accuracy (`arxiv.org/pdf/2512.02230`).
- *Partial-Credit Evaluation of LLM Agents in CTF* (`arxiv.org/pdf/2604.19354`) ;
  MITRE ATT&CK Evaluations (`mitre-engenuity.org/attackevaluations/`).
- Pré-enregistrement pour expériences d'agents IA, ICML 2026 (`arxiv.org/pdf/2606.11217`).
- *SoK: Unified Replicability for Computer Security*, USENIX 2025 ; guidelines
  artefact USENIX ; *Benchmarking Crimes* (van der Kouwe et al.).
- *Position: Embracing Negative Results in ML* (`arxiv.org/html/2406.03980v1`).

## Voir aussi

- `objectifs/ETAT-COURANT.md` — Blocages 0-4, « Comparer les trois approches ».
- `research/2026-10-30-famille-pilote-registres-constructeur/` — le rejet pilote
  (preuve que le test de clôture exécutable est nécessaire).
- `research/2026-10-21-hypotheses-benchmark/` — registre d'hypothèses (V0, H1-H6).
