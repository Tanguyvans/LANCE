# Plan de conception — famille pilote `s_registres_constructeur` (révision 2)

**Cycle de vie : Actif — plan de conception soumis à relecture** — ouvert le
**2026-10-30**, dernière révision **2026-10-30 14:35 (Europe/Brussels, UTC+01:00)**.

> **Révision 2.** La révision 1 a été rejetée par deux relectures
> indépendantes : neuf risques méthodologiques, sept techniques. Les
> décisions qui suivent ont été prises par l'auteur du cahier des charges le
> 2026-10-30. Ce document remplace la révision 1 ; les motifs de rejet sont
> consignés dans `relectures.md`.

---

## 0. Décisions verrouillées

| # | Décision | Motif | Levée par |
| --- | --- | --- | --- |
| D1 | **Interprétation seule, journal figé, aucun outil.** | Dès que le bras émet des sondes, la comparaison mesure « qui peut vérifier ». | R8 révision 1 |
| D2 | **Vocabulaire = noms, jamais nature** : le libellé nomme une unité de mesure, pas un rôle. La règle de sécurité dépend de l'unité. | Une convention sur les rôles serait juste par hasard ; une échelle de valeurs (classe a) rendrait toute règle générique juste. | — |
| D3 | **Le test de clôture vit avec la famille.** `src/benchmark/` ne reçoit que des primitives génériques. | — | — |
| D4 | **Inférence inchangée** : la famille pilote est descriptive. Vingt registres sont vingt observations d'**une** famille. Aucune décision statistique ne peut en sortir, et la famille ne prétendra rien de tel. | l'inférence exige au moins trois familles pour émettre un chiffre et cinq pour décider ; la famille pilote ne lève rien. | arbitrage du 2026-10-30 |
| D5 | **Rattachement à H4, avec un contraste réécrit.** Le registre ambigu est un problème de **sémantique**, pas d'extraction : un extracteur H3 lirait parfaitement le libellé et conclurait faux. Le contraste de H4 est **l'absence de table de correspondance côté LLM**, pas un catalogue identique aux trois bras. | révision 1 : catalogue identique ⇒ mesurait H3. | arbitrage du 2026-10-30 |
| D6 | **Contrôle positif partiel assumé.** Il couvre `intentional_flaws` 0 et 1 ; il ne couvre pas les collections. Un bras écrit pour le contrôle ne prouve rien sur D1+. | `run_rules` ne lit jamais une collection. | arbitrage du 2026-10-30 |

### D5 appliquée : ce que chaque bras reçoit

| Bras | Documentation publique | Table de correspondance (libellé → unité) | Observations |
| --- | --- | --- | --- |
| **D1+** | oui | **oui** — la table lui est fournie, c'est sa condition de compétence | oui |
| **Convention** | oui | non — il **devine** la table depuis le texte | oui |
| **LLM** | oui | **non** — il lit le texte, exactement comme pour H4 | oui |
| **Témoin de borne** (`bound`) | oui | oui | oui |

Le **témoin de borne** est un bras à règles qui possède la table : il mesure
si D1+ échoue *faute de table* ou *faute de règle*. S'il réussit et que D1+
échoue, la cause est la table, donc le contraste de H4 est bien celui qui est
mesuré. S'il échoue aussi, la famille est mal conçue et doit être rejetée
avant toute mesure.

**Ce que D5 exclut.** Si le LLM réussit à reconstruire la table depuis le texte
public, la famille ne sépare plus rien : c'est un résultat, il rejette la
famille au même titre que l'absorption par la convention.

---

## 1. Modèle d'adressage — établi par trames brutes

**Vérifié le 2026-10-30 sur le dépôt**, pymodbus 3.15.0, boucle locale, par
trames MBAP brutes (le parcours exact du chemin de service est décrit ci-dessous).

| Fait constaté | Preuve |
| --- | --- |
| `ModbusServerContext` expose `simdevices` et `async_getValues` ; `async_getValues` renvoie `ExcCodes.DEVICE_BUSY` (6) sur le chemin 3.x déprécié. | `datastore/context.py`, `context.async_getValues(...)` → `6` |
| Un serveur `ModbusTcpServer` construit avec `ModbusServerContext(devices={u: ModbusDeviceContext(...)})` **sert bien** ses registres. | `fc3 addr 10 unit 47` → `0x2332` = 9010, la valeur placée au registre 10 ; `fc6` accepté |
| L'adresse n'est **pas** décalée par le bloc : un bloc déclaré à `lo` expose `lo` sur le fil, pas `lo-1`. | `fc3 addr 100` → **exception 02** ; `fc3 addr 10` → 9010. La révision 1 concluait `lo+1`, à tort. |
| `ModbusSequentialDataBlock(0, ...)` lève `TypeError` (`address-1 = -1`). | `sequential.py` l.17-18 |

**Le piège de la révision 1.** La sonde de révision 1 utilisait
`ModbusSequentialDataBlock(lo + 1, …)` et lisait `[9912]` au registre 100.
Ce chiffre venait de la **table de test** (valeurs sentinelles construites
pour cet offset), pas du fil : le serveur répondait correctement à l'adresse
100 d'une table décalée d'un cran, ce qui **donne l'impression** que
l'écriture isole bien `n` alors que le registre réellement écrit n'était pas
celui de la documentation. La vérification du relecteur technique a débusqué
ce point, bien que sa description du mécanisme fût inexacte (elle invoquait
`ModbusDeviceContext.async_getValues`, méthode absente dans la version
installée) : le résultat mesuré, lui, est reproductible par trames brutes.

**Règle retenue.** Le simulateur déclare `ModbusSequentialDataBlock(lo, …)` et
expose l'adresse `lo` telle que la documentation de la famille la nomme.
**Le test d'offset ne s'exécute pas via l'objet client** : il envoie des
trames MBAP brutes et vérifie (a) que `n` change, (b) que `n-1`, `n+1` et le
registre d'entrée de même adresse sont intacts, (c) qu'une adresse hors
fenêtre renvoie **exception 02**. Un test qui passerait sur une table décalée
doit échouer.

**Portabilité.** `pymodbus==3.15.0` est épinglé dans un `requirements.txt`
de la famille, la version est lue et imprimée dans le manifeste, et un test
échoue hors intervalle. La 3.15 est retenue parce qu'elle est celle du dépôt,
et parce que sa conversion `SimCore` est celle qui sert ; ce fait est testé,
pas supposé.

---

## 2. Le journal : une capture enregistrée

Le journal **n'est pas** « ce que le scanner aurait produit » : ni le scanner
(`nmap -sV -p 502`, `modbus-discover`) ni `modbus_write` ne relisent un
registre. C'est une **capture enregistrée**, produite par le générateur de la
famille, avec sa provenance et son hash.

```json
{
  "schema_version": 1,
  "family": "s_registres_constructeur",
  "provenance": "recorded_capture",
  "producer": {"sut": "fixture/sut.py", "sut_sha256": "…", "generator_sha256": "…",
               "pymodbus": "3.15.0", "captured_at": "…", "seed_sha256": "…"},
  "journal_sha256": "…",
  "target": {"asset_id": "…", "ip": "…", "port": 502, "unit_id": 47},
  "documentation": "…texte public, ou null…",
  "observations": [
    {"observation_ref": "obs-0001", "kind": "holding_read", "address": 100, "value": 4120, "raw_type": "uint16"},
    {"observation_ref": "obs-0002", "kind": "holding_write", "address": 100, "written": 4120, "read_back": 4120, "raw_type": "uint16"},
    {"observation_ref": "obs-0003", "kind": "input_read", "address": 100, "value": 24, "raw_type": "uint16"}
  ]
}
```

**Rejeu déterministe.** `replay(journal, sut) -> dict[ref, état observé]` :
le générateur recrée la SUT à l'état initial, rejoue les `fc6` dans l'ordre
d'`observation_ref`, lit chaque registre nommé **et ses voisins immédiats et
son registre d'entrée**, et produit un état comparé **à l'identique** à
celui du journal. Le rejeu est testé sur un cas vert et sur un cas falsifié
(`written ≠ read_back`). Sans rejeu vert, le journal n'est qu'un
enregistrement, pas une preuve.

**Ce que le journal ne contient jamais** : l'oracle, la classe (a/b/c), le
nombre attendu de registres ambigus, la consigne de sécurité, la table de
correspondance.

**Types.** Le fait vérifiable est seulement « le registre accepte un entier
0–65535 et le rend tel quel ». Aucun libellé de type (`float32_high_word`,
etc.) n'est imposé : il était une pétition de principe en révision 1.

---

## 3. Les huit dossiers, et le décompte

Huit dossiers, `{référence, variante} × {sans, avec défaut}`. Chaque dossier
contient **vingt registres ambigus** : un registre est ambigu lorsque son
libellé nomme une unité de mesure et qu'une situation — un second libellé, une
valeur, un comportement — peut le contredire. C'est le dénominateur du
décompte : **vingt par dossier**, pas huit.

| Dossier | Défaut ? | Ce qui est ambigu |
| --- | --- | --- |
| `t01` (réf.) | non | aucun registre n'est ambigu : libellés, unités et valeurs concordent |
| `t02` (var.) | non | mêmes unités, autres mots, ordre de configuration différent |
| `t03` (réf.) | **oui** | vingt registres ambigus, dont **un** est réellement projeté |
| `t04` (var.) | **oui** | même défaut, **place** de l'ambiguïté tirée par le générateur |
| `t05` (réf.) | non | les vingt registres sont ambigus, aucune projection ; documentation complète |
| `t06` (var.) | non | ambigus, aucune projection, **documentation partielle** |
| `t07` (réf.) | **oui** | **documentation absente** : la table n'est pas fournie, seul le texte public reste |
| `t08` (var.) | **oui** | défaut présent, **témoin de borne** nécessaire pour d'autres raisons (voir § 6) |

**F0 (témoin sain)** = `t01`, `t02`, `t05`, `t06`. `t01`/`t02` n'ont pas
d'ambiguïté par construction ; `t05`/`t06` en ont mais leur oracle dit
`none` : c'est le cas qui rejette un bras qui dit `projection` dès qu'un
libellé est ambigu. Le taux de base est **4 dossiers sur 8** ; il est publié,
et P1 ne peut donc se lire qu'à la marge au-dessus.

**Pool de registres.** Le générateur tire adresses, unités, ordre de
configuration et valeurs d'une graine non publiée. Le pool de libellés est
**commun à `t01`–`t08`** : la variante recombine, elle n'apprend pas d'un
dossier à l'autre. Il contient **vingt fois plus de libellés** que de
registres nécessaires, si bien que D1+ ne peut pas apprendre par cœur.

---

## 4. L'oracle privé

Table `(appareil, registre, classe, propriété attendue, preuve admissible)`.

**Classes.** (a) décodage et (b) comportement observable sont des
**témoins** : une erreur sur elles invalide la famille, elle ne se compare
pas. Seule la classe (c) est mesurée. La révision 1 comptait l'échelle dans
l'oracle de mesure ; elle est retirée. La règle générique sur le comportement
observable est une **règle de témoin**, pas de classification.

**Preuve liée.** Une décision n'est attestée que si son `observation_ref`
apparaît dans l'oracle **avec ses deux voisins immédiats et son registre
d'entrée**, de sorte qu'un identifiant devinable ne suffit pas : le rejeu doit
reproduire l'état cité.

**Préenregistrement.** Avant tout run, `closure/pre_register.json` contient la
version de D1+, de la convention et du témoin de borne, leurs `sha256`, le
`journal_sha256` des huit dossiers, le `sha256` de l'oracle, la graine
hashée, les seuils P1-P4, le taux de base et la liste des propriétés (c).
Le rapport porte le `sha256` de ce fichier. **L'étape 5 n'exécute que les
hashs du manifeste** ; toute réécriture d'un bras exige un nouveau
préenregistrement complet, et la mesure précédente est jetée.

---

## 5. Le test de clôture

```
verdict ∈ {closed, absorbed, found_by_design, inconclusive, qualified}
```

**Même grille pour les quatre bras** (R2) :

| Verdict | Condition | Conséquence |
| --- | --- | --- |
| `closed` | D1+ ou le témoin de borne conclut `projection` sur un dossier dont l'oracle dit `none` (ou l'inverse) | rejet consigné |
| `found_by_design` | D1+ conclut correctement `projection` (attestée) sur au moins un dossier où l'oracle dit `projection` | rejet consigné : la famille ne mesure rien |
| `absorbed` | la convention devine **au moins aussi bien que D1+** sur la classe (c) — même nombre de propriétés attestées — donc impossible de parler d'un gain du LLM | rejet consigné |
| `inconclusive` | tout bras rend `undetermined` sur une propriété (c), ou le préenregistrement est incomplet | rejet consigné : pas de mesure |
| `qualified` | la convention devine **moins bien** que D1+ sur (c) ; tous les bras sont exacts sur les témoins (a)/(b) | passage à l'étape 6, puis point d'arrêt |

**Le mode « abstention » est déclaré, pas implicite (R1).** Un bras a le droit
de répondre `undetermined`. Un `undetermined` sur une propriété (c) rend le
test `inconclusive`, **ce qui rejette la famille** : il ne peut jamais servir
à la qualifier. La révision 1 laissait un D1+ prudent obtenir `inconclusive`
sans conséquence ; ce trou est fermé.

**Un `no_projection` sans preuve de la non-projection** est `unsupported_gap`,
compté à part des faux négatifs, et ne vaut jamais un succès.

**Contrôle positif (D6).** Deux sous-contrôles, tous deux **sur le comportement
de D1+**, pas sur un bras écrit exprès :

- **PC-a** : sur la politique protégée (`intentional_flaws = 0`), `run_rules`
  réussit et ne cite aucune divulgation ; sur la vulnérable
  (`intentional_flaws = 1`), il échoue sans en citer. Si l'un des deux n'est
  plus vrai, le contrôle est cassé.
- **PC-b (non couvert)** : la fuite par col­lection n'est **pas** détectée par
  `run_rules`, qui ne lit que `/v1/objects/{id}`. Le contrôle est
  **partiel** et l'est déclaré : il ne mesure pas une famille dont la règle
  de sécurité porte sur un canal que les règles ne peuvent pas inspecter.
  C'est une raison de plus de mesurer l'interprétation.

Le contrôle est déclaré valide quand PC-a passe. La révision 1 annonçait un
contrôle complet ; il ne l'est pas, et le renoncement est écrit ici.

---

## 6. Les quatre bras

### D1+ — compétent, mais sans table

`run_d1plus(journal_for_d1plus)` reçoit **le journal, la documentation et la
table de correspondance**. Ses règles sont versionnées, une par ligne, chacune
avec sa `derived_from`. Sa limite est **déclarée** : sans la table, il ne
peut pas rattacher un libellé à une unité, donc il doit s'abstenir
(`undetermined`) sur une désignation qu'il ne résout pas. **C'est cette
limite qui fait échouer la clôture si elle est fausse.**

Le **témoin de borne** (`bound`) reçoit la même table et applique la règle
complète ; il ne sert qu'à séparer l'absence de table de l'absence de règle,
et il n'entre dans aucun prédicat.

### Convention élargie — obligatoire dès la conception

`run_convention(journal)` devine, **sans aucune clé du corpus**, la classe
d'unité depuis le texte. Il n'applique pas la règle de sécurité fine : il
conclut `projection` sur le premier registre qu'il croit porteur d'une
quantité facturée. Il ne contient **aucun** libellé, adresse ou identifiant de
la famille, et un **test exécuté** vérifie qu'aucune clé du corpus n'y figure
(contre `t01`–`t08`).

**Il est écrit et hashé avant `t03`–`t08`.** La révision 1 pouvait le
réécrire après coup ; cette révision l'écrit en même temps que D1+, et l'étape
5 refuse tout manifeste dont les hashs ne correspondent pas.

### LLM — sans table, avec le texte

Le prompt contient le journal, la documentation ; **il ne contient pas la
table de correspondance** (D5). Le modèle rend
`{decision, register, refs, raw_type}`. Une `projection` sans
`observation_ref` admissible est `unsupported_finding`.

### Budget

P4 est reformulé : le budget n'est pas un nombre de tentatives (le LLM n'a
pas d'outils), c'est la **longueur du journal**. Trois passages : 40, 120,
360 observations. P4 exige que l'écart ne dépende pas du journal. La
révision 1 exigeait « 1, 3 puis 10 tentatives » sans mécanisme.

---

## 7. Prédicats

| # | Prédicat | Mesure |
| --- | --- | --- |
| P1 | A1 > D1+ sur la **justesse attestée**, classe (c), **par registre** | propriétés (c) attestées / 20 par dossier ; gain contre D1+ **et** contre la convention ; **descriptif**, aucune p-value |
| P2 | Égalité des bras sur les témoins (a) et (b) | **succès commun** exigé, pas une simple égalité ; tout écart rejette la famille |
| P3 | Faux positifs « sémantique inventée » ≤ τ | τ = 1 / 4 dossiers F0 ; **étalonné sur `t01`–`t08`, pas sur des fixtures d'entraînement séparées** |
| P4 | L'écart ne dépend pas du budget | passages à journal de 40, 120 et 360 observations |

---

## 8. Ordre des livrables

| Étape | Livrable | Artefact vérifiable |
| --- | --- | --- |
| 0 | **Ce plan, deux relectures** | `relectures.md` |
| 1 | D1+, convention, témoin de borne | `closure/manifest.json` |
| 2 | Test de clôture + préenregistrement + contrôle PC-a | `pre_register.json`, `tests/test_closure.py` |
| 3 | Simulateur et modèle d'adressage par trames brutes | `tests/test_registre_simulator.py` |
| 4 | Huit dossiers, oracle, rejeu | `journal-t0N.json`, `oracle/t0N.yaml` |
| 5 | **Passage du test de clôture** | `closure-report.json` ; si `closed`, `found_by_design` ou `absorbed` → **arrêt**, rejet consigné |
| 6 | Mesure quatre bras, trois passages de budget | journaux de runs |
| 7 | Conclusion P1-P4 ou « non qualifiée » | rapport anglais |

**Point d'arrêt réel.** Toute issue autre que `qualified` arrête la famille à
l'étape 5 et se consigne dans `README.md` et l'index.
