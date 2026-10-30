# Plan de conception — étude de cas `s_registres_constructeur` (révision 4)

**Cycle de vie : Actif — plan de conception final avant code** — ouvert le
**2026-10-30**, dernière révision **2026-10-30 14:50 (Europe/Brussels, UTC+01:00)**.

> **Révision 4, la dernière avant le code.** Les quatre relectures
> indépendantes des révisions 1 à 3 sont consignées dans `relectures.md`.
> Décisions verrouillées par l'auteur du cahier des charges le 2026-10-30.

> **Statut.** Cette famille est une **étude de cas de faisabilité**, hors
> registre d'hypothèses, au même titre que `s_api_organisations`. Elle
> **n'ouvre aucune hypothèse** ; elle établit la faisabilité d'une famille
> indépendante et d'un test de clôture exécutable. Une ouverture ultérieure
> de H3 ou H4 réutilisera ce mécanisme, avec le corpus élargi que
> l'hypothèse exigera.

---

## 0. Décisions verrouillées

| # | Décision |
| --- | --- |
| D1 | **Interprétation seule** : journal figé, aucun outil. La vérification par sondes n'est pas mesurée. |
| D2 | **Vocabulaire = noms, jamais nature** : le libellé nomme une unité de mesure. |
| D3 | **Le test de clôture vit avec la famille.** |
| D4 | **Décompte par registre ambigu** ; aucune décision statistique. |
| D5 | **Aucune hypothèse ouverte**, et **aucun effet revendiqué**, même si l'écart est là. |
| D6 | **Contrôle positif partiel assumé** : couvre `intentional_flaws` 0/1, pas les collections. |

**Ce que cette étude ne rapporte pas, et l'écrira ainsi :** aucun écart de
performance entre bras ; aucune inférence statistique ; aucune comparaison
avec une autre famille ; aucune portée sur H3, H4 ou une autre hypothèse ;
aucune extrapolation au-delà des huit dossiers ; aucune recommandation sur le
choix d'une politique d'audit. Les scores par bras existent dans l'artefact
de mesure, **jamais dans la conclusion**.

---

## 1. Historique des chemins faux, et le protocole qui les distingue

Trois chemins ont été déclarés « vérifiés » à tort, avant que le quatrième ne
tienne devant trois relectures indépendantes.

| # | Chemin | Ce que la sonde disait | Ce que la mesure complète a montré |
| --- | --- | --- | --- |
| 1 | `ModbusSequentialDataBlock(lo + 1, …)` | « écriture du registre 100 isolée » | Faux : les sentinelles étaient construites pour l'offset supposé. |
| 2 | `ModbusSequentialDataBlock(lo, …)` | « pas de décalage » | Faux : `SimData(lo - 1, …)` ; `fc3 100` renvoie `valeurs[1]`. |
| 3 | `SimDevice(unit, simdata=(co, di, hr, ir))` | « adresse exacte » | Inutilisable : quatre listes obligatoires, mode binaire forcé. |
| 4 | **`ModbusSparseDataBlock`** | — | **Tient** : trois relectures indépendantes, sur 3.15.0 et 3.14.0. |

**Cause commune.** Chaque sonde validait le décalage qu'elle supposait juste :
valeurs construites pour cet offset, puis table à zéros. **Un test de fenêtre
sur des zéros passe sur une table décalée.**

**Protocole figé**, qui rend l'erreur détectable — il fait partie du test de
clôture (étape 3) :

1. Table à **valeurs toutes distinctes et non nulles** :
   `hr[100+i] = 5000+i`, `ir[100+i] = 6000+i`.
2. L'égalité porte sur **la valeur attendue à l'adresse documentée**, jamais
   sur une valeur choisie après coup.
3. Bornes vérifiées : `99` et `120` → **exception 02** ; `100` et `119` →
   leurs valeurs.
4. `fc4 addr 100` → `6000`, **différent** de `fc3 addr 100`.
5. `fc3 addr 100 count=3` → `[5000, 5001, 5002]` ; `fc3 addr 99 count=3` →
   exception.
6. `fc6 addr 100 = 777` laisse `99`, `101` et `ir[100]` **exactement**
   inchangés.
7. **`fc3 addr 100` avec l'unité `9` → exception 04** : l'unité
   d'identification filtre, et `hr` et `ir` coexistent sous une seule unité.

---

## 2. Adressage retenu et garde de version

`ModbusSparseDataBlock` dans un `ModbusDeviceContext`, servi par
`ModbusServerContext(devices={unit_id: device}, single=False)`.

Mesure du 2026-10-30 (pymodbus 3.15.0, unité 47, trames MBAP brutes),
reproduite à l'identique par deux relecteurs indépendants, et sur 3.14.0 :

| Trame | Réponse |
| --- | --- |
| `fc3 99` | exception 02 |
| `fc3 100` | 5000 |
| `fc3 101` | 5001 |
| `fc3 119` | 5019 |
| `fc3 120` | exception 02 |
| `fc4 100` | 6000 |
| `fc3 100 c3` | `[5000, 5001, 5002]` |
| `fc3 99 c3` | exception 02 |
| `fc3 100 unit 9` | exception 04 |
| `fc6 100 = 777` | `100 = 777` ; `99` exc 02, `101` = 5001, `fc4 100` = 6000 |

**La sentinelle.** Le bloc déclaré construit **20 entrées** (100..119).
`SimDevice.build_device` y ajoute une **sentinelle `DataType.INVALID`** en fin
de bloc (soit 21 registres internes), identique pour tout bloc, **non exposée
sur le fil** et **hors de l'oracle**. Ce n'est ni une définition d'adressage
ni un objet de test : le test de fenêtre vérifie les **bornes** `99`, `100`,
`119`, `120`, que la table seule définit.

**Garde de version.** `benchmarks/experiments/registres-constructeur/requirements.txt`
**à créer** (étape 1) avec `pymodbus==3.15.0`. Le test de garde échoue
**explicitement**, jamais en saut silencieux :

- `pymodbus.__version__ == "3.15.0"` — **égalité exacte** : `startswith` passe
  sur 3.16, et une borne en chaînes échoue même sur la version correcte ;
- les noms `ModbusSparseDataBlock`, `ModbusDeviceContext`,
  `ModbusServerContext` sont importables depuis `pymodbus.datastore` ;
- un aller-retour `fc3`/`fc6` réel sur la boucle locale reproduit la première
  ligne du tableau ;
- message d'échec nommant l'API attendue et l'API trouvée.

Le garde **n'utilise pas** `pytest.importorskip` : un saut silencieux serait
un succès non comptabilisé.

---

## 3. Le journal : capture enregistrée

Ni le scanner (`nmap -sV -p 502`, `modbus-discover`) ni `modbus_write` ne
relisent un registre. Le journal est une **capture enregistrée**, produite par
le générateur de la famille.

```json
{
  "schema_version": 1,
  "family": "s_registres_constructeur",
  "provenance": "recorded_capture",
  "api": {"pymodbus": "3.15.0"},
  "sut_sha256": "…", "generator_sha256": "…",
  "seed": "<graine en clair>",
  "journal_sha256": "…",
  "unit_id": 47,
  "window": {"hr": [100, 119], "ir": [100, 119]},
  "initial_state": {"hr": {"100": 5000, "…": "…"}, "ir": {"100": 6000, "…": "…"}},
  "observations": [
    {"seq": 1, "observation_ref": "obs-0001", "space": "hr", "kind": "read", "address": 100, "value": 5000},
    {"seq": 2, "observation_ref": "obs-0002", "space": "hr", "kind": "write", "address": 100, "written": 5000, "read_back": 5000},
    {"seq": 3, "observation_ref": "obs-0003", "space": "hr", "kind": "neighbour", "address": 99, "result": "exception_02"}
  ]
}
```

`window`, `unit_id`, l'API, `sut_sha256` et l'espace (`hr`/`ir`) sont
**exigés** : sans eux, `initial_state` ne détermine pas l'état servi.

**Rejeu.** `replay(journal, sut)` recrée la SUT depuis `initial_state` avec la
fenêtre et l'unité déclarées, applique les écritures dans l'ordre de `seq`,
relit chaque registre nommé, ses voisins et son registre d'entrée, et compare
à l'identique. Testé sur un cas vert et un cas falsifié (`written ≠
read_back`).

**Ce que le journal ne contient jamais** : l'oracle, la classe, le nombre
attendu de projections, la consigne de sécurité, la seed des tirages de la
variante, ni la table de correspondance.

---

## 4. Les huit dossiers

| Dossier | Défaut ? | Ambiguïté |
| --- | --- | --- |
| `t01` | non | aucune |
| `t02` | non | mêmes unités, autres mots, ordre différent |
| `t03` | **oui** | vingt ambigus, **un** porteur d'une projection |
| `t04` | **oui** | même défaut, place tirée par le générateur |
| `t05` | non | vingt ambigus, aucune projection, documentation complète |
| `t06` | non | vingt ambigus, aucune projection, documentation partielle |
| `t07` | **oui** | documentation absente |
| `t08` | **oui** | documentation présente, majeure partie hors documentation |

**Génération, pour que deux implémenteurs obtiennent les mêmes fichiers.**
Deux tirages indépendants :

- **tirage public** (la seed est dans `pre_register.json`, publiée après
  préenregistrement, jamais transmise aux bras) : adresses,
  unités, ordre de configuration, valeurs chiffrées, libellés de rôle ;
- **tirage de variante** (secret, seulement hashé) : recombinaison pour
  `t02`, `t04`, `t06`, `t08`.

Le générateur est une fonction pure `generate(seed) -> {t01…t08}` ; un test
recalcule les huit dossiers depuis la seule seed et échoue au moindre écart.

**Pool de libellés.** Commun à `t01`–`t08`, vingt fois plus de libellés que
nécessaire ; la variante recombine, elle n'apprend pas.

**F0** = `t01`, `t02`, `t05`, `t06`, consigné comme **choix préenregistré**,
pas comme témoin neutre : `t05`/`t06` portent une ambiguïté réelle sans
projection.

---

## 5. L'oracle

`(appareil, registre, espace, classe, statut attendu, preuve admissible)`.

- **Classe (c)** : une propriété = **un registre × son statut** (`projection`
  ou `none`) → **20 propriétés par dossier**.
- **Classes (a) et (b)** : témoins, jamais mesurées comme résultat.

**`is_supported`, pseudo-code typé.**

```
refs      : frozenset[str]        # observation_ref seules ; seq jamais accepté
register  : tuple[str, int]       # (espace: "hr"|"ir", adresse)
admissible(propriété) -> frozenset[str]   # NON VIDE, y compris pour statut "none"
```

```
is_supported(answer, oracle):
    erreurs = []
    if answer.register not in oracle.registres:      erreurs += ["registre_inconnu"]
    if answer.refs - journal.refs:                   erreurs += ["ref_inexistante"]
    p = oracle.propriété(answer.register)
    if answer.decision != p.statut:                  erreurs += ["statut"]
    if answer.refs != p.admissible:                  erreurs += ["preuve_non_egale"]
    return (not erreurs, erreurs)
```

Règles fermées :
- une `ref` **en trop** ⇒ `preuve_non_egale` (pas de tolérance) ;
- une `ref` **inexistante** au journal ⇒ `ref_inexistante`, réponse
  **rejetée**, jamais d'exception ;
- pour un statut `none`, l'ensemble admissible **n'est jamais vide** : il
  contient la lecture qui montre l'absence de projection (voisin, registre
  d'entrée, exception). Sinon la seule réponse possible serait
  `undetermined`, donc `inconclusive` par construction ;
- une réponse **non soutenue** (`is_supported` faux) est
  `unsupported_finding`, comptée dans P3, **jamais un succès**.

---

## 6. Les bras

| Bras | Reçoit | Interdiction |
| --- | --- | --- |
| **D1+** | journal, documentation, table | **11 règles maximum, 60 requêtes maximum**, déposées et hashées à l'étape 1 |
| **Convention** | journal, documentation | aucune clé du corpus ; test exécuté qui l'établit contre `t01`–`t08` |
| **Témoin de borne** | journal, documentation, table | — |
| **LLM** | journal, documentation | aucun outil |
| **Aléatoire** | rien d'utile | script seedé déposé à l'étape 1, **borne inférieure descriptive**, pas un critère d'issue |

Les sorties des cinq bras sont **écrites** à l'étape 5 et **ne sont pas
comparées** dans la conclusion (§ 7).

---

## 7. Le test de clôture

### Fonction de verdict, pure et déterministe

```
verdict(journal, oracle, sortie_d1plus, sortie_convention, sortie_temoin,
        sortie_aleatoire) -> verdict
```

Aucune horloge, aucun fichier hors ceux du manifeste, aucun paramètre laissé
au juge. **`found_by_design` n'existe pas** : il n'existe qu'un cas où les
règles battent le test, et c'est `d1plus_succeeds`, vérifié par une égalité,
pas par un jugement de mérite.

### Le critère d'issue est binaire : **l'instrument discrimine ou il ne discrimine pas**

Sur les **20 registres à projection** :

1. **le témoin de borne obtient exactement le score de l'oracle** — la
   réponse est atteignable ;
2. **le bras convention ne reproduit pas le témoin sur au moins un registre**
   — le poste n'est pas trivial ;
3. **les sorties des deux bras à règle ne sont pas identiques au témoin sur
   l'ensemble des registres** — l'instrument sépare.

Trois **égalités sur des ensembles**, aucun seuil, aucun α. Le bras aléatoire
est une **borne inférieure préenregistrée pour l'analyse descriptive** et
n'entre dans aucune de ces trois conditions.

### Table de vérité, exhaustive et exclusive

Ordre de priorité explicite, évalué de haut en bas ; le premier satisfait
l'emporte :

| Priorité | Verdict | Condition (égalités sur ensembles) |
| --- | --- | --- |
| 1 | `closed` | un bras conclut un statut **attesté** différent de l'oracle sur au moins un registre |
| 2 | `d1plus_succeeds` | D1+ conclut le bon statut, **attesté**, sur au moins un registre à projection |
| 3 | `not_binary_issue` | les trois conditions de discrimination ne sont pas **toutes** satisfaites |
| 4 | `inconclusive` | un bras rend `undetermined` sur une propriété (c) ; un serveur absent ou une `EvidenceWriteError` en posture de contrôle ; préenregistrement incomplet |
| 5 | `discriminates` | les trois conditions de discrimination sont satisfaites, et aucun cas 1 à 4 |

`undetermined` **n'est jamais neutre** : il tombe dans `inconclusive`, donc
dans une issue non favorable.

### Contrôle positif PC-a

Rapporté à **`benchmarks/experiments/api_reference.py`, `run_rules`, ligne
186** (`EvidenceWriteError` levé ligne 239). **Ne pas** confondre avec
`mqtt_formats.py:326`, qui est la fonction H2.

Trois issues distinctes, mesurées par la relecture technique :

- **nominal** : `status=completed`, `finding=false` dans les deux postures ;
- **serveur absent** : `status=completed, finding=false` — **indiscernable
  d'un F0 réussi** si l'on ne vérifie que `status`. Le test de clôture exige
  `control_proven` et `inventory_proven` **issus du journal**, sinon
  `inconclusive` ;
- **journal non inscriptible** : `EvidenceWriteError` levée, sans `status` ni
  `error_type`. L'assertion vise donc `pytest.raises(EvidenceWriteError)`
  et la présence d'au moins une observation archivée, jamais
  `exc.value.status` (qui lèverait `AttributeError`).

**PC-b non couvert** : `run_rules` ne lit jamais une collection. Le contrôle
est **partiel** et l'est déclaré.

### Préenregistrement

`closure/pre_register.json`, écrit **avant toute fixture**, contient : les
hashs de D1+ (11 règles, 60 requêtes), de la convention, du témoin et du bras
aléatoire ; les hashs des huit journaux et de l'oracle ; la **graine en
clair** ; la table de vérité du § 7 ; les seuils P1-P4 et le taux de base ; la
série attendue du bras aléatoire.

**Une fois l'étape 2 passée, la grille est fermée.** L'étape 5 n'exécute que
les hashs du manifeste ; toute réécriture d'un bras exige un nouveau
préenregistrement complet, et la mesure précédente est jetée.

Les fichiers cités ici — `requirements.txt`, `closure/manifest.json`,
`pre_register.json`, dossier `benchmarks/experiments/registres-constructeur/` —
**n'existent pas encore** et sont créés aux étapes 1 et 2.

---

## 8. Prédicats (descriptifs, aucune décision statistique)

| # | Prédicat | Mesure |
| --- | --- | --- |
| P1 | A1 > D1+ sur la justesse attestée, classe (c), par registre | propriétés attestées / 20 ; **descriptif** |
| P2 | Succès commun sur les témoins (a) et (b) | aucun écart entre bras |
| P3 | Faux positifs « sémantique inventée » | τ = 1 / 4 dossiers **à défaut** (`t03`, `t04`, `t07`, `t08`) ; `unsupported_finding` compte comme faux positif |
| P4 | Écart indépendant du budget | journal de 40, 120, 360 observations ; **taux d'attestation** = propriétés attestées / 20 par dossier ; seuil X préenregistré, ne décroît pas de plus de X points |

P1 et P4 sont des **descriptions**, pas des tests : aucun p-value, aucune
décision.

---

## 9. Ordre des livrables

| Étape | Livrable |
| --- | --- |
| 0 | Ce plan ; relectures consignées |
| 1 | D1+ (11 règles, 60 requêtes), convention, témoin, aléatoire, SUT, `requirements.txt`, garde de version |
| 2 | `pre_register.json`, fonction de verdict, PC-a (y compris serveur absent et `EvidenceWriteError`) |
| 3 | Test d'adressage par trames brutes, protocole § 1 en 7 points |
| 4 | Huit dossiers par `generate(seed)`, oracle, rejeu |
| 5 | **Passage du test de clôture** : `discriminates` ou issue alternative consignée |
| 6 | Mesure descriptive : **annexe**, jamais la conclusion |
| 7 | Conclusion : faisabilité établie ou non ; famille non admise dans la campagne |

**Aucune conséquence de l'étape 5 ne ressemble à une ouverture d'hypothèse.**
L'issue dit que l'instrument fonctionne ou non, jamais qui gagne.
