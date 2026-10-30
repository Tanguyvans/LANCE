# Compte rendu de rejet — `s_registres_constructeur`

**Cycle de vie : conclu — rejet** — ouvert le **2026-10-30**, clos le
**2026-10-30**. Dernière révision : **2026-10-30 15:20 (Europe/Brussels, UTC+01:00)**.
Statut : **famille rejetée ; aucune mesure produite ; aucune hypothèse ouverte.**

> **Ce document n'est pas un plan.** Le plan de conception a été validé après
> six relectures indépendantes ; il est conservé tel quel dans
> [`plan-conception.md`](plan-conception.md) (révision 4) et n'a pas été
> réécrit pour s'adapter au code. Ce compte rendu consigne ce que la
> première observation réelle a montré, et pourquoi la famille est rejetée.

---

## 1. Résumé

Huit relectures indépendantes — quatre sur le plan de conception, quatre sur
les révisions suivantes — ont validé un dispositif dont le test de clôture
était exécutable, la grille binaire et la preuve liée spécifiée. Une seule
observation réelle, construite en une heure, a invalidé la famille : le piège
qui devait faire échouer les règles est franchi par une règle générique.

**La famille ne mesure rien.** Elle est rejetée avant toute mesure, au titre
même que sa condition d'ouverture prévoyait.

---

## 2. Ce qui a été construit

| Élément | État |
| --- | --- |
| Plan de conception, révision 4 | Écrit, six relectures consignées dans [`relectures.md`](relectures.md) |
| Modèle d'adressage (`ModbusSparseDataBlock`) | Établi par trames MBAP brutes, reproduit par trois relecteurs, y compris sur pymodbus 3.14.0 |
| Sonde : trois registres, journal attribuable | [`benchmarks/experiments/registres-constructeur/dossier_sonde.py`](../../benchmarks/experiments/registres-constructeur/dossier_sonde.py) |
| D1+, convention, oracle, huit dossiers, test de clôture | **Non construits** : le rejet intervient avant |

La sonde construit un dossier de trois registres — un commandeur, un inerte,
un cache — avec lectures réelles des voisins, écritures-testet attribution
explicite de chaque lecture à une seule écriture. Elle applique deux bras :
la convention (unité facturée + changement) et un lecteur de voisins.

---

## 3. Ce que la sonde a montré

| Registre | Vérité | Convention | Lecteur de voisins |
| --- | --- | --- | --- |
| 100 — unité facturée, change, voisins stables | `projection` | ✓ | ✓ |
| 101 — unité mesurée, inerte | `none` | ✓ | ✓ |
| 102 — unité mesurée, change **et propage** (cache) | `none` | ✗ | ✓ |
| **Score** | | **2/3** | **3/3** |

Le lecteur de voisins arrive à 3/3 et **nomme la bonne écriture** sur les
trois registres (`wrt-0015`, `wrt-0025`, `wrt-0035`) ; il conclut que 102 est
un cache parce que l'écriture propage dans `[101, 103]`, ce qui est le fait.

**Et c'est précisément pour cela que la famille est rejetée.**

---

## 4. Pourquoi la famille ne mesure rien

Le bras qui réussit 3/3 **est un script**. Il lit le journal, compare la
lecture d'un voisin avant et après une écriture, et conclut. Il n'a ni modèle,
ni table de référence, ni heuristique apprise.

La règle qu'il applique — « un registre dont l'écriture déplace ses voisins
republie une valeur, il ne commande pas » — est :

- **dérivable des entrées publiques** : elle se lit dans les observations ;
- **générique** : elle ne nomme aucune adresse, aucun libellé, aucune unité ;
- **exactement ce qu'un D1+ compétent doit contenir.**

Dès lors :

- si **D1+ contient** cette règle, il fait 3/3 et la règle `d1plus_succeeds`
  s'applique : rejet, exactement le cas de l'étape 5 ;
- si **D1+ ne la contient pas**, la famille mesure une omission de D1+ et non
  une limite de l'interprétation : elle serait rejetée pour la même raison,
  un degré plus loin.

Il n'existe pas de troisième voie. Le piège du cache n'est pas plus difficile
que la lecture des voisins.

### La leçon, dans les termes de son auteur

J'ai construit un piège que les règles franchissent, en une heure. Le dossier
reprochait aux familles existantes d'être construites autour de ce que les
règles trouvent ; j'ai fait la même chose, en sachant pourquoi c'était faux,
et c'est une observation qui l'a montré, pas une relecture.

Six relectures validaient le mécanisme. Elles ne pouvaient pas voir ce que
seule une exécution révèle : **qu'une règle générique suffit**. C'est
l'argument le plus clair en faveur du protocole de clôture exécutable, et
contre la revue de conception seule.

---

## 5. Ce qui reste acquis

Ces trois résultats sont indépendants du rejet et réutilisables par toute
famille future.

**A1 — L'absence se déduit, elle ne se déclare pas (option D).** Un statut
« pas de commande » est attesté sans aucune étiquette dans le journal, par
l'écriture-test : le registre ne change pas, ses voisins ne changent pas,
l'exception est cohérente avec la fenêtre. Une étiquette d'absence aurait mis
la réponse dans le journal ; la déduction la laisse à l'interprétation. Le
dossier de trois registres le démontre.

**A2 — Un journal doit être attribuable.** Aucune observation ne peut relever
de deux causes. Cela exige : un identifiant stable par écriture, une phase
`before` ou `after` sur chaque lecture, et des lectures réelles — jamais une
valeur nulle. Trois défauts ont été trouvés successivement sur ce point, et
chacun rendait un bras juste ou faux pour une mauvaise raison. Sur vingt
registres contigus, où chaque registre est voisin du suivant, l'absence
d'attribution rendrait le bras systématiquement faux avec un score crédible.

**A3 — Le protocole de clôture fonctionne.** Une observation a rejeté ce que
six relectures validaient. Le coût de l'observation est d'une heure ; le coût
des six relectures est de plusieurs heures. Toute famille future doit être
soumise à sa plus petite observation **avant** sa première relecture, et non
après.

---

## 6. Ce que le registre d'hypothèses doit retenir

`s_registres_constructeur` **reste non ouverte**.

La raison n'est pas un manque de corpus. C'est que **le mécanisme est franchi
par une règle générique**. Toute famille future sur H4 devra proposer un cas
qu'une règle générique ne franchit pas ; sans cela, elle mesurera
l'exhaustivité de D1+, pas la limite de l'interprétation.

---

## 7. Ce que ce rejet ne prouve pas

- Rien sur les autres mécanismes : une famille ne fait pas une carte.
- **Rien sur H4 elle-même.** Le rejet ne dit pas que H4 est fausse ; il dit
  que **ce mécanisme-là** — un cache distingué par la propagation de son
  écriture dans ses voisins — est franchi par une règle générique. Un
  mécanisme différent pourrait survivre, et c'est la seule chose que la
  famille future devra démontrer avant d'être construite, non après.
- Rien sur le niveau du modèle : aucun modèle n'a été exécuté. Ce n'est pas
  le LLM qui a fait échouer la famille, c'est un script.
- Rien sur l'indépendance statistique : elle exige trois familles.

---

## 7 bis. Un test rouge n'est pas un témoin

Pendant la conception, un test a été écrit **volontairement rouge** pour
attester un trou du plan : le module qu'il importait n'existait pas encore,
et son échec devait rappeler que la règle de clôture du § 5 n'était pas
définie. C'était le témoin du point d'arrêt.

Il a bloqué la collecte de **4514 tests**. Un fichier de test qui importe un
module inexistant ne marque pas un trou : il fait tomber la suite entière, et
la panne masque tout ce que la suite aurait dit par ailleurs. Il a donc été
supprimé quand le trou a été consigné en prose.

**La leçon : un témoin se consigne, pas ne se commite cassé.** L'état
incomplet d'un travail s'écrit dans le document qui le porte — ici, ce compte
rendu, et le § 5 du plan de conception — jamais dans un test qui empêche la
validation de tout le reste.


---

## 8. Documents et artefacts

- [`plan-conception.md`](plan-conception.md) — plan révision 4, validé puis
  invalidé par l'observation.
- [`relectures.md`](relectures.md) — journal des relectures.
- [`README.md`](README.md) — cahier des charges, statut d'origine.
- [`dossier_sonde.py`](../../benchmarks/experiments/registres-constructeur/dossier_sonde.py) —
  la sonde qui a produit le rejet ; elle reproduit ses trois scores.
- `tests/test_modbus_tools.py` — garde de l'outil `modbus_write`.
