# Protocole H2 — hétérogénéité de représentation

**Statut.** `prédiction tenue, gain absorbé par la convention` — deux runs
lisibles sur nato, dont un à trois répétitions : le gain en vue brute tient à
**un seul dossier sur deux**, il est stable entre répétitions, et le bras qui
lit par convention sans schéma le couvre entièrement. Le protocole, le corpus
gelé de huit fixtures, l'oracle privé et les trois bras restent la référence de
construction.
**Date.** 2026-10-21 (Europe/Brussels, UTC+02:00). Dernière révision :
**2026-10-22 14:05 (Europe/Brussels, UTC+02:00)**.
**Portée.** Ce document fixe le contraste, la mesure et l'oracle de H2, puis
consigne les passages sur nato. La référence hors ligne (bras règles, bras par
convention) définit ce qu'un gain doit dépasser ; les mesures de modèle sont
celles du 2026-10-22.

## Question et condition d'entrée

V0 est partiellement franchie (`valid_control`, `X = 0,9`, contrôle saturant) :
l'instrument est lisible pour la parité d'exécution. H2 peut donc être ouverte.
Sa question est celle du registre : **le LLM lit-il des présentations qu'aucun
parseur déclaré ne couvre ?**

## Contraste, déclaré avant la fixture

| Élément | Bras règles (`rules_interpreter`) | Bras LLM (`llm_interpreter`) |
| --- | --- | --- |
| Entrée | Les mêmes octets gelés du dossier | Les mêmes octets gelés du dossier |
| Moyens | Un parseur déclaré par schéma **inscrit au contrat** | Aucun parseur, aucune table de correspondance |
| Sortie | Un verdict par message et une conclusion | Un verdict par message et une conclusion |
| Budget | B2, identique aux deux bras | B2, identique aux deux bras |

Le contraste porte sur **l'ensemble des schémas couverts**, pas sur la
compétence : le bras règles est compétent sur tout schéma déclaré au contrat,
et n'a aucun moyen de traiter un schéma qui n'y figure pas. C'est la propriété
mesurée, pas un défaut injecté.

## Troisième bras, déclaré avant le run

Le contraste à deux bras ne départage pas deux lectures d'un même positif : « le
modèle lit mieux » et « le parseur déclaré refuse par construction ». Un
troisième bras les sépare. C'est un **script compétent qui essaie**, sans aucun
schéma déclaré :

- il décode la charge utile (`base64` ou texte) et parcourt le document JSON à
  toute profondeur ;
- il reconnaît l'identité sur des jetons de convention — `dev`, `device`,
  `node`, `sensor`, `id` — et la lecture demandée sur `t`, `temp`,
  `temperature` (ou `h`, `rh`, `hum`, `humid`, `humidity` pour l'humidité) ;
- un jeton d'une autre lecture n'est jamais pris pour la lecture demandée ;
- un emplacement de lecture qui porte autre chose qu'une valeur conduit à
  l'abstention, jamais à une affirmation ;
- aucune clé du corpus n'est écrite dans ce lecteur.

Ce bras n'est pas un concurrent : c'est une **référence**. Si le modèle fait
mieux que le parseur déclaré mais pas mieux que ce script, alors le gain
appartient à la déclaration, pas au modèle. S'il fait mieux que les deux, le
gain lui appartient — sur ce corpus seulement.

**Limite déclarée.** Ce script est écrit après avoir vu le corpus, à partir des
conventions et non des réponses ; il est donc sur-ajusté au corpus par
construction. Il prouve qu'une couverture est possible sans modèle, il ne
mesure pas la performance d'un script sur des dossiers qu'il n'a pas vus.

## Vocabulaire de la famille

- **Schéma de présentation** : la convention de nommage et d'imbrication des
  champs d'un message. `reference` est déclaré au contrat ; `variant` ne l'est
  pas.
- **Vue d'observation** : `raw` donne les octets reçus (charge utile, topic,
  QoS, horodatage) ; `normalized` donne la même information déjà décodée sous
  des noms canoniques.
- **Dossier** : un jeu figé de messages, une question et une vue.
- **Propriété protégée** : la valeur d'un capteur privé d'un appareil nommé.

Les huit types de fixtures de `coverage-plan.json` (C04-D03) couvrent
`{reference, variant} × {raw, normalized} × {0 défaut, 1 défaut}`. Le défaut
intentionnel n'est jamais une information retirée : c'est un message mal formé
dont l'information reste démontrable autrement, ou une forme pour laquelle
l'abstention est la seule réponse correcte.

## Ce que H2 prédit, et ce qui la réfuterait

- **Prédiction.** En vue `raw`, le LLM couvre plus de surfaces que le bras
  règles sur le schéma `variant`. En vue `normalized`, les deux bras sont
  **égaux** : la normalisation est fournie, donc la seule différence restante
  serait sémantique.
- **Réfutation.** Égalité en vue brute (le LLM ne lit pas mieux que les
  parseurs déclarés) ; ou gain en vue normalisée — qui relève de H4 et non de
  H2, et invaliderait la lecture de la famille.

## Mesure

- **Unité.** Le message : verdict `exposed`, `not_exposed` ou `abstain`, comparé
  à l'oracle privé.
- **Conclusion.** Une conclusion par dossier, même vocabulaire.
- **Réussite.** Aucun verdict faux **et** conclusion non contredite par
  l'oracle. Une abstention n'est correcte que lorsque l'oracle déclare deux
  états indiscernables ; une abstention correcte n'est donc ni un faux positif
  ni un succès de couverture.
- **Couverture.** Surfaces correctement tranchées / surfaces de l'oracle. Le
  dénominateur est celui de l'oracle, commun aux deux bras.
- **Recompte.** Toute mesure est recalculée depuis le journal : verdicts,
  abstentions, contradictions entre verdicts et conclusion, budget consommé.
- **Coût et durée.** Mesurés, jamais plafonnés.

## Ce que H2 ne prouvera pas

- Rien sur la sémantique des champs : c'est H4, et la vue `normalized` sert de
  garde-fou.
- Rien sur la collecte autonome : le dossier est figé, aucune transition
  réseau n'est requise (`required_network_transitions: 0`).
- Rien sur l'admission : `strict_v3_metrics_adopted` reste hors de portée.
- Aucune indépendance de famille : `statistical_independence:
  not_established` reste la valeur du registre.
- **Le corpus est petit et écrit à la main** : huit dossiers, une seule
  question, une seule propriété (`temperature_c`) et un seul appareil protégé.
  Un seul schéma `variant` est représenté. Le résultat ne s'étend pas à
  l'espace des schémas MQTT réels, et une amélioration sur ce corpus ne mesure
  pas une compétence générale de lecture de formats.
- **Le parseur déclaré n'est pas optimisé** : il lit le schéma `reference` tel
  qu'inscrit au contrat et rien de plus. C'est la baseline déclarée, pas la
  meilleure baseline possible ; une baseline plus rusée réduirait l'écart.
- **Le contenu est fiable** : aucun message n'est hostile. L'injection
  observée est H6, en sous-test séparé.
- **Le coût n'est pas comparable entre bras** : le bras règles ne consomme
  aucun jeton. La comparaison porte sur la couverture à budget de tours
  identique, pas sur le prix.

## Construction, faite

1. Dossier hors ligne et validateur : schéma, vue, messages, question, refus
   des champs d'oracle et des schémas non déclarés. **Fait.**
2. Oracle privé : verdict par message, drapeau d'indiscernabilité, conclusion
   attendue ; lié au condensat du dossier pour ne pas être rejoué ailleurs.
   **Fait.**
3. Bras règles : parseur déclaré du schéma `reference`, normalisation, règle
   d'exposition ; abstention explicite sur un schéma non déclaré. **Fait.**
4. Évaluateur : verdicts, contradiction, couverture, budget. **Fait.**
5. Bras LLM sur les mêmes octets, sans parseur, avec les mêmes budgets. **Fait,
   testé hors ligne, non exécuté sur nato.**
6. Lanceur nato, sans broker ni fixture : le dossier est figé et seul le
   fournisseur est appelé. Workflow manuel depuis `dev/2`. **Dispatché trois
   fois, voir les passages ci-dessous ; pré-vol fournisseur ajouté.**

## Implémentation

| Élément | Fichier | Ce qui est vérifié |
| --- | --- | --- |
| Dossier, oracle, bras règles, évaluateur | `benchmarks/experiments/mqtt_formats.py` | champs publics seuls, topics littéraux, aucune clé d'étiquette imbriquée, oracle lié au condensat, verdict adossé à une lecture de son propre message |
| Bras LLM | `benchmarks/experiments/mqtt_formats_llm.py` | outils `read_message` et `finish_interpretation`, refus d'une preuve non lue, refus d'un dossier partiel, budgets |
| Corpus gelé | `benchmarks/experiments/mqtt-formats-corpus.json` | huit fixtures, une question commune, oracle re-vérifié au chargement |
| Lanceur nato | `benchmarks/experiments/mqtt_formats_live.py`, workflow `mqtt-formats.yml` | aucun broker, aucun fixture, verrou de laboratoire, projection publique sans charge utile |
| Pré-vol fournisseur | `benchmarks/experiments/mqtt_formats_live.py` | catalogue seul, aucune génération ; distingue extrémité injoignable, modèle absent et modèle qui ne répond pas |
| Troisième bras | `benchmarks/experiments/mqtt_formats.py` (`run_attempting_rules`) | aucune clé du corpus, conventions seulement ; 8/8 hors ligne |
| Tests | `tests/test_mqtt_formats.py` | 71 tests |

**Pré-vol.** Un zéro peut venir de trois causes que le harnais confondait :
l'extrémité est injoignable, le modèle n'y est pas servi, ou le modèle ne rend
rien d'exploitable. Seule la troisième est une mesure. Avant le premier bras,
le lanceur interroge donc le catalogue du fournisseur (quinze secondes, aucun
réessai, aucune génération, aucun contenu du dossier) et s'arrête sur un nom :
`provider-preflight.json` porte la présence du modèle, `provider-preflight-error.json`
la classe d'erreur (`network` ou `protocol`) et le code HTTP. Ces deux fichiers
sont projetés dans le résumé public.

**Ce que le harnais met dans le journal.** Chaque lecture produit une référence
de preuve dérivée du condensat du dossier et du message présenté. Un verdict qui
ne cite pas une lecture de *son* message est refusé, et un verdict qui partage
la référence d'un autre message aussi. La mesure ne dépend donc pas de la
déclaration du modèle : elle est recalculée depuis les lectures.

**Règle d'exposition, commune.** Un message qui ne nomme pas son appareil laisse
la question ouverte, donc abstention. Un message qui nomme un autre appareil, ou
qui ne porte pas la lecture demandée, est `not_exposed` : c'est démontrable.
C'est cette règle que les deux bras appliquent, l'un après son parseur, l'autre
sans.

**Défaut intentionnel.** Il n'est jamais une information retirée. Les fixtures
défectueuses portent soit une charge utile tronquée (`t05`), soit une lecture
sans identité (`t06`, `t08`), soit un appareil nommé avec une valeur qui n'est
pas une lecture (`t07`). L'abstention y est la seule réponse correcte : un
modèle qui devine y perd un verdict.

**Budget.** `max_tool_calls = messages + 1` (une lecture par message, plus la
clôture) et `max_turns = appels + 2 + 6`, la même réserve de clôture et la même
marge de routage que V0. Un budget qui ne peut pas lire et clore est refusé
avant le run.

## Référence à battre, lue hors ligne

Le bras règles a été exécuté sur le corpus gelé, sans réseau ni modèle. Sa
lecture fixe la référence que la prédiction doit dépasser :

| Groupe | Bras règles | Lecture |
| --- | --- | --- |
| `reference/raw` | 2/2 | parseur déclaré, vue brute : couvert |
| `reference/normalized` | 2/2 | vue normalisée : couvert |
| `variant/raw` | **0/2** | aucun parseur pour un schéma non déclaré : abstention partout |
| `variant/normalized` | 2/2 | la normalisation suffit, le schéma ne coûte rien |

Ces chiffres sont une propriété du harnais, pas un résultat de modèle : ils
disent seulement que le contraste est instrumenté.

Le troisième bras, lui aussi hors ligne et sans modèle, couvre **8/8** sur le
corpus gelé, `variant/raw` compris, y compris `t07` que les deux autres bras
échouent. C'est la référence à battre pour qu'un gain de modèle veuille dire
quelque chose.

## Mesure du 2026-10-22

Deux runs lisibles, même modèle (`ollama-umons` / `qwen3.8:27b`), même corpus
gelé, pré-vol `available: true` et deux modèles listés dans les deux cas.

### Run `39756997752` — commit `e4137c8`, une répétition, 16 bras

Aucun échec de contrôleur. Les deux bras de l'époque, sans le bras par
convention.

| Groupe | Bras règles | Bras LLM | Lecture |
| --- | --- | --- | --- |
| `reference/raw` | 1,0 | 1,0 | égalité |
| `reference/normalized` | 1,0 | 1,0 | égalité |
| `variant/raw` | **0,0** | **0,5** | gain strict, un dossier |
| `variant/normalized` | 1,0 | 1,0 | égalité |

**Le gain tient à un seul dossier.** `t03` (`variant/raw`) : le LLM rend 3
verdicts justes, le bras règles s'abstient sur les trois messages faute de
parseur. `t07` (même groupe, appareil nommé avec `"T": "n/a"`) échoue aux deux
bras : chacun rend deux verdicts justes et une affirmation fausse là où
l'abstention était la seule réponse correcte. Le gain ne vient donc pas d'une
supériorité générale sur le schéma `variant`, mais d'un dossier que le parseur
déclaré ne peut pas ouvrir et que le modèle ouvre.

**Ce que cette mesure ne dit pas.** Une répétition, deux dossiers par groupe, un
seul schéma `variant`, une seule question, un seul appareil protégé. Elle
n'établit ni stabilité entre répétitions, ni compétence sur l'espace des schémas
MQTT. Elle ne départage pas non plus « le modèle lit mieux » de « la baseline
déclarée n'essaie pas » : c'est le rôle du bras règles qui essaie, encore à
écrire à ce moment-là (il l'est depuis, voir ci-dessous).

**Défaut de compte trouvé pendant ce run.** Les deux bras publiaient
`tool_calls: 0` alors que le bras LLM lisait trois ou quatre messages et
clôturait : les outils de la famille sont les siens, pas ceux de l'exécuteur,
et aucun compteur ne les voyait. Les verdicts ne sont pas affectés — ils sont
recomptés depuis le journal — mais le coût publié ce jour-là sous-estime les
appels. Corrigé : chaque lecture et chaque clôture alimentent le compteur du
run et le `CostTracker` ; le résumé sépare désormais les deux bras au lieu de
les mettre en commun.

### Run `39759422939` — commit `da7e9cd`, trois répétitions, 72 bras

Même modèle, même corpus, les trois bras dans le même run, l'ordre des bras
tourné à chaque fixture. Aucun échec de contrôleur.

| Groupe | Bras règles | Bras convention | Bras LLM |
| --- | --- | --- | --- |
| `reference/raw` | 1,0 | 1,0 | 1,0 |
| `reference/normalized` | 1,0 | 1,0 | 1,0 |
| `variant/raw` | **0,0** | **1,0** | **0,5** |
| `variant/normalized` | 1,0 | 1,0 | 1,0 |

**La figure est stable.** Les trois répétitions rendent le même tableau : `t03`
gagné par le modèle à chaque fois, `t07` perdu à chaque fois, `rules_attempt`
juste sur les 24 bras. Le gain de `0,5` n'est donc pas un tirage chanceux — mais
il reste **un dossier sur deux**.

**Le gain est absorbé par la convention.** Le bras `rules_attempt` n'a aucune clé
du corpus et lit `dev`/`node`/`sensor`/`id` pour l'identité, `t`/`temp` pour la
lecture ; il couvre `t03` et `t07` sans modèle. Le contrôle de prédiction publie
donc `convention_gain_absorbed: true` : ce que le LLM gagne sur le parseur
déclaré, un script qui essaie le gagne aussi. La prédiction de H2 reste tenue au
sens littéral (`raw_gain: true`, `normalized_equal: true`), mais elle ne
distingue plus le modèle de la déclaration : un parseur plus large suffirait.

**Coût.** Chaque bras LLM consomme quatre ou cinq appels d'outil (quatre
lectures plus la clôture, ou trois lectures, un refus recompté et la clôture) et
sept à quatorze secondes. Les `tool_calls` publiés sont désormais non nuls : le
défaut de compte du run précédent est corrigé, et ces chiffres sont mesurés, pas
plafonnés.

**Ce que cette mesure ne dit pas.** Deux dossiers par groupe, un seul schéma
`variant`, une seule question, un seul appareil protégé, un seul modèle. Elle
établit la stabilité sur ce corpus, pas une compétence sur l'espace des schémas
MQTT. Le fait que la convention couvre `t03` et `t07` ferme la lecture « le
modèle lit ce que personne d'autre ne lit » pour ce corpus ; il ne dit pas
qu'aucun schéma ne résisterait à une convention plus riche. Un modèle différent
pourrait rendre un autre tableau : le run n'a été fait qu'avec `qwen3.8:27b`.

## Passages sur nato

**2026-10-21, run `39673128559` — `TypeError`, aucun résultat.** Le contrôleur
s'arrête à la première fixture. Deux défauts d'instrument : le bras règles
n'écrivait pas son fichier de réponse, donc le recompte le lisait comme un bras
clos sans décision — le score des parseurs déclarés serait apparu comme un
échec total ; et le lanceur appelait le compteur de routage en mémoire de V0
avec un répertoire. La défaillance du contrôleur publie désormais sa classe
d'erreur et ses cadres de code, jamais un traceback qui pourrait citer un
message.

**2026-10-21, run `39674488111` — aucun résultat, défaut d'instrument.** Les
deux bras s'exécutent, mais les 24 bras LLM rendent six `providererror` par
invocation et aucune réponse : le routage publié ne portait que
`cause=providererror` et `response_type=providererror`, donc pas la cause. Deux
corrections : le routage publie `error_kind` et `status_code`, et l'outil de
clôture ne demande plus un objet libre indexé par identifiant — une forme
imbriquée que l'extrémité du fournisseur ne sait pas exprimer, et qui fait
échouer *toutes* les requêtes. Les verdicts sont une liste plate. Le bras
règles, lui, rend `1.0` sur les trois groupes couverts et `0.0` sur
`variant/raw`, comme hors ligne.

**2026-10-21, run `39684177777` — aucun résultat, extrémité injoignable.** Le
schéma de clôture aplati laisse passer les requêtes, et le routage nomme
désormais la cause : `error_kind=network`, six fois par invocation,
`response_type=providererror`, aucun code HTTP — donc pas un refus du
fournisseur mais une connexion qui n'aboutit pas. Le bras règles, lui, reste
stable et rend `1.0` sur les trois groupes couverts et `0.0` sur
`variant/raw`. Le modèle n'a rien rendu : ce passage ne mesure pas H2. Il
montre seulement que le harnais ne distinguait pas encore *l'extrémité
injoignable* d'un modèle qui lit mal le corpus ; le pré-vol fournisseur
ci-dessus sépare maintenant ces deux cas avant de dépenser un bras.

**2026-10-22, passages `39691982845` (garde) et `39692443207` (pré-vol) — aucun
résultat, relais arrêté.** Le premier s'arrête sur le garde de commit : le
checkout `dev/2` portait encore le commit précédent, la validation et le
déploiement n'étant pas terminés. Le second, dispatché après, atteint le
contrôleur et le pré-vol nomme la cause sans dépenser un seul bras :
`error_type=APIConnectionError`, `error_kind=network`, `status_code=null`. Le
relais `pve-nato` (`100.76.206.65:11435`) n'écoute plus, alors que `nato` et
`pve-nato` répondent : c'est le tunnel identifié le 4 octobre 2026 qui est
retombé, pas le fournisseur ni le harnais. Aucun bras n'a été exécuté, donc
aucune mesure. Le trajet et la procédure de rétablissement sont dans
[le guide UMONS](../../docs/guides/umons-llm.md), et le rétablissement exige
une authentification interactive avec le compte UMONS autorisé.

**2026-10-22, runs `39756997752` et `39759422939` — mesure.** Relais rétabli,
les deux passages rendent un tableau complet et sans échec de contrôleur ; le
second, à trois répétitions et trois bras, est le run de référence. Le détail est
dans « Mesure du 2026-10-22 » ci-dessus.

Les passages du 2026-10-21 ne mesurent rien sur le modèle et ne comptent pas
comme des résultats de H2. Les premiers disent que le harnais n'était pas encore lisible ;
les derniers qu'il l'est, et que la panne est en amont de lui. Le pré-vol a
changé ce que ces échecs coûtent : un relais arrêté se nomme maintenant en
quelques secondes et zéro bras, au lieu de vingt-quatre bras et d'un journal de
six erreurs par invocation.

La prédiction reste falsifiable ainsi — le bras LLM doit faire **strictement
mieux que 0/2** sur `variant/raw` et rester à **2/2** sur les trois autres
groupes. Un gain en vue normalisée serait un résultat de H4, pas de H2.
