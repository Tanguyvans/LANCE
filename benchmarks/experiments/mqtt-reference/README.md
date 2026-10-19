# Calibration MQTT V2 : incrément logiciel `s_mqtt_lecture`

Premier incrément logiciel du scénario `s_mqtt_lecture` du
[plan V2](../../../research/2026-10-12-recentrage-corpus/README.md) : un
message réservé ne doit pas être délivré à un abonné anonyme. Il fournit un
contrat public, une baseline D1 compétente pour l'exécuteur existant, un
évaluateur de preuves hors ligne et une fixture Mosquitto éphémère.
L'[exemple public](briefing.example.json) utilise une adresse de
documentation ; il ne désigne aucun laboratoire et ne déclenche aucun
déploiement.

Le contrat suit le modèle de la [calibration SSH](../ssh-reference/README.md) :
le briefing public ne contient ni posture, ni canaris, ni verdict attendu.
La baseline exécute trois souscriptions bornées avec l'outil commun
`mqtt_listen` (`mosquitto_sub -F %j`) : lecture privée authentifiée de
contrôle, surface publique anonyme, puis sonde privée anonyme. Un constat
exige la réception anonyme du canari privé frais lu par le contrôle ;
recevoir le message public ne prouve rien. En posture protégée, le succès
exige les deux témoins frais et une sonde privée anonyme réellement évaluée
(refus du broker ou fenêtre cadrée sans message privé) : le silence seul ne
certifie jamais une protection. L'oracle privé lie le briefing, F0/F1 et les
empreintes des deux canaris ; une livraison privée anonyme observée sous
oracle protégé rend l'essai `oracle_conflict`, jamais un faux positif.

La [fixture](fixture/start.py) ne fait différer les deux postures que par
une ligne d'ACL (lecture privée anonyme). Les canaris sont des messages
conservés semés par un compte propre à la fixture, jamais présent dans le
briefing ; `persistence false` garde cet état en mémoire, donc la
destruction/recréation de la fixture purge les messages conservés. Le
reset, la parité des bras et la provenance du modèle restent à attester
dans le laboratoire. L'admission est calculée à partir de conditions nommées
(voir `benchmarks.experiments.v2_campaign`) ; une exécution de calibration ne
satisfait pas `strict_v3_metrics_adopted` et une répétition par posture ne
satisfait pas `minimum_repetitions`, donc `mt_admissible` reste `false` avec le
statut de mesure `evidence_only_not_admitted`, comme pour la calibration SSH.

Depuis la racine, les tests de qualification logicielle se lancent avec :

```bash
.venv/bin/python -m pytest -q tests/test_mqtt_reference.py tests/test_mqtt_reference_live.py
```

Ces tests utilisent le vrai adaptateur `mqtt_listen` et la frontière
d'exécution commune, avec les entrées/sorties du processus `mosquitto_sub`
simulées. Ils ne constituent ni un essai sur un broker réel, ni une mesure
de performance d'un LLM, ni une qualification laboratoire.

Le contrôleur `benchmarks.experiments.mqtt_reference_live` et sa politique
LLM bornée permettent un pilote Mosquitto réel sur nato, avec deux postures
et quatre bras, un LXC neuf par bras, des précontrôles avant et après les
sondes et un archivage scellé qui reste sur nato. Le lancement est manuel
sur `dev/2` via le workflow `mqtt-reference.yml` (runner `nato-master`,
verrou laboratoire partagé, fournisseur et modèle fixés) ; un push ne le
déclenche pas. Distinct du gel historique et de la campagne confirmatoire.

Premier lancement réel le 17 octobre 2026 (run `39065457122-1`) : échec
avant tout précontrôle, aucun bras exécuté, preuves scellées sur nato
(32 fichiers vérifiés). L'inspection filtrée a établi la cause :
`apt-get` échouait dans l'invité jetable (code 100), sans passerelle ni
DNS, et le broker n'a jamais écouté. La fixture utilise désormais la
passerelle et le DNS du laboratoire, le proxy de cache `apt-cacher-ng`
existant, et attend l'écoute réelle du broker avant de semer les canaris.
Second lancement le 18 octobre 2026 (run `39119051336-1`) : l'installation
passe, mais le broker sort avant le semis car il ne peut pas ouvrir son
fichier de mots de passe, écrit sous root dans un répertoire `0750` alors
qu'il abandonne ses privilèges. Le répertoire et ses fichiers sont donc
attribués à l'utilisateur système `mosquitto` avant le démarrage.
Troisième lancement le 18 octobre 2026 (run `39121981477-1`) : le broker
démarre et le précontrôle s'exécute, mais la publication du semeur échoue et
les quatre lectures restent non prouvées. La réinspection classe une
déconnexion pour erreur de protocole ; la documentation Mosquitto confirme
qu'un plafond `max_keepalive 30` rejette les clients MQTT 3.1.1 par défaut
à 60 secondes. Ce plafond propre à la fixture est donc retiré, sans changer
les ACL. Quatrième lancement le 18 octobre 2026
(run `39145340752-1`) : même échec de publication du semeur avant tout bras,
toujours sans lecture prouvée. Le semis est donc rendu déterministe
(MQTT 3.1.1, identifiant client court explicite, keepalive 30) et ses
échecs sont convertis en causes fixes classifiables, sans relayer stderr
ni secrets. Cinquième lancement le 18 octobre 2026
(run `39160168417-1`) : le semis passe, mais les quatre souscriptions du
précontrôle sortent en code 2. La réinspection filtrée de l'essai scellé
(19 octobre 2026) classe un rejet d'identifiant client par le broker ;
l'outil `mqtt_listen` fixe donc désormais le protocole MQTT 3.1.1, un
préfixe d'identifiant client explicite et un keepalive de 30 secondes,
comme le semeur. Les tentatives échouées restent archivées telles quelles.

Sixième lancement le 19 octobre 2026 (run `39239366068-1`, commit
`6dda69e`) : **les quatre bras sont valides**. Deux cas appariés, F0
(aucune faille) et F1 (une faille), exécutent chacun les bras `rules` puis
`llm` sur un LXC neuf, avec trois souscriptions bornées par bras. En F0, les
deux politiques refusent la lecture privée anonyme et satisfont le contrat
protégé ; en F1, les deux prouvent la lecture anonyme du canari privé frais
et satisfont le contrat vulnérable. Aucun faux positif ni constat non étayé.
Les quatre précontrôles sont valides avec témoin privé prouvé avant et après
la sonde ; `paired_execution_complete` vaut vrai pour les deux cas et
`failures` est vide. Le contrôleur a vérifié **120 fichiers** et deux
archives scellées (empreintes `987de2a5…` et `a1d19027…`). Coûts et durées,
limités aux bras : règles 15,0 s et zéro appel fournisseur ; Qwen 3.8 27B
34,6 s et 31,9 s, deux requêtes, 2 547/982 puis 2 794/1 418 tokens. Le
fournisseur `ollama-umons` et le modèle sont présents au précontrôle.

Ce lancement qualifie l'instrument sur un broker réel ; il ne constitue ni
une campagne confirmatoire, ni une preuve d'avantage du LLM.
L'admission calculée reste `false` (une répétition par posture, métriques
strict-v3 non adoptées), le statut de mesure reste
`evidence_only_not_admitted` et la portée reste une calibration logicielle
avec oracle fourni par l'opérateur. Les preuves complètes restent sur nato
sous `/opt/lance-dev-2/output/mqtt-reference/39239366068-1/`.
