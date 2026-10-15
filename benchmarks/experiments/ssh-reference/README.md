# Première calibration SSH V2

Le premier incrément logiciel de `s_ssh_identifiants` fournit un contrat public,
un adaptateur D1 pour l'exécuteur existant et un évaluateur de preuves hors ligne.
L'[exemple public](briefing.example.json) utilise une adresse de documentation ;
il ne désigne aucun laboratoire et ne déclenche aucun déploiement.

La [référence d'utilisation et les limites](../../../docs/benchmark/agent-vs-automation-cli.md#calibration-ssh-v2)
décrivent le branchement, l'oracle privé, le verdict, l'archivage et le travail
restant. Le [plan de recherche](../../../research/2026-10-12-recentrage-corpus/README.md)
conserve les hypothèses et la sélection des expériences.

Depuis la racine, les tests de qualification logicielle se lancent avec :

```bash
.venv/bin/python -m pytest -q tests/test_ssh_reference.py
```

Ces tests utilisent le vrai adaptateur `ssh_exec` et la frontière d'exécution
commune, avec les entrées/sorties du processus SSH simulées. Ils ne constituent
ni un essai sur un serveur SSH réel ni une mesure de performance d'un LLM.
Le contrôleur `benchmarks.experiments.ssh_reference_live` et sa politique LLM
bornée permettent maintenant un pilote OpenSSH réel sur nato, avec deux postures
et quatre bras. Le [guide](../../../docs/benchmark/agent-vs-automation-cli.md#premier-pilote-ssh-réel-sur-dev2)
décrit le lancement **manuel** sur `dev/2`, l'isolation et les preuves conservées
localement sur nato. Les tests simulés ne prouvent pas l'exécution de ce pilote.
Le gel expérimental et le pipeline A1 complet restent distincts. Les manifestes
et résultats de la campagne historique ne sont pas modifiés.

Validation logicielle du 15 octobre 2026 : les 32 cas de ce module passent ; la
suite complète `python -m pytest -q tests model_training/tests` termine avec
**3 885 tests réussis, un ignoré et deux avertissements de dépréciation de
fixtures**. Les tests de précontrôle ouvrant un serveur local ont été exécutés
avec l'autorisation d'écoute sur `127.0.0.1`. Le contrôle des ressources gelées du
pilote passe sans modifier son manifeste. Cette validation ne constitue pas un
résultat expérimental sur la plus-value d'un LLM.

## État de l'exécution réelle

Le pilote utilise exclusivement **Qwen `qwen3.8:27b` via `ollama-umons`**.
Le workflow et le contrôleur refusent un autre fournisseur ou modèle. Une panne
UMONS bloque l'essai ; elle ne déclenche aucun repli vers MiniMax. La sélection
erronée du lancement historique ci-dessous n'a produit aucun appel modèle :
la préparation s'est arrêtée avant les quatre bras.

La [CI du commit `6691af4`](https://github.com/Tanguyvans/LANCE/actions/runs/38745281005)
a réussi : 3 903 tests, deux ignorés, deux avertissements ; le déploiement
dev/2 a annoncé ce même commit et le verrou actif. Le
[lancement manuel](https://github.com/Tanguyvans/LANCE/actions/runs/38745339418)
du 15 octobre 2026 s'est arrêté avant toute connexion SSH : le binaire Docker
est absent de `nato-master`. Aucun résultat script/LLM n'a donc été mesuré.
La collection de préparation reste sur nato sous
`/opt/lance-dev-2/output/ssh-reference/38745339418-1/`.

La fixture utilise désormais le **LXC natif de pve-nato** via Ansible et le
template Debian 9000 déjà présents dans le laboratoire. Docker n'est plus un
prérequis du pilote ; aucun moteur temporaire ni service système n'a été installé.
Le contrôleur vérifie les outils et le catalogue Qwen avant toute allocation,
refuse une autre charge active sur vmbr1 et exige la propriété du LXC avant de
le détruire. Le code de nettoyage Docker reste réservé aux anciennes tentatives.
La CI et le déploiement de l'adaptation native `9bfc6b1` ont réussi. Son
[premier lancement](https://github.com/Tanguyvans/LANCE/actions/runs/38758419755)
a vérifié le catalogue Qwen depuis nato, puis s'est arrêté avant les bras :
le serveur OpenSSH n'est pas devenu joignable. Les 32 fichiers de la tentative
ont été scellés et vérifiés sous
`/opt/lance-dev-2/output/ssh-reference/38758419755-1/` ; ils ne constituent pas
quatre essais exécutés. L'inspection filtrée des erreurs est autorisée depuis
le 15 octobre 2026 ; les preuves complètes restent sur nato.

Le lancement de la fixture transmet maintenant un `argv[0]` absolu à OpenSSH.
Un test avec le vrai binaire, une configuration volontairement absente et aucun
port ouvert reproduit le refus avant correction et atteint la lecture de
configuration après correction. Cette validation logicielle ne démontre pas
encore que la préparation réelle et les quatre bras ont abouti.

Le [lancement corrigé `50fc5a7`](https://github.com/Tanguyvans/LANCE/actions/runs/38767219662)
a exécuté les quatre bras et vérifié **120 fichiers**, avec deux archives de
paire. Les quatre précontrôles initiaux étaient valides ; trois bras sont en
non-succès et le LLM obtient une preuve dans le cas vulnérable. Ces résultats
restent intacts sous `/opt/lance-dev-2/output/ssh-reference/38767219662-1/`.
Les accès légitimes qui échouent immédiatement après les refus motivent un
diagnostic de la protection temporaire par source, avant toute interprétation
comparative. Le précontrôle exige désormais que le témoin fonctionne également
après le dictionnaire, et la fixture statique désactive `PerSourcePenalties`.
La qualification de cette correction exige un nouveau lancement ; les verdicts
anciens ne sont ni recalculés ni remplacés.
