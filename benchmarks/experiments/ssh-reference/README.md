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
