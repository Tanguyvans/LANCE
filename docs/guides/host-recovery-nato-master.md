# Remise en route de nato-master après réinstallation

`nato-master` est l'hôte Tailscale qui porte les trois instances LANCE
(`main` `/opt/nato-smartcity-iot` :8501, `dev-1` `/opt/lance-dev-1` :8502,
`dev-2` `/opt/lance-dev-2` :8503). Après une réinstallation de l'hôte,
plusieurs **prérequis hôte** ne sont pas rétablis par le déploiement : le
pipeline redéploie alors un scénario et échoue tôt. Cette liste les restaure,
dans l'ordre où ils bloquent le déploiement d'un scénario.

> Chaque prérequis est indépendant : `03_deploy_scenario.yml` échoue
> successivement sur chacun tant qu'il n'est pas réglé.

## 1. Outils système (`nmap`, `ansible`)

Ce sont des **paquets système**, pas des dépendances `requirements.txt` ; le
service les cherche sur son `PATH` via `shutil.which`.

```bash
apt update && apt install -y nmap ansible
systemctl restart lance-dev-1   # (et nato-fastapi / lance-dev-2 au besoin)
```

Voir aussi les prérequis côté hôte maître dans
[`benchmarks/ansible/README.md`](../../benchmarks/ansible/README.md).

## 2. Locale `en_US.UTF-8`

Ansible refuse de démarrer si `en_US.UTF-8` n'est pas généré
(`unsupported locale setting`). Le code force `LANG`/`LC_ALL=en_US.UTF-8` pour le
sous-processus Ansible (`src/agent/core/lifecycle.py`), **même si l'unité systemd
du service tourne sous `C.UTF-8`** — il faut donc générer `en_US.UTF-8` sur
l'hôte quoi qu'il en soit.

```bash
localedef -i en_US -f UTF-8 en_US.UTF-8
LANG=en_US.UTF-8 LC_ALL=en_US.UTF-8 python3 -c 'import locale; locale.setlocale(locale.LC_ALL,""); print("ok")'
```

## 3. Clé SSH nato-master → Proxmox

Ansible pilote le nœud Proxmox par SSH avec `~/.ssh/id_ed25519` (cf.
`inventory.yml`). Si la clé manque :

```bash
ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N ''
ssh-copy-id -i /root/.ssh/id_ed25519.pub root@<PROXMOX_IP>
# vérifier (doit répondre sans mot de passe) :
ssh -i /root/.ssh/id_ed25519 -o BatchMode=yes root@<PROXMOX_IP> hostname
```

## 4. Inventaire — adresse du Proxmox

`inventory.yml` porte un placeholder `<PROXMOX_IP>` dans git ; la vraie valeur
est **locale par instance** (`git update-index --skip-worktree`, copiée depuis
l'instance stable — voir [`development-instances.md`](development-instances.md)).
Renseigner `ansible_host` avec l'IP réelle du Proxmox sur la **stable** ; les
instances dev en héritent au déploiement.

## 5. Ansible Vault

Le déploiement déchiffre `benchmarks/ansible/group_vars/all/vault_master.yml`
avec le mot de passe de `/root/.vault_pass`. Si le fichier manque mais que **tu
as le mot de passe** :

```bash
printf '%s' 'LE_MOT_DE_PASSE' > /root/.vault_pass && chmod 600 /root/.vault_pass
# vérifier :
cd /opt/lance-dev-1 && ansible-vault view benchmarks/ansible/group_vars/all/vault_master.yml \
  --vault-password-file /root/.vault_pass >/dev/null && echo ok
```

### Si le mot de passe du vault est perdu (dernier recours)

> ⚠️ **À ne faire qu'après avoir confirmé le mot de passe irrécupérable** :
> chercher `~/.vault_pass`/`/root/.vault_pass` sur les autres machines, et
> demander à la personne qui a créé le vault (voir l'historique git de
> `vault_master.yml`). Re-chiffrer **détruit irréversiblement** l'ancien coffre.

Portée : le chemin « déployer un scénario » (`03_deploy_scenario.yml`,
`99_teardown.yml`, `inventory.yml`) n'a besoin que de **`vault_proxmox_token`**.
Un vault **minimal** suffit donc à relancer les pentests — mais il **casse les
autres playbooks** (`deploy_master.yml`, `00_proxmox_init.yml`, injection des
clés modèles), qui attendent les sept secrets de
[`vault_master.yml.example`](../../benchmarks/ansible/group_vars/vault_master.yml.example) ;
les repeupler depuis ce template avant de relancer ces playbooks. Les secrets du
**service déjà en route** viennent du `.env` (injecté par `deploy_master`), pas
de ce vault — un vault minimal ne casse donc pas une instance en cours.

1. Régénérer le token API Proxmox (sur le nœud Proxmox ; **révoque l'ancien**,
   ce qui casse tout autre consommateur de ce token) :
   ```bash
   pveum user token remove ansible@pam benchmark
   pveum user token add ansible@pam benchmark --privsep 0   # noter la value
   ```
2. Choisir un nouveau mot de passe et construire le vault minimal (sur nato-master) :
   ```bash
   read -rsp 'Nouveau mot de passe Vault : ' VP && printf '%s' "$VP" > /root/.vault_pass && chmod 600 /root/.vault_pass && unset VP && echo
   cd /opt/lance-dev-1 && umask 077
   read -rsp 'Value du token Proxmox : ' TK && printf 'vault_proxmox_token: "%s"\n' "$TK" > /tmp/vp.yml && unset TK && echo
   ansible-vault encrypt /tmp/vp.yml --vault-password-file /root/.vault_pass \
     --output benchmarks/ansible/group_vars/all/vault_master.yml
   shred -u /tmp/vp.yml 2>/dev/null; rm -f /tmp/vp.yml
   ```

## 6. Modèle / fournisseur UMONS

Les modèles `ollama-umons` (`qwen3.8:27b`, `gemma4:26b`) passent par un tunnel
SSH qui **ne tourne plus sur pve-nato mais sur la tour `corsair`** (seule machine
à encore joindre le cluster UMONS). Procédure complète — tunnel **et** repointage
du fournisseur dans les trois bases — dans [`umons-llm.md`](umons-llm.md). Pour
valider sans l'UMONS, un modèle `local` (`qwen3-14b-32k`, sur la tour
`100.66.221.22:11434`) suffit.

## À rendre durable (TODO code / déploiement, hors de cette doc)

- Un **preflight** au démarrage ou dans `scripts/deployment/deploy-instance.sh`
  qui vérifie `nmap`, `ansible-playbook` et la présence du locale `en_US.UTF-8`,
  et échoue avec un message clair (généraliser le `which` déjà présent dans
  `src/benchmark/policy_pair_runner.py`).
- Un **service supervisé** (p. ex. `autossh`) pour le tunnel UMONS sur la tour,
  à la place du lancement manuel.
