# Benchmark Commands

## Setup initial (une seule fois)

### 1. Installer les dépendances

```bash
pip install ansible proxmoxer requests passlib
ansible-galaxy collection install community.general
```

### 2. Copier la clé SSH sur Proxmox

```bash
ssh-copy-id root@192.168.88.100
```

### 3. Initialiser Proxmox (bridge, user ansible, token API)

```bash
cd benchmarks/ansible
ansible-playbook -i inventory.yml playbooks/00_proxmox_init.yml
```

Sauvegarder le token affiché dans `group_vars/vault.yml` :

```bash
ansible-vault encrypt_string 'VOTRE_TOKEN' --name vault_proxmox_token >> group_vars/vault.yml
```

### 4. Créer les templates VM

```bash
ansible-playbook -i inventory.yml playbooks/01_create_templates.yml --ask-vault-pass
ansible-playbook -i inventory.yml playbooks/02_config_openwrt.yml --ask-vault-pass
```

Crée :
- `9000` — LXC Debian 13 (base pour tous les services Linux)
- `9010` — KVM OpenWrt 23.05 configuré (LAN=192.168.100.1, NAT actif)

---

## Utilisation quotidienne

```bash
cd benchmarks/ansible

# Déployer un scénario (exemple : scénario 2)
ansible-playbook -i inventory.yml playbooks/03_deploy_scenario.yml --ask-vault-pass --extra-vars "scenario_id=2"
ansible-playbook -i inventory.yml playbooks/04_inject_vulns.yml --ask-vault-pass --extra-vars "scenario_id=2"
ansible-playbook -i inventory.yml playbooks/05_populate_services.yml --ask-vault-pass --extra-vars "scenario_id=2"

# Vérifier que les vulnérabilités sont actives
ansible-playbook -i inventory.yml playbooks/06_verify.yml --ask-vault-pass --extra-vars "scenario_id=2"

# Détruire toutes les VMs du scénario
ansible-playbook -i inventory.yml playbooks/99_teardown.yml --ask-vault-pass --extra-vars "scenario_id=2"
```

Ou via les wrappers :

```bash
cd benchmarks/ansible
./deploy.sh 2        # équivalent 03 + 04 + 05
./verify.sh 2        # équivalent 06
```

---

## Debug

```bash
# Tester SSH vers une VM (exemple : s2-jump, IP 192.168.100.15)
ssh admin@192.168.100.15

# Tester la connectivité Ansible vers Proxmox
ansible -i benchmarks/ansible/inventory.yml proxmox -m ping

# Relancer uniquement l'injection de failles
ansible-playbook -i benchmarks/ansible/inventory.yml benchmarks/ansible/playbooks/04_inject_vulns.yml --ask-vault-pass --extra-vars "scenario_id=2"

# Voir la config d'une VM depuis Proxmox
ssh root@192.168.88.100 "pct config 112"
ssh root@192.168.88.100 "qm config 110"

# Lister les VMs en cours sur Proxmox
ssh root@192.168.88.100 "qm list; pct list"

# Détruire manuellement un range de VMs (scénario 2 : 110-119)
ssh root@192.168.88.100 "for id in \$(seq 110 119); do pct stop \$id 2>/dev/null; pct destroy \$id 2>/dev/null; qm stop \$id 2>/dev/null; qm destroy \$id --purge 2>/dev/null; done"
```
