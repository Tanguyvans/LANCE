# Benchmark Commands

## Setup initial (une seule fois)

### 1. Installer les dépendances sur le Mac

```bash
pip install ansible proxmoxer requests passlib
ansible-galaxy collection install community.general
```

### 2. Copier la clé SSH sur Proxmox

```bash
ssh-copy-id root@192.168.1.100
```

### 3. Créer le template Debian avec virt-customize

```bash
# Copier ta clé publique sur Proxmox
cat ~/.ssh/id_ed25519.pub | ssh root@192.168.1.100 "cat > /tmp/bench_key.pub"

# Créer le template (user bench, clé SSH, password, python3, guest agent)
ssh root@192.168.1.100 << 'REMOTE'
wget -q https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2 -O /tmp/debian-12-cloud.qcow2

apt-get install -y libguestfs-tools 2>/dev/null || true

KEY=$(cat /tmp/bench_key.pub)

virt-customize -a /tmp/debian-12-cloud.qcow2 \
  --run-command 'useradd -m -s /bin/bash -G sudo bench' \
  --run-command 'echo "bench ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/bench' \
  --run-command 'mkdir -p /home/bench/.ssh && chmod 700 /home/bench/.ssh' \
  --write "/home/bench/.ssh/authorized_keys:$KEY" \
  --run-command 'chmod 600 /home/bench/.ssh/authorized_keys && chown -R bench:bench /home/bench/.ssh' \
  --run-command 'sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config' \
  --run-command 'echo "bench:benchpass" | chpasswd' \
  --run-command 'apt-get update && apt-get install -y qemu-guest-agent python3' \
  --run-command 'systemctl enable qemu-guest-agent ssh'

qm create 9000 --name tpl-debian --memory 512 --cores 1 \
  --net0 virtio,bridge=vmbr0 --scsihw virtio-scsi-pci
qm set 9000 --scsi0 local-lvm:0,import-from=/tmp/debian-12-cloud.qcow2
qm set 9000 --ide2 local-lvm:cloudinit
qm set 9000 --boot order=scsi0
qm set 9000 --serial0 socket --vga serial0
qm set 9000 --agent enabled=1
qm template 9000

rm -f /tmp/debian-12-cloud.qcow2
echo "Template 9000 ready."
REMOTE
```

### 4. Recréer le template (si besoin)

```bash
ssh root@192.168.1.100 "qm destroy 9000 --purge"
# Puis relancer l'étape 3
```

---

## Utilisation quotidienne

```bash
# Lister les scénarios disponibles
./bench.sh list

# Déployer un scénario
./bench.sh deploy s01

# Voir le statut des VMs
./bench.sh status s01

# Lancer le benchmark LLM
./bench.sh run s01 --model claude-sonnet-4-20250514

# Restaurer l'état initial entre les runs
./bench.sh reset s01

# Détruire toutes les VMs d'un scénario
./bench.sh teardown s01
```

---

## Debug

```bash
# Tester SSH vers une VM
ssh bench@192.168.1.201

# Tester Ansible
ansible -i "192.168.1.201," -m ping -u bench all

# Relancer uniquement l'injection de failles
ANSIBLE_CONFIG=ansible/ansible.cfg \
ansible-playbook ansible/playbooks/inject_vulns.yml \
  -i <(python3 scripts/proxmox_vms.py --bench-dir . inventory scenarios/s01_flat_auth/)

# Voir la config d'une VM
ssh root@192.168.1.100 "qm config 201"

# Détruire manuellement des VMs
for id in 201 202 203 204; do
  ssh root@192.168.1.100 "qm stop $id; qm destroy $id --purge"
done
```
