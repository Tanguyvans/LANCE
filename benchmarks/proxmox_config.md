---
name: Proxmox Benchmark Server Config
description: Configuration du mini PC BMAX avec Proxmox VE pour le benchmark IoT
type: reference
---

# Proxmox Benchmark Server

## Hardware
- **Machine** : BMAX mini PC
- **SSD** : 128 Go
- **BIOS** : Delete pour entrer, CSM enabled, Secure Boot disabled

## Proxmox Install
- **Version** : Proxmox VE 9.1-1 (Debian Trixie)
- **Hostname** : benchmark.local
- **Interface** : nic0 (management)
- **IP (maison)** : 192.168.1.100/24
- **Gateway (maison)** : 192.168.1.1
- **DNS** : 8.8.8.8
- **Accès web** : https://192.168.1.100:8006
- **User** : root

## API Token (Ansible)
- **Token ID** : `benchmark@pam!benchmark`
- **Token Secret** : `0d383b4a-1644-4eb3-81cd-6d92c0ada02a`
- **User** : benchmark@pam (rôle PVEAdmin)

## Templates VM
| ID | Nom | Base | Status |
|---|---|---|---|
| 9000 | tpl-debian | Debian 12 Bookworm cloud-init (genericcloud-amd64) | OK |

## Cloud-Init Config
- **Snippet** : `/var/lib/vz/snippets/userconfig.yml`
- Active `ssh_pwauth: true` pour autoriser le login par mot de passe
- User par défaut : `bench` / `benchpass`

## Post-install effectué
- [x] Repo enterprise désactivé (`pve-enterprise.sources`, `ceph.sources` → `Enabled: no`)
- [x] Repo no-subscription ajouté (`pve-no-subscription.list`)
- [x] `apt update && apt full-upgrade -y` (74 packages mis à jour)
- [x] API token créé pour Ansible
- [x] Template Debian 12 cloud-init créé (ID 9000)
- [x] Test clone → VM 200 (test-mqtt) → SSH OK

## Test validé
```
Template 9000 (tpl-debian)
    → clone → VM 200 (test-mqtt)
        → IP: 192.168.1.201/24
        → SSH: bench@192.168.1.201 (password: benchpass)
        → Status: OK
```

## Notes
- L'IP devra être changée au lab (fichier `/etc/network/interfaces`)
- Boot USB : UEFI mode, flashé avec Balena Etcher
- Clé BIOS : Delete au démarrage
- Proxmox 9 utilise `.sources` (format deb822) au lieu de `.list`
- VM de test (200) à détruire après validation : `qm stop 200 && qm destroy 200`

## Prochaines étapes
- [ ] Tester Ansible depuis le Mac (`ansible -m ping`)
- [ ] Créer template MikroTik CHR
- [ ] Créer template OpenWrt x86
- [ ] Coder `bench.sh` et les rôles Ansible
- [ ] Déployer le premier scénario (S01)
