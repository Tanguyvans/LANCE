# Proxmox Benchmark Server

## Hardware

- **Machine** : BMAX mini PC
- **SSD** : 128 Go
- **BIOS** : Delete pour entrer, CSM enabled, Secure Boot disabled

## Proxmox

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

## Template VM (ID 9000)

Créé avec `virt-customize` sur l'image Debian 12 cloud.
Contient directement dans l'image :

- User `bench` avec sudo NOPASSWD
- Clé SSH de l'opérateur dans `~bench/.ssh/authorized_keys`
- `PasswordAuthentication yes` dans sshd_config
- Password `benchpass` pour le user bench
- `python3` et `qemu-guest-agent` pré-installés

## Post-install effectué

- [x] Repos enterprise désactivés (`.sources` → `Enabled: no`)
- [x] Repo no-subscription ajouté
- [x] Système mis à jour
- [x] API token créé
- [x] `libguestfs-tools` installé (pour `virt-customize`)
- [x] Template Debian 12 créé avec virt-customize
- [x] Clé SSH copiée sur Proxmox (`ssh-copy-id`)
- [x] Scénario S01 déployé et validé (4 VMs, Ansible OK)

## Notes

- L'IP devra être changée au lab (`/etc/network/interfaces`)
- Proxmox 9 utilise `.sources` (format deb822) au lieu de `.list`
- Cloud-init `cicustom` ne fonctionne pas sur Proxmox 9 → utiliser `virt-customize` pour pré-configurer l'image
- Boot USB : UEFI mode, flashé avec Balena Etcher, touche Delete pour le BIOS
