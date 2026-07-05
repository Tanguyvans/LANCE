# Proxmox Benchmark Server

## Hardware

- **Machine** : BMAX mini PC
- **SSD** : 128 Go
- **BIOS** : Delete pour entrer, CSM enabled, Secure Boot disabled

## Proxmox

- **Version** : Proxmox VE 9.1-1 (Debian Trixie)
- **Nœud Proxmox** : `pve-benchmark` (valeur `proxmox_node` dans `group_vars/all/main.yml`)
- **Interface** : nic0 (management)
- **IP** : `<PROXMOX_IP>/24`
- **Gateway** : `<GATEWAY_IP>`
- **DNS** : 8.8.8.8
- **Accès web** : `https://<PROXMOX_IP>:8006`
- **User** : root

## API Token (Ansible)

- **Utilisateur** : `ansible@pam` (créé par `00_proxmox_init.yml`, rôle `BenchmarkRole`)
- **Token ID** : `ansible@pam!benchmark` (`proxmox_api_user` + `proxmox_api_token_id` dans `inventory.yml`)
- **Token Secret** : `<PROXMOX_API_TOKEN_SECRET>`

## Template Debian (ID 9000)

Conteneur **LXC Debian 13** créé par `01_create_templates.yml` via `pct create`
(template `debian-13-standard` récupéré avec `pveam`). Pas de `virt-customize`.
La configuration de base du template :

- Connexion **root** (mot de passe `benchmark`)
- Clé SSH de l'opérateur dans `/root/.ssh/authorized_keys`
- Paquets préinstallés : `openssh-server`, `python3`, `curl`, `wget`

> `PasswordAuthentication yes` n'est **pas** activé dans le template : il est
> appliqué par scénario lors de l'injection (`04_inject_vulns.yml`).

Le template OpenWrt (KVM, ID 9010) est construit séparément par `02_config_openwrt.yml`.

## Post-install effectué

- [x] Repos enterprise désactivés (`.sources` → `Enabled: no`)
- [x] Repo no-subscription ajouté
- [x] Système mis à jour
- [x] Utilisateur `ansible@pam` + API token créés (`00_proxmox_init.yml`)
- [x] Template Debian 13 LXC créé avec `pct` / `pveam`
- [x] Template OpenWrt (9010) configuré (`02_config_openwrt.yml`)
- [x] Clé SSH copiée sur Proxmox (`ssh-copy-id`)
- [x] Scénario S01 déployé et validé (4 VMs, Ansible OK)

## Notes

- L'IP devra être changée au lab (`/etc/network/interfaces`)
- Proxmox 9 utilise `.sources` (format deb822) au lieu de `.list`
- Les services Linux tournent dans des conteneurs LXC (`pct`) clonés depuis le template 9000 ; seul le routeur OpenWrt est une VM KVM (`qm`)
- Boot USB : UEFI mode, flashé avec Balena Etcher, touche Delete pour le BIOS
