# Fiabiliser le relais UMONS (autossh + systemd)

Le relais `flint`/`qwen` est un transfert de port SSH lancé **sur la tour `corsair`** :
`100.66.221.22:11435` → `cluster.ig.umons.ac.be:22000` → `192.168.10.12:11434`.
Lancé à la main (`ssh -fN …`), il tombe sans se relancer : si la session SSH
meurt ou la tour redémarre, le harness ne joint plus le modèle et un audit échoue
en phase 1 (« connexion au modèle impossible »).

Ce guide le transforme en **service supervisé** qui se reconnecte seul au boot et
après coupure.

> **Pré-requis incontournable : l'authentification par clé.** Un service ne peut
> pas saisir un mot de passe. L'auth UMONS observée est `keyboard-interactive`
> (mot de passe). Il faut donc d'abord autoriser une **clé SSH** pour `vansnickt`
> sur le cluster. Sans ça, cette procédure ne peut pas fonctionner — ne mets
> jamais de mot de passe dans une commande ni dans un fichier de service.

## 1. Générer une clé dédiée (sur `corsair`)

Sans passphrase, car le service démarre sans intervention. La clé ne sert qu'à ce
tunnel.

```bash
ssh-keygen -t ed25519 -f ~/.ssh/umons_tunnel -N '' -C 'umons-tunnel@corsair'
```

## 2. Autoriser la clé côté UMONS

Dépose la clé publique dans `~/.ssh/authorized_keys` de `vansnickt` sur le
cluster. Si le serveur accepte `publickey` :

```bash
ssh-copy-id -p 22000 -i ~/.ssh/umons_tunnel.pub vansnickt@cluster.ig.umons.ac.be
```

Si `ssh-copy-id` échoue (serveur en `keyboard-interactive` seul), demande à
l'**admin UMONS** d'ajouter la clé, en la **restreignant au seul transfert** vers
le serveur Ollama — c'est une clé sans passphrase, on limite sa portée. Ligne à
mettre dans `authorized_keys` :

```
restrict,permitopen="192.168.10.12:11434",port-forwarding ssh-ed25519 AAAA...umons-tunnel@corsair
```

`restrict` coupe tout (pas de shell, pas de PTY, pas d'agent) puis on ne réautorise
que le port-forwarding, borné par `permitopen` à l'hôte:port du modèle.

**Vérifie l'auth par clé avant d'aller plus loin** (doit ouvrir sans mot de passe) :

```bash
ssh -i ~/.ssh/umons_tunnel -p 22000 -o BatchMode=yes -O check \
  vansnickt@cluster.ig.umons.ac.be 2>/dev/null; \
ssh -i ~/.ssh/umons_tunnel -p 22000 -o BatchMode=yes -N -L 11435:192.168.10.12:11434 \
  vansnickt@cluster.ig.umons.ac.be & sleep 3; \
curl -s --max-time 10 http://127.0.0.1:11435/v1/models | head -c 120; echo; kill %1
```

Si le catalogue remonte **sans** demander de mot de passe, la clé est bonne.

## 3. Installer autossh

```bash
sudo apt-get update && sudo apt-get install -y autossh
```

## 4. Le service systemd

Crée `/etc/systemd/system/umons-tunnel.service` (adapte `User=` si le compte de la
tour n'est pas `tanguy`) :

```ini
[Unit]
Description=UMONS SSH tunnel (relais flint/qwen :11435)
After=network-online.target tailscaled.service
Wants=network-online.target

[Service]
User=tanguy
Environment=AUTOSSH_GATETIME=0
ExecStart=/usr/bin/autossh -M 0 -N -p 22000 \
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -o ExitOnForwardFailure=yes -o ConnectTimeout=10 \
  -o StrictHostKeyChecking=accept-new -o BatchMode=yes \
  -i /home/tanguy/.ssh/umons_tunnel \
  -L 100.66.221.22:11435:192.168.10.12:11434 \
  vansnickt@cluster.ig.umons.ac.be
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Points importants :
- `-M 0` + `ServerAlive*` : autossh s'appuie sur le keepalive SSH (pas de port de
  monitoring séparé) pour détecter une connexion morte.
- `AUTOSSH_GATETIME=0` : autossh ne renonce pas si le tout premier essai échoue
  au boot (tant que Tailscale ou le réseau n'est pas prêt).
- `ExitOnForwardFailure=yes` : si le bind `100.66.221.22:11435` échoue (IP
  Tailscale pas encore montée), SSH sort et systemd réessaie après 10 s.
- Le service **lie l'IP Tailscale** `100.66.221.22` : le relais n'est joignable que
  depuis le tailnet (les instances LANCE), pas depuis l'extérieur.

## 5. Activer et vérifier

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now umons-tunnel.service
systemctl status umons-tunnel.service --no-pager
```

Le port doit écouter, et le catalogue répondre :

```bash
ss -ltnp 'sport = :11435'
curl --fail-with-body --connect-timeout 5 --max-time 15 http://100.66.221.22:11435/v1/models
```

Test de résilience : tue le process, il doit revenir seul en ~10 s.

```bash
sudo systemctl kill umons-tunnel.service ; sleep 12 ; ss -ltnp 'sport = :11435'
```

## 6. Journaux

```bash
journalctl -u umons-tunnel.service -n 100 --no-pager
```

> Ce service remplace la relance manuelle `ssh -fN …` de
> [umons-llm.md](umons-llm.md). Si tu dois repasser en manuel (clé pas encore
> autorisée), la commande interactive reste dans ce guide.
