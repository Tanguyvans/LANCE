# Utiliser le LLM UMONS

## 1. Se connecter et choisir un modèle

1. Se connecter au réseau **Tailscale autorisé**.
2. Ouvrir [Main](http://100.103.253.86:8501), [Dev 1](http://100.103.253.86:8502) ou [Dev 2](http://100.103.253.86:8503).
3. Dans **Model global**, choisir un modèle du groupe **`ollama-umons`**.
4. Si le mode **Multi-modèle** est actif, vérifier aussi les modèles de chaque phase.

| Réglage | Valeur |
| --- | --- |
| Fournisseur / type | `ollama-umons` / `local` |
| URL de base | `http://100.76.206.65:11435/v1` |
| Qwen | `qwen3.8:27b` |
| Gemma | `gemma4:26b-a4b-it-q4_K_M` |

Valeurs vérifiées le **1er octobre 2026**. Le catalogue ci-dessous fait foi si les modèles changent.

Le relais SSH en aval de pve-nato a été identifié et rétabli le 4 octobre 2026 ;
sa commande est conservée dans le dépannage ci-dessous. Aucun service de démarrage
automatique n'a été identifié ni installé. L'administration de la machine GPU
en aval reste à confirmer avec l'administrateur UMONS.

> **« Disponible » ne prouve pas que le serveur répond.** Le bouton d’actualisation recharge les modèles enregistrés dans LANCE ; il ne teste pas UMONS.

## 2. Tester la connexion

Dans un terminal avec `curl` et accès Tailscale. Pour tester le trajet réellement utilisé par LANCE, exécuter aussi ces commandes **sur nato-master**.

**Lister les modèles :**

```bash
curl --fail-with-body --show-error --connect-timeout 5 --max-time 15 \
  http://100.76.206.65:11435/v1/models
```

Résultat attendu : un JSON contenant `data` et les identifiants des modèles.

**Tester une réponse de Qwen, sans lancer d’audit :**

```bash
curl --fail-with-body --show-error --no-buffer \
  --connect-timeout 5 --max-time 180 \
  http://100.76.206.65:11435/v1/chat/completions \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "model": "qwen3.8:27b",
    "messages": [{"role": "user", "content": "Réponds uniquement OK."}],
    "max_tokens": 128,
    "stream": true
  }'
```

- Résultat attendu : du texte dans `choices[].delta.content`, puis la fin du flux `data:`.
- Pour tester Gemma : remplacer l’identifiant dans `model` par celui du catalogue.
- Le premier appel peut charger le modèle et prendre plus de temps. Un catalogue accessible ne garantit pas une génération réussie.

## 3. Si ça ne répond pas

| Problème | Que faire ? |
| --- | --- |
| Connexion refusée ou expirée | Vérifier Tailscale, puis le relais sur **pve-nato** |
| Modèle introuvable | Copier son identifiant exact depuis `/v1/models` |
| Catalogue accessible, réponse bloquée | Faire vérifier la charge GPU, la file d’attente et les journaux du serveur |
| Appel direct réussi, LANCE en erreur | Vérifier fournisseur, URL et modèles par phase ; consulter les événements du run |

```bash
tailscale status
tailscale ping 100.76.206.65
```

**Relais en panne :** passer de Qwen à Gemma sur ce même relais ne suffit pas. Choisir un autre fournisseur opérationnel et vérifier les choix par phase. Cela ne reprend pas automatiquement un run en échec.

**Pour la remise en route du pont identifié, suivre le tunnel SSH dans le dépannage avancé ci-dessous. Le démarrage automatique reste à configurer.**

<details>
<summary><strong>Administration — ajouter ou modifier un modèle</strong></summary>

1. Ouvrir **⚙️ Modèles** sur l’instance concernée.
2. Vérifier le provider et son URL avec le tableau en haut du guide.
3. Ajouter l’identifiant exact du modèle, choisir `ollama-umons` et cocher **Activé**.
4. Actualiser le sélecteur.

| À savoir | Conséquence |
| --- | --- |
| La clé du gestionnaire sert uniquement aux modifications de providers | Modifier les modèles exige une [session administrateur](admin-session.md) valide dans le navigateur, ou un client API autorisé avec un jeton Bearer |
| Le dashboard n’a plus de formulaire de connexion à cette session | Saisir la clé du provider ne crée pas de session ; demander à l’administrateur si nécessaire |
| Les registres Main / Dev 1 / Dev 2 sont séparés | Répéter les réglages sur les instances voulues |
| Ajouter une entrée n’installe pas le modèle sur UMONS | L’administrateur doit le rendre disponible côté serveur |

Voir les [fournisseurs](provider-auth.md) et les [instances de développement](development-instances.md).

</details>

<details>
<summary><strong>Dépannage avancé — relais et serveur Ollama</strong></summary>

**Trajet :** navigateur → LANCE sur `nato-master` (`100.103.253.86`) → point d’accès sur `pve-nato` (`100.76.206.65:11435`) → serveur UMONS à confirmer.

Le tunnel SSH a été identifié et rétabli le 4 octobre 2026 (procédure ci-dessous). Son serveur de destination est en aval du cluster UMONS ; aucun accès d'administration au serveur GPU n'a été établi. Le homelab personnel est hors périmètre.

### Tunnel SSH identifié le 4 octobre 2026

Le relais observé est un transfert local SSH lancé sur **pve-nato** :
`100.76.206.65:11435` → `cluster.ig.umons.ac.be:22000` →
`192.168.10.12:11434`. L'historique de l'administrateur et la trace de connexion
ont identifié ce trajet. Après son rétablissement, le catalogue a exposé
`qwen3.8:27b` et une génération minimale a renvoyé `OK` le 4 octobre 2026.
Cela confirme l'accès au modèle, pas la réussite d'un audit complet.

Si le port n'écoute plus, se connecter à **pve-nato** avec le compte administrateur
prévu, confirmer son identité et vérifier `ss -ltnp 'sport = :11435'` avant de
relancer le tunnel. Utiliser son compte UMONS autorisé :

```bash
UMONS_USER='votre_compte_umons'
ssh -fN -p 22000 \
  -o ConnectTimeout=10 \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=3 \
  -L 100.76.206.65:11435:192.168.10.12:11434 \
  "$UMONS_USER@cluster.ig.umons.ac.be"
```

L'authentification observée est interactive (`keyboard-interactive`). `-f`
place SSH en arrière-plan **après** authentification ; `-N` n'exécute aucune
commande distante. Aucun `nohup` supplémentaire n'est nécessaire. Si l'invite
ne revient pas, interrompre cette tentative puis ajouter `-v` pour voir l'étape
bloquante. Refaire le catalogue et une génération une fois le tunnel établi.
Voir le [manuel OpenSSH](https://man.openbsd.org/ssh).

Cette commande ne configure pas de démarrage au boot ni de reconnexion après
la fin du processus. Aucun service automatique n'a été identifié par la
recherche de noms effectuée. Une exploitation sans intervention demande une
méthode d'authentification autorisée adaptée et un service supervisé ; ne pas
placer un mot de passe dans une commande ou un fichier de service.

### Sur pve-nato, avec un compte administrateur autorisé

Identifier la machine et le processus qui écoute :

```bash
hostname
ip -o -4 addr show
sudo ss -ltnp 'sport = :11435'
systemctl list-units --all --type=service --no-pager | grep -Ei 'ollama|umons|tunnel|relay'
```

Confirmer l’adresse `100.76.206.65`. La recherche par nom peut manquer un service : utiliser aussi le PID indiqué par `ss`.

Remplacer le nom ci-dessous par **le service réellement identifié** :

```bash
RELAY_SERVICE='REMPLACER_PAR_LE_SERVICE_IDENTIFIE.service'
sudo systemctl status "$RELAY_SERVICE" --no-pager
sudo systemctl cat "$RELAY_SERVICE"
sudo journalctl -u "$RELAY_SERVICE" -n 100 --no-pager
```

Retirer les secrets des sorties avant partage. Si la configuration est correcte et qu’aucune exécution n’utilise le relais, l’administrateur peut le relancer :

```bash
sudo systemctl restart "$RELAY_SERVICE"
```

Refaire ensuite les deux tests de connexion. Redémarrer LANCE ne répare pas le relais.

### Sur le serveur Ollama confirmé

```bash
ollama list    # modèles installés
ollama ps      # modèles chargés
nvidia-smi     # si GPU NVIDIA et outil disponible
```

**Uniquement si l’installation utilise le service systemd `ollama` :**

```bash
sudo systemctl status ollama --no-pager
sudo journalctl -u ollama -n 100 --no-pager
# Après vérification qu’aucun travail en cours ne sera interrompu :
sudo systemctl restart ollama
```

- Un cluster peut utiliser un job GPU ou un conteneur : respecter son mode d’exploitation.
- Installer un modèle avec `ollama pull <identifiant>` relève de l’administrateur UMONS.
- Pour une erreur liée aux outils, voir la [compatibilité UMONS](provider-auth.md#dialogue-avec-les-outils).

</details>

<details>
<summary>Vérifications et sources</summary>

Le 1er octobre 2026 : catalogue distant, configuration du provider sur Main et identité Tailscale vérifiés en lecture seule. Aucun redémarrage, appel de génération ni audit effectué pendant la rédaction.

Sources officielles consultées à cette date : [API compatible OpenAI](https://docs.ollama.com/api/openai-compatibility), [CLI Ollama](https://docs.ollama.com/cli), [exploitation](https://docs.ollama.com/faq).

Code de référence : `src/api/routes/providers.py`, `src/api/routes/models.py`, `src/static/app.js` et `src/agent/provider.py`.

</details>
