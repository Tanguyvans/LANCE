# LLM UMONS : connexion, modèles et dépannage

## Point d’entrée

Ce guide décrit l’accès utilisé par LANCE, le choix d’un modèle et les vérifications
à faire si les appels échouent. Il concerne **nato / pve-nato**, pas le homelab personnel.

Configuration vérifiée en lecture seule le **1er octobre 2026** :

| Élément | Valeur |
| --- | --- |
| Fournisseur LANCE | `ollama-umons` |
| Type | `local` (API compatible OpenAI) |
| URL de base | `http://100.76.206.65:11435/v1` |
| Machine du point d’accès Tailscale | `pve-nato` (`100.76.206.65`) |
| Serveur de l’application LANCE | `nato-master` (`100.103.253.86`) |
| Modèle par défaut enregistré | `qwen3.8:27b` |
| Autre modèle exposé lors de la vérification | `gemma4:26b-a4b-it-q4_K_M` |

Le navigateur communique avec LANCE ; **le serveur LANCE** appelle ensuite le
point d’accès UMONS. Un test réussi depuis un ordinateur personnel ne prouve donc
pas que l’accès fonctionne depuis nato-master. Les ports 8501/8502/8503 servent
les interfaces LANCE ; le port 11435 sert l’API des modèles.

La connexion en aval de pve-nato (tunnel, machine GPU, service ou allocation de
cluster) n’a pas pu être inspectée : SSH a refusé la clé du poste lors de cette
vérification. Ne pas supposer que le processus Ollama tourne sur pve-nato lui-même.
Les noms du service de relais et de la machine GPU restent à confirmer avec
l’administrateur avant de donner une commande exacte de redémarrage.

## Choisir un modèle dans LANCE

1. Ouvrir l’instance voulue : [Main](http://100.103.253.86:8501),
   [Dev 1](http://100.103.253.86:8502) ou [Dev 2](http://100.103.253.86:8503).
2. Dans **Model global**, sélectionner le modèle du groupe `ollama-umons`.
   Son libellé peut être lisible (« Qwen 3.8 27B — UMONS »), mais son identifiant
   technique doit correspondre exactement à celui renvoyé par `/v1/models` :
   ce catalogue fait foi, pas le libellé affiché.
3. Si **Mode Multi-modèle (Expert)** est activé, vérifier également les choix
   propres aux phases : ils peuvent remplacer le modèle global.
4. Pour ajouter ou corriger une entrée, ouvrir **⚙️ Modèles**. Dans les providers,
   vérifier le nom `ollama-umons`, le type `local` et l’URL ci-dessus. Ajouter le
   modèle avec son identifiant exact, ce fournisseur, puis cocher **Activé**.
   Les écritures nécessitent une authentification administrateur.
   **Attention :** la clé saisie dans le gestionnaire n’est envoyée que pour
   ajouter ou modifier un provider. Pour modifier les modèles dans l’interface,
   il faut une [session administrateur valide](admin-session.md) dans ce navigateur ;
   saisir cette clé ne crée pas la session. Il n’existe actuellement plus de
   formulaire de connexion à cette session dans le dashboard. Sans session,
   utiliser l’API avec `Authorization: Bearer <LANCE_ADMIN_TOKEN>` via un client
   autorisé, ou demander à l’administrateur de configurer les entrées.
5. Recharger les choix avec le bouton d’actualisation à côté du filtre de modèles.

**Actualiser relit le registre LANCE**, pas le catalogue distant Ollama.
Le statut de disponibilité du sélecteur dépend de la configuration du fournisseur
et de sa clé éventuelle ; ce n’est pas une sonde réseau. Une entrée peut rester
sélectionnable pendant une panne. En particulier, sans `api_key_env` configuré
pour `ollama-umons`, le sélecteur le considère disponible sans tester le serveur.
Ajouter un modèle dans LANCE ne l’installe pas
sur le serveur UMONS.

Les bases de Main, Dev 1 et Dev 2 sont séparées. Une modification du registre sur
une instance ne se réplique pas automatiquement sur les autres ; voir les
[instances de développement](development-instances.md).

## Vérifier la connexion sans lancer d’audit

Commandes à exécuter dans un terminal avec accès au réseau Tailscale autorisé.
Les exemples utilisent `curl` et `python3`. Pour vérifier le chemin réel de LANCE,
les exécuter aussi **sur nato-master**, avec un compte SSH autorisé.

### 1. Vérifier le réseau et le catalogue distant

```bash
tailscale status
tailscale ping 100.76.206.65

UMONS_BASE='http://100.76.206.65:11435/v1'
curl --fail-with-body --show-error --connect-timeout 5 --max-time 15 \
  "$UMONS_BASE/models"
```

Un résultat HTTP 200 contenant `data` confirme l’accès au catalogue. Pour afficher
uniquement les identifiants :

```bash
curl --fail-with-body --silent --show-error --connect-timeout 5 --max-time 15 \
  "$UMONS_BASE/models" \
  | python3 -c 'import json,sys; print("\n".join(m["id"] for m in json.load(sys.stdin)["data"]))'
```

### 2. Faire un petit appel de génération

Ce test utilise le modèle et peut charger ses poids en mémoire ; il ne lance
aucun audit. Copier un identifiant du catalogue, sans remplacer arbitrairement
sa version ou sa quantification. Les variables `UMONS_BASE` et `UMONS_MODEL`
doivent être définies dans le même terminal. Dans le bloc ci-dessous, Python
construit le JSON et le transmet directement à `curl` ; copier le bloc entier.

```bash
UMONS_MODEL='qwen3.8:27b'
python3 - "$UMONS_MODEL" <<'PY' | curl --fail-with-body --show-error --no-buffer \
  --connect-timeout 5 --max-time 180 \
  "$UMONS_BASE/chat/completions" \
  -H 'Content-Type: application/json' --data-binary @-
import json, sys
print(json.dumps({
    'model': sys.argv[1],
    'messages': [{'role': 'user', 'content': 'Réponds uniquement OK.'}],
    'max_tokens': 128,
    'stream': True,
}))
PY
```

La réponse arrive sous forme de lignes `data:`. Chercher du contenu dans
`choices[].delta.content` puis la fin du flux. HTTP 200 ou un catalogue valide
ne suffit pas à prouver qu’une génération a réussi. Le premier appel peut être
plus lent après déchargement du modèle. Un dépassement de 180 secondes ne
permet pas, à lui seul, de distinguer chargement lent, file d’attente et panne.

Pour essayer Gemma, remplacer `UMONS_MODEL` par `gemma4:26b-a4b-it-q4_K_M`
si cet identifiant figure toujours dans le catalogue, puis refaire le test.

### 3. Comparer avec la configuration LANCE

```bash
LANCE_BASE='http://100.103.253.86:8501'  # 8502 pour Dev 1, 8503 pour Dev 2
curl --fail-with-body --silent --show-error --max-time 15 "$LANCE_BASE/api/providers" \
  | python3 -c 'import json,sys; print(json.dumps([p for p in json.load(sys.stdin)["providers"] if p["name"] == "ollama-umons"], indent=2))'
curl --fail-with-body --show-error --max-time 15 "$LANCE_BASE/api/models?refresh=true"
```

Si la génération directe réussit mais pas LANCE, comparer l’URL, l’identifiant
et le fournisseur sélectionnés, y compris ceux des phases. Consulter ensuite
les événements du run et les journaux de l’instance concernée.

## Si le point d’accès est indisponible

| Symptôme | Vérification suivante |
| --- | --- |
| Tailscale ne voit pas pve-nato | Connexion au bon réseau, état de pve-nato et droits d’accès |
| Connexion refusée sur 11435 | Processus qui écoute sur pve-nato (relais ou service, pas forcément Ollama), à identifier avec `ss` |
| Connexion expirée | Routage, règles réseau, relais et accès à sa destination |
| HTTP 404 sur `/v1/models` | URL/port du service et compatibilité OpenAI |
| Modèle introuvable | Identifiant exact dans le catalogue, puis entrée du registre LANCE |
| Catalogue accessible, génération bloquée | Charge GPU, modèle chargé, file d’attente et journaux en aval |
| Appel direct réussi, LANCE en erreur | Configuration de l’instance et historique d’outils ; voir [compatibilité UMONS](provider-auth.md#dialogue-avec-les-outils) |

### Sur pve-nato : identifier le relais avant de le relancer

Avec un accès SSH administrateur autorisé à **pve-nato** :

```bash
hostname
ip -o -4 addr show
sudo ss -ltnp 'sport = :11435'
systemctl list-units --all --type=service --no-pager | grep -Ei 'ollama|umons|tunnel|relay'
```

Vérifier l’identité pve-nato et l’adresse `100.76.206.65` avant intervention.
La recherche par nom n’est pas exhaustive : partir aussi du PID affiché par `ss`.
Après identification du service réel, remplacer la valeur ci-dessous :

```bash
RELAY_SERVICE='REMPLACER_PAR_LE_SERVICE_IDENTIFIE.service'
sudo systemctl status "$RELAY_SERVICE" --no-pager
sudo systemctl cat "$RELAY_SERVICE"
sudo journalctl -u "$RELAY_SERVICE" -n 100 --no-pager
```

Ces sorties peuvent contenir des détails de connexion : retirer tout secret
avant de les partager. Ne pas créer un nouveau tunnel au hasard sur le même port.
Si le service est bien celui du relais, sa configuration est correcte et aucune
exécution ne l’utilise, l’administrateur peut le relancer :

```bash
sudo systemctl restart "$RELAY_SERVICE"
```

Refaire ensuite le catalogue **et** la génération, idéalement depuis nato-master.
Redémarrer LANCE ne répare pas un relais UMONS arrêté.

### Sur la machine qui héberge réellement Ollama

Ces commandes ne s’appliquent qu’après confirmation du serveur et de son mode
d’installation. Un cluster peut utiliser un job GPU ou un conteneur plutôt
qu’un service systemd ; ne pas lancer un second serveur pour contourner ce mode.

```bash
ollama list    # modèles installés
ollama ps      # modèles chargés
nvidia-smi     # si GPU NVIDIA et outil disponible
```

Si Ollama est effectivement géré par le service Linux `ollama` :

```bash
sudo systemctl status ollama --no-pager
sudo journalctl -u ollama -n 100 --no-pager
# Seulement après vérification des utilisateurs et des travaux en cours :
sudo systemctl restart ollama
```

Installer un modèle absent (`ollama pull <identifiant>`) relève de l’administrateur
UMONS et consomme de l’espace ; changer le menu LANCE ne suffit pas. Changer de
Qwen vers Gemma sur le même point d’accès ne contourne pas une panne du relais.
Pour continuer pendant une panne, choisir un **autre fournisseur opérationnel**
et contrôler les sélections par phase. Un run déjà en échec n’est pas repris
automatiquement en changeant le modèle du formulaire.

## Limites et sources

La vérification du 1er octobre a confirmé le catalogue distant, le fournisseur
enregistré sur Main et l’identité Tailscale du point d’accès. Elle n’a pas relancé
le relais, changé un modèle, ni déclenché de génération ou d’audit. La procédure
de redémarrage reste conditionnelle tant que le service réel n’est pas identifié.

Références officielles consultées le 1er octobre 2026 :
[API compatible OpenAI](https://docs.ollama.com/api/openai-compatibility),
[commandes Ollama](https://docs.ollama.com/cli),
[configuration et exploitation](https://docs.ollama.com/faq).
Contrats LANCE : `src/api/routes/providers.py`, `src/api/routes/models.py`,
`src/static/app.js`, `src/agent/provider.py` et
[authentification des fournisseurs](provider-auth.md).
