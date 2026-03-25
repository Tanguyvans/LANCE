#!/bin/bash
# deploy.sh — Déploiement complet d'un scénario benchmark en une commande
#
# Usage :
#   ./deploy.sh <scenario_id> [--no-populate] [--vault-pass-file <file>]
#
# Exemples :
#   ./deploy.sh 1                          # déploie S1 complet
#   ./deploy.sh 2 --no-populate            # S2 sans données IoT réalistes
#   ./deploy.sh 3 --vault-pass-file ~/.vault_pass
#
# Ce script exécute dans l'ordre :
#   1. Teardown du scénario actif si besoin
#   2. 03_deploy_scenario.yml
#   3. 04_inject_vulns.yml
#   4. 05_populate_services.yml  (sauf si --no-populate)
#
# En cas d'erreur à n'importe quelle étape, le script s'arrête.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INVENTORY="$SCRIPT_DIR/inventory.yml"
PLAYBOOKS="$SCRIPT_DIR/playbooks"

# ── Couleurs ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

log_step()  { echo -e "\n${BLUE}${BOLD}[$(date +%H:%M:%S)] ► $1${NC}"; }
log_ok()    { echo -e "${GREEN}✓ $1${NC}"; }
log_warn()  { echo -e "${YELLOW}⚠ $1${NC}"; }
log_error() { echo -e "${RED}✗ $1${NC}"; exit 1; }

# ── Arguments ──
SCENARIO_ID=""
POPULATE=true
VAULT_ARGS="--ask-vault-pass"

while [[ $# -gt 0 ]]; do
  case $1 in
    [1-5])
      SCENARIO_ID="$1"
      shift ;;
    --no-populate)
      POPULATE=false
      shift ;;
    --vault-pass-file)
      VAULT_ARGS="--vault-password-file $2"
      shift 2 ;;
    --help|-h)
      sed -n '2,14p' "$0" | sed 's/^# \?//'
      exit 0 ;;
    *)
      log_error "Argument inconnu : $1. Usage : ./deploy.sh <1|2|3> [--no-populate]"
      ;;
  esac
done

[[ -z "$SCENARIO_ID" ]] && log_error "scenario_id manquant. Usage : ./deploy.sh <1|2|3>"

# ── Résumé scénarios ──
declare -A SCENARIO_NAMES=(
  [1]="Réseau plat        (4 VMs  — mqtt, web, ssh)"
  [2]="Gateway exposée    (6 VMs  — web, mqtt, iot-gw, db, jump)"
  [3]="Réplique NATO Lab  (8 VMs  — wisgate, rpi5, iot-hub, jetson, ap, cam, nvr)"
)

declare -A SCENARIO_BASES=([1]=100 [2]=110 [3]=120)

echo -e "\n${BOLD}╔══════════════════════════════════════════════════════════╗"
echo -e "║     Benchmark IoT — Déploiement automatique              ║"
echo -e "╚══════════════════════════════════════════════════════════╝${NC}"
echo -e "  Scénario  : ${BOLD}S${SCENARIO_ID} — ${SCENARIO_NAMES[$SCENARIO_ID]}${NC}"
echo -e "  Populate  : $([ "$POPULATE" = true ] && echo "${GREEN}oui${NC}" || echo "${YELLOW}non${NC}")"
echo -e "  Répertoire: $SCRIPT_DIR"
echo ""

ANSIBLE_CMD="ansible-playbook -i $INVENTORY $VAULT_ARGS"
EXTRA="--extra-vars scenario_id=$SCENARIO_ID"
START_TIME=$(date +%s)

# ── Étape 0 : Teardown si un autre scénario tourne ──
log_step "Vérification des scénarios actifs..."

RUNNING=$(ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@$(grep ansible_host "$INVENTORY" | head -1 | awk '{print $2}' | cut -d: -f2) \
  "pct list 2>/dev/null | awk 'NR>1 && \$2==\"running\" {print \$1}'; qm list 2>/dev/null | awk 'NR>1 && \$3==\"running\" {print \$1}'" 2>/dev/null || true)

BASE=${SCENARIO_BASES[$SCENARIO_ID]}
CONFLICT_SCENARIO=""
for vmid in $RUNNING; do
  [[ "$vmid" -lt 100 || "$vmid" -gt 199 ]] 2>/dev/null && continue
  [[ "$vmid" -ge "$BASE" && "$vmid" -lt "$((BASE+20))" ]] && continue
  for s in 1 2 3 4 5; do
    case $s in 1) b=100 ;; 2) b=110 ;; 3) b=120 ;; 4) b=130 ;; 5) b=150 ;; esac
    if [[ "$vmid" -ge "$b" && "$vmid" -lt "$((b+20))" ]]; then
      CONFLICT_SCENARIO="$s"
      break
    fi
  done
  [[ -n "$CONFLICT_SCENARIO" ]] && break
done

if [[ -n "$CONFLICT_SCENARIO" ]]; then
  log_warn "Scénario S${CONFLICT_SCENARIO} actif détecté — teardown en cours..."
  $ANSIBLE_CMD "$PLAYBOOKS/99_teardown.yml" --extra-vars "scenario_id=$CONFLICT_SCENARIO" \
    || log_error "Teardown S${CONFLICT_SCENARIO} échoué"
  log_ok "Scénario S${CONFLICT_SCENARIO} supprimé"
else
  log_ok "Aucun conflit détecté"
fi

# ── Étape 1 : Déploiement ──
log_step "Déploiement S${SCENARIO_ID} — ${SCENARIO_NAMES[$SCENARIO_ID]}"
$ANSIBLE_CMD "$PLAYBOOKS/03_deploy_scenario.yml" $EXTRA \
  || log_error "Déploiement échoué (03_deploy_scenario.yml)"
log_ok "VMs déployées et connectées"

# ── Étape 2 : Injection des vulnérabilités ──
log_step "Injection des vulnérabilités..."
$ANSIBLE_CMD "$PLAYBOOKS/04_inject_vulns.yml" $EXTRA \
  || log_error "Injection échouée (04_inject_vulns.yml)"
log_ok "Vulnérabilités injectées"

# ── Étape 3 : Peuplement (optionnel) ──
if [[ "$POPULATE" = true ]]; then
  log_step "Peuplement des services (données IoT réalistes)..."
  $ANSIBLE_CMD "$PLAYBOOKS/05_populate_services.yml" $EXTRA \
    || log_warn "Peuplement partiellement échoué (05_populate_services.yml) — non bloquant"
  log_ok "Services peuplés"
fi

# ── Résumé final ──
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

echo -e "\n${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗"
echo -e "║  ✓ Scénario S${SCENARIO_ID} prêt en ${MINUTES}m${SECONDS}s$(printf '%*s' $((44 - ${#MINUTES} - ${#SECONDS})) '')║"
echo -e "╠══════════════════════════════════════════════════════════╣${NC}"

case $SCENARIO_ID in
  1)
    echo -e "  Router : ssh root@192.168.100.1"
    echo -e "  MQTT   : mosquitto_sub -h 192.168.100.11 -t '#' -v"
    echo -e "  Web    : curl http://192.168.100.12/backup/"
    echo -e "  SSH    : ssh admin@192.168.100.13  (password: admin)"
    ;;
  2)
    echo -e "  Router : ssh root@192.168.100.1  (+ admin WAN exposé)"
    echo -e "  MQTT   : mosquitto_sub -h 192.168.100.12 -t '#' -v"
    echo -e "  IoT GW : curl http://192.168.100.13/api/devices"
    echo -e "  DB     : mysql -h 192.168.100.14 -u root smartcity"
    echo -e "  Jump   : ssh admin@192.168.100.15  (password: admin)"
    ;;
  3)
    echo -e "  Router  : telnet 192.168.100.1  |  ftp 192.168.100.1"
    echo -e "  WisGate : curl http://192.168.100.11/api/devices"
    echo -e "  RPi5    : mosquitto_sub -h 192.168.100.12 -t '#' -v"
    echo -e "  IoT Hub : mosquitto_sub -h 192.168.100.13 -t '#' -v"
    echo -e "  Jetson  : ssh admin@192.168.100.14  (password: admin)"
    ;;
esac

echo -e "\n  Vérification : ${BOLD}./verify.sh $SCENARIO_ID${NC}"
echo -e "  Teardown    : ${BOLD}ansible-playbook playbooks/99_teardown.yml --extra-vars scenario_id=$SCENARIO_ID${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}\n"
