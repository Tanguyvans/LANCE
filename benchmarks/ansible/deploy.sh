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
    [1-7])
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
      log_error "Argument inconnu : $1. Usage : ./deploy.sh <1|2|3|4|5|6|7> [--no-populate]"
      ;;
  esac
done

[[ -z "$SCENARIO_ID" ]] && log_error "scenario_id manquant. Usage : ./deploy.sh <1|2|3|4|5|6|7>"

# ── Résumé scénarios ──
case $SCENARIO_ID in
  1) SCENARIO_NAME="Réseau plat           (4 VMs  — mqtt, web, ssh)" ;;
  2) SCENARIO_NAME="Gateway exposée       (6 VMs  — web, mqtt, iot-gw, db, jump)" ;;
  3) SCENARIO_NAME="Réplique NATO Lab     (8 VMs  — wisgate, rpi5, iot-hub, jetson, ap, cam, nvr)" ;;
  4) SCENARIO_NAME="Réseau segmenté       (8 VMs  — admin, webapp, mqtt, lora-gw, plc, hmi, historian)" ;;
  5) SCENARIO_NAME="Smart Building        (8 VMs  — cam1, cam2, nvr, access-ctrl, hvac, mqtt, web)" ;;
  6) SCENARIO_NAME="Domotique centralisée (6 VMs  — hub, mqtt, db, cam, web)" ;;
  7) SCENARIO_NAME="Edge-Cloud pivot      (6 VMs  — edge-gw, edge-mqtt, edge-compute, cloud-api, cloud-db)" ;;
esac

case $SCENARIO_ID in
  1) BASE=100; SUBNET="10.10.0" ;; 2) BASE=110; SUBNET="10.20.0" ;;
  3) BASE=120; SUBNET="10.30.0" ;; 4) BASE=130; SUBNET="10.40.0" ;;
  5) BASE=150; SUBNET="10.50.0" ;; 6) BASE=160; SUBNET="10.60.0" ;;
  7) BASE=170; SUBNET="10.70.0" ;; 8) BASE=180; SUBNET="10.80.0" ;;
  9) BASE=190; SUBNET="10.90.0" ;; 10) BASE=210; SUBNET="10.100.0" ;;
esac

echo -e "\n${BOLD}╔══════════════════════════════════════════════════════════╗"
echo -e "║     Benchmark IoT — Déploiement automatique              ║"
echo -e "╚══════════════════════════════════════════════════════════╝${NC}"
echo -e "  Scénario  : ${BOLD}S${SCENARIO_ID} — ${SCENARIO_NAME}${NC}"
echo -e "  Populate  : $([ "$POPULATE" = true ] && echo "${GREEN}oui${NC}" || echo "${YELLOW}non${NC}")"
echo -e "  Répertoire: $SCRIPT_DIR"
echo ""

run_playbook() { ansible-playbook -i "$INVENTORY" $VAULT_ARGS "$@"; }
EXTRA="--extra-vars scenario_id=$SCENARIO_ID"
START_TIME=$(date +%s)

# ── Étape 0 : Info VLAN ──
log_step "Scénario S${SCENARIO_ID} — VLAN isolé sur ${SUBNET}.0/24"
log_ok "Chaque scénario utilise son propre VLAN — pas de conflit possible"

# ── Étape 1 : Déploiement ──
log_step "Déploiement S${SCENARIO_ID} — ${SCENARIO_NAME}"
run_playbook "$PLAYBOOKS/03_deploy_scenario.yml" $EXTRA \
  || log_error "Déploiement échoué (03_deploy_scenario.yml)"
log_ok "VMs déployées et connectées"

# ── Étape 2 : Injection des vulnérabilités ──
log_step "Injection des vulnérabilités..."
run_playbook "$PLAYBOOKS/04_inject_vulns.yml" $EXTRA \
  || log_error "Injection échouée (04_inject_vulns.yml)"
log_ok "Vulnérabilités injectées"

# ── Étape 3 : Peuplement (optionnel) ──
if [[ "$POPULATE" = true ]]; then
  log_step "Peuplement des services (données IoT réalistes)..."
  run_playbook "$PLAYBOOKS/05_populate_services.yml" $EXTRA \
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
    echo -e "  Router : ssh root@${SUBNET}.1"
    echo -e "  MQTT   : mosquitto_sub -h ${SUBNET}.11 -t '#' -v"
    echo -e "  Web    : curl http://${SUBNET}.12/backup/"
    echo -e "  SSH    : ssh admin@${SUBNET}.13  (password: admin)"
    ;;
  2)
    echo -e "  Router : ssh root@${SUBNET}.1  (+ admin WAN exposé)"
    echo -e "  MQTT   : mosquitto_sub -h ${SUBNET}.12 -t '#' -v"
    echo -e "  IoT GW : curl http://${SUBNET}.13/api/devices"
    echo -e "  DB     : mysql -h ${SUBNET}.14 -u root smartcity"
    echo -e "  Jump   : ssh admin@${SUBNET}.15  (password: admin)"
    ;;
  3)
    echo -e "  Router  : telnet ${SUBNET}.1  |  ftp ${SUBNET}.1"
    echo -e "  WisGate : curl http://${SUBNET}.11/api/devices"
    echo -e "  RPi5    : mosquitto_sub -h ${SUBNET}.12 -t '#' -v"
    echo -e "  IoT Hub : mosquitto_sub -h ${SUBNET}.13 -t '#' -v"
    echo -e "  Jetson  : ssh admin@${SUBNET}.14  (password: admin)"
    ;;
  4)
    echo -e "  Router  : ssh root@${SUBNET}.1  (+ admin WAN exposé)"
    echo -e "  Admin   : ssh admin@${SUBNET}.11  (password: admin)"
    echo -e "  Webapp  : curl http://${SUBNET}.12/  (upload PHP sans validation)"
    echo -e "  MQTT    : mosquitto_sub -h ${SUBNET}.13 -t '#' -v"
    echo -e "  PLC     : python3 -c \"from pymodbus.client import ModbusTcpClient; c=ModbusTcpClient('${SUBNET}.15'); c.connect(); print(c.read_holding_registers(0,10))\""
    echo -e "  HMI     : curl http://${SUBNET}.16/"
    echo -e "  DB      : mysql -h ${SUBNET}.17 -u root smartcity"
    ;;
  5)
    echo -e "  Router  : ssh root@${SUBNET}.1  (+ admin WAN exposé)"
    echo -e "  Cam1    : curl http://${SUBNET}.11/admin  (no auth)"
    echo -e "  Cam2    : curl http://${SUBNET}.12/api/info"
    echo -e "  NVR     : ssh ubnt@${SUBNET}.13  (password: ubnt)"
    echo -e "  MQTT    : mosquitto_sub -h ${SUBNET}.16 -t '#' -v"
    echo -e "  Web     : curl http://${SUBNET}.17/"
    ;;
  6)
    echo -e "  Router  : ssh root@${SUBNET}.1  (+ admin WAN exposé)"
    echo -e "  Hub     : curl http://${SUBNET}.11/admin  (no auth)"
    echo -e "  Hub API : curl http://${SUBNET}.11/api/devices"
    echo -e "  MQTT    : mosquitto_sub -h ${SUBNET}.12 -t '#' -v"
    echo -e "  DB      : mysql -h ${SUBNET}.13 -u root smartcity"
    echo -e "  Camera  : curl http://${SUBNET}.14/admin  (no auth)"
    echo -e "  Web     : curl http://${SUBNET}.15/backup/"
    ;;
  7)
    echo -e "  Router     : ssh root@${SUBNET}.1  (+ admin WAN exposé)"
    echo -e "  Edge GW    : ssh-audit ${SUBNET}.11  (Dropbear CVE-2023-48795)"
    echo -e "  Edge GW    : curl http://${SUBNET}.11/api/devices"
    echo -e "  Edge MQTT  : mosquitto_sub -h ${SUBNET}.12 -t '#' -v"
    echo -e "  Edge SSH   : ssh admin@${SUBNET}.13  (password: admin)"
    echo -e "  Cloud API  : curl http://${SUBNET}.14/backup/cloud_db_backup.sql"
    echo -e "  Cloud DB   : mysql -h ${SUBNET}.15 -u root smartcity"
    ;;
esac

echo -e "\n  Vérification : ${BOLD}./verify.sh $SCENARIO_ID${NC}"
echo -e "  Teardown    : ${BOLD}ansible-playbook playbooks/99_teardown.yml --extra-vars scenario_id=$SCENARIO_ID${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}\n"
