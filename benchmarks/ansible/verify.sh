#!/bin/bash
# verify.sh — Vérifie que les vulnérabilités du scénario actif sont bien en place
#
# Usage : ./verify.sh <scenario_id> [--vault-pass-file <file>]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_ID="${1:-}"
VAULT_ARGS=(--ask-vault-pass)

[[ "$SCENARIO_ID" =~ ^[0-9]+$ ]] \
  || { echo "Usage : ./verify.sh <1-29> [--vault-pass-file <file>]"; exit 1; }
(( SCENARIO_ID >= 1 && SCENARIO_ID <= 29 )) \
  || { echo "scenario_id invalide : $SCENARIO_ID (attendu : 1-29)"; exit 1; }
if [[ "${2:-}" == "--vault-pass-file" ]]; then
  [[ -n "${3:-}" ]] || { echo "--vault-pass-file requiert un chemin"; exit 1; }
  VAULT_ARGS=(--vault-password-file "$3")
fi

ansible-playbook -i "$SCRIPT_DIR/inventory.yml" \
  "$SCRIPT_DIR/playbooks/06_verify.yml" \
  "${VAULT_ARGS[@]}" \
  --extra-vars "scenario_id=$SCENARIO_ID"
