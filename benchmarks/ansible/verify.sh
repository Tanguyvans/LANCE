#!/bin/bash
# verify.sh — Vérifie que les vulnérabilités du scénario actif sont bien en place
#
# Usage : ./verify.sh <scenario_id> [--vault-pass-file <file>]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_ID="${1:-}"
VAULT_ARGS="--ask-vault-pass"

[[ -z "$SCENARIO_ID" ]] && { echo "Usage : ./verify.sh <1|2|3|4|5|6|7>"; exit 1; }
[[ "$2" == "--vault-pass-file" ]] && VAULT_ARGS="--vault-password-file $3"

ansible-playbook -i "$SCRIPT_DIR/inventory.yml" \
  "$SCRIPT_DIR/playbooks/06_verify.yml" \
  $VAULT_ARGS \
  --extra-vars "scenario_id=$SCENARIO_ID"
