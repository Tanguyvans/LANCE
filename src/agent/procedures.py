"""Versioned descriptions of the procedures supported by existing runners.

This catalogue describes approved Python implementations; parameters never become
shell programs. Importing it does not load tools, models, scenarios or secrets.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil

SCRIPT_IDS = frozenset({"discovery-v1", "service-inventory-v1", "smoke-v1"})
INVENTORY_PORTS = "21,22,23,53,80,443,445,554,1883,3306,5432,5672,6379,8000,8080,8443,8883,9000,9090,9200,27017"

_PROCEDURES = (
    {
        "id": "discovery-v1", "version": "1.0.0", "category": "Découverte",
        "title": "Découvrir les équipements", "runner_kind": "scripted",
        "script_id": "discovery-v1", "target_kind": "network", "diagnostic": False,
        "summary": "Repérer les hôtes qui répondent sur un réseau IPv4 autorisé.",
        "outputs": "Inventaire des adresses observées et traces de découverte.",
        "scope": "Découverte des hôtes avec Nmap. Aucun contrôle de vulnérabilité.",
        "effects": "Envoie des sondes réseau ; ne déploie ni ne modifie les machines.",
        "dependencies": ["nmap"], "defaults": {"max_tool_calls": 1, "max_duration_s": 120},
        "steps": [{"id": "discovery", "label": "Découvrir les hôtes"},
                  {"id": "results", "label": "Enregistrer les observations"}],
    },
    {
        "id": "service-inventory-v1", "version": "1.0.0", "category": "Inventaire",
        "title": "Inventorier les services", "runner_kind": "scripted",
        "script_id": "service-inventory-v1", "target_kind": "network", "diagnostic": False,
        "summary": "Découvrir les équipements puis identifier leurs services TCP usuels.",
        "outputs": "Table des hôtes, ports, services et versions observées, avec leurs traces.",
        "scope": "Jusqu’à 16 hôtes observés, sur une liste fixe de ports TCP. Les hôtes silencieux et les autres ports restent hors couverture.",
        "effects": "Envoie des sondes de découverte et d’identification de services ; ne déploie pas de machines.",
        "dependencies": ["nmap"], "defaults": {"max_tool_calls": 17, "max_duration_s": 600},
        "max_hosts": 16, "ports": INVENTORY_PORTS,
        "steps": [{"id": "discovery", "label": "Découvrir les hôtes"},
                  {"id": "services", "label": "Identifier les services TCP"},
                  {"id": "results", "label": "Enregistrer l’inventaire"}],
    },
    {
        "id": "rules-audit-v1", "version": "1.0.0", "category": "Audit de sécurité",
        "title": "Auditer un scénario automatiquement", "runner_kind": "rules",
        "script_id": None, "target_kind": "scenario", "diagnostic": False,
        "summary": "Déployer un scénario du laboratoire, analyser ses services et vérifier les failles candidates.",
        "outputs": "Constats et confirmations par équipement, erreurs de contrôle et preuves.",
        "scope": "Analyse et vérification par règles, sans modèle. Scénarios publics déployables uniquement.",
        "effects": "Crée les machines du scénario. Certains contrôles modifient l’état des services simulés. Le nettoyage automatique peut supprimer les machines de ce scénario.",
        "dependencies": ["ansible-playbook"],
        "defaults": {"max_tool_calls": 200, "max_duration_s": 600},
        "steps": [{"id": "deployment", "label": "Préparer le scénario"},
                  {"id": "analysis", "label": "Analyser les équipements"},
                  {"id": "verification", "label": "Vérifier les constats"},
                  {"id": "cleanup", "label": "Nettoyer le scénario"},
                  {"id": "results", "label": "Restituer les preuves"}],
    },
    {
        "id": "smoke-v1", "version": "1.0.0", "category": "Diagnostic",
        "title": "Vérifier le lancement hors ligne", "runner_kind": "scripted",
        "script_id": "smoke-v1", "target_kind": "none", "diagnostic": True,
        "summary": "Vérifier le lancement, les événements et l’enregistrement d’une exécution.",
        "outputs": "État du diagnostic et fichiers enregistrés.",
        "scope": "Diagnostic de l’application. Aucun résultat d’audit de sécurité.",
        "effects": "Aucun accès réseau, appel modèle ou réservation du laboratoire.",
        "dependencies": [], "defaults": {"max_duration_s": 120},
        "steps": [{"id": "checked", "label": "Vérifier le lancement"},
                  {"id": "results", "label": "Enregistrer le diagnostic"}],
    },
)


def get_procedure(identifier: str) -> dict:
    """Return a detached description and its implementation fingerprint."""
    source = next((item for item in _PROCEDURES if item["id"] == identifier), None)
    if source is None:
        raise ValueError("Unknown procedure")
    result = deepcopy(source)
    root = Path(__file__).resolve().parent
    paths = [root / "procedures.py", root / "run_modes.py", root / "procedure_observations.py"]
    if source["runner_kind"] == "rules":
        paths += [root / "scanner.py", root / "procedure_progress.py", root / "phases/verification/rules.py",
                  root / "phases/verification/contract.py", root / "rules_audit.py"]
    digest = hashlib.sha256(json.dumps(source, sort_keys=True).encode())
    for path in paths:
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes())
    result["fingerprint"] = digest.hexdigest()
    return result


def procedure_catalogue() -> dict:
    items = []
    for source in _PROCEDURES:
        item = get_procedure(source["id"])
        missing = [name for name in item["dependencies"] if shutil.which(name) is None]
        item["availability"] = {"available": not missing, "missing_dependencies": missing}
        items.append(item)
    return {"schema_version": 1, "procedures": items}
