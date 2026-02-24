"""CLI entry point for risk scoring.

Usage:
    python3 -m src.risk_cli                     # score with live NVD scan
    python3 -m src.risk_cli --skip-nvd          # score without CVE data (network metrics only)
"""

import argparse
import os
from pathlib import Path

from .cve_lookup import load_cpe_mapping, scan_all_devices
from .loader import build_graph, load_yaml
from .risk_scorer import print_risk_report, score_all_devices

YAML_PATH = Path(__file__).resolve().parent.parent / "infrastructure" / "nato_lab.yaml"
CPE_PATH = Path(__file__).resolve().parent.parent / "infrastructure" / "cpe_mapping.yaml"


def main() -> None:
    parser = argparse.ArgumentParser(description="Risk scoring for NATO IoT lab")
    parser.add_argument(
        "--skip-nvd",
        action="store_true",
        help="Skip NVD CVE scan (score based on network metrics only)",
    )
    args = parser.parse_args()

    print("Loading infrastructure...")
    backend = build_graph(YAML_PATH)
    infra = load_yaml(YAML_PATH)

    if args.skip_nvd:
        print("Skipping NVD scan (--skip-nvd)")
        cve_reports = []
    else:
        api_key = os.environ.get("NVD_API_KEY")
        if not api_key:
            print("No NVD_API_KEY set — using public rate limit (5 req/30s)")
        print("Loading CPE mapping...")
        cpe_mapping = load_cpe_mapping(CPE_PATH)
        print(f"Scanning NVD for {len(cpe_mapping)} devices...")
        cve_reports = scan_all_devices(infra, cpe_mapping, api_key)

    print("Computing risk scores...")
    scores = score_all_devices(backend, cve_reports)
    print_risk_report(scores)


if __name__ == "__main__":
    main()
