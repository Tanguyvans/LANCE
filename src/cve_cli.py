"""CLI entry point for NVD CVE scanning.

Usage:
    python3 -m src.cve_cli
    NVD_API_KEY=xxx python3 -m src.cve_cli   # faster with API key
"""

import os
import sys
from pathlib import Path

from src.cve_lookup import load_cpe_mapping, scan_all_devices
from src.loader import load_yaml

YAML_PATH = Path(__file__).resolve().parent.parent / "infrastructure" / "nato_lab.yaml"
CPE_PATH = Path(__file__).resolve().parent.parent / "infrastructure" / "cpe_mapping.yaml"


def main():
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        print(f"Using NVD API key (faster rate limit)")
    else:
        print("No NVD_API_KEY set — using public rate limit (5 req/30s)")

    print("Loading infrastructure...")
    infra = load_yaml(YAML_PATH)

    print("Loading CPE mapping...")
    cpe_mapping = load_cpe_mapping(CPE_PATH)
    print(f"  {len(cpe_mapping)} devices to scan\n")

    print("Scanning NVD for CVEs (this may take a while)...\n")
    reports = scan_all_devices(infra, cpe_mapping, api_key)

    total_cves = 0
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    print("=" * 60)
    print("CVE SCAN REPORT")
    print("=" * 60)

    for report in reports:
        ip = next(
            (d.ip for d in infra.devices if d.id == report.device_id), "N/A"
        )
        print(f"\n[{report.device_id}] {report.device_name} ({ip})")
        print(f"  Queries: {', '.join(report.queries)}")

        if report.error:
            print(f"  ERROR: {report.error}")

        if not report.cves:
            print("  No CVEs found.")
            continue

        print(f"  Found {len(report.cves)} CVEs:")
        total_cves += len(report.cves)

        for cve in report.cves[:10]:  # show top 10
            score = f"{cve.cvss_score:.1f}" if cve.cvss_score else "N/A"
            sev = cve.severity or "N/A"
            vec = cve.attack_vector or "?"
            desc = cve.description[:80]
            print(f"    {cve.cve_id}  CVSS {score:>4} {sev:<9} ({vec})  {desc}")

            if cve.severity and cve.severity in severity_counts:
                severity_counts[cve.severity] += 1

        if len(report.cves) > 10:
            print(f"    ... and {len(report.cves) - 10} more")

    print(f"\n{'=' * 60}")
    print(f"SUMMARY: {total_cves} CVEs across {len(reports)} devices")
    parts = [f"{k}: {v}" for k, v in severity_counts.items() if v > 0]
    if parts:
        print(f"  {' | '.join(parts)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
