"""NIST NVD CVE lookup module.

Queries the NVD REST API v2.0 to find CVEs for devices/services
based on CPE strings or keyword searches.
"""

import os
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests
import yaml

from src.config import (
    NVD_MAX_REQUESTS_NO_KEY,
    NVD_MAX_REQUESTS_WITH_KEY,
    NVD_RATE_WINDOW_SECONDS,
    NVD_REQUEST_TIMEOUT,
)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_URL = "https://nvd.nist.gov/vuln/detail/"
_request_timestamps: list[float] = []


@dataclass
class CVEResult:
    cve_id: str
    description: str
    cvss_score: float | None = None
    severity: str | None = None
    attack_vector: str | None = None


@dataclass
class DeviceCVEReport:
    device_id: str
    device_name: str
    queries: list[str] = field(default_factory=list)
    cves: list[CVEResult] = field(default_factory=list)
    error: str | None = None


def load_cpe_mapping(path: Path) -> dict[str, list[str]]:
    """Load CPE/keyword mapping from YAML file."""
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _rate_limit(has_api_key: bool) -> None:
    """Sleep if necessary to respect NVD rate limits."""
    max_requests = NVD_MAX_REQUESTS_WITH_KEY if has_api_key else NVD_MAX_REQUESTS_NO_KEY
    window = NVD_RATE_WINDOW_SECONDS
    now = time.time()
    _request_timestamps[:] = [t for t in _request_timestamps if now - t < window]
    if len(_request_timestamps) >= max_requests:
        sleep_time = window - (now - _request_timestamps[0]) + 0.5
        if sleep_time > 0:
            time.sleep(sleep_time)
    _request_timestamps.append(time.time())


def _nvd_get(params: dict, api_key: str | None = None) -> dict:
    """Make a rate-limited GET request to the NVD API, with exponential backoff retry."""
    _rate_limit(api_key is not None)
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    last_exc: Exception | None = None
    for attempt in range(3):
        if attempt > 0:
            delay = 2 * (2 ** (attempt - 1))  # 2s, 4s
            time.sleep(delay)
        try:
            resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=NVD_REQUEST_TIMEOUT)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            last_exc = e
    raise last_exc  # type: ignore[misc]


def _parse_cve_item(vuln: dict) -> CVEResult:
    """Parse a single NVD vulnerability item into a CVEResult."""
    cve = vuln["cve"]
    cve_id = cve["id"]

    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d["lang"] == "en"), ""
    )

    metrics = cve.get("metrics", {})
    cvss_data = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            break

    return CVEResult(
        cve_id=cve_id,
        description=description[:300],
        cvss_score=cvss_data.get("baseScore") if cvss_data else None,
        severity=cvss_data.get("baseSeverity") if cvss_data else None,
        attack_vector=cvss_data.get("attackVector") if cvss_data else None,
    )


def query_nvd(query: str, api_key: str | None = None) -> list[CVEResult]:
    """Query NVD by CPE name or keyword. Auto-detects query type."""
    if query.startswith("cpe:"):
        params = {"cpeName": query, "resultsPerPage": 50}
    else:
        params = {"keywordSearch": query, "resultsPerPage": 50}

    data = _nvd_get(params, api_key)
    return [_parse_cve_item(v) for v in data.get("vulnerabilities", [])]


def scan_device(
    device_id: str,
    device_name: str,
    queries: list[str],
    api_key: str | None = None,
) -> DeviceCVEReport:
    """Scan a single device using its CPE/keyword queries. Deduplicates CVEs."""
    report = DeviceCVEReport(
        device_id=device_id,
        device_name=device_name,
        queries=queries,
    )
    seen_ids: set[str] = set()

    for q in queries:
        try:
            results = query_nvd(q, api_key)
            for cve in results:
                if cve.cve_id not in seen_ids:
                    seen_ids.add(cve.cve_id)
                    report.cves.append(cve)
        except requests.RequestException as e:
            report.error = f"Query '{q}' failed: {e}"

    report.cves.sort(key=lambda c: c.cvss_score or 0, reverse=True)
    return report


def scan_all_devices(
    infra,
    cpe_mapping: dict[str, list[str]],
    api_key: str | None = None,
) -> list[DeviceCVEReport]:
    """Scan all devices that have CPE mappings."""
    device_names = {d.id: d.name for d in infra.devices}
    reports = []

    for device_id, queries in cpe_mapping.items():
        name = device_names.get(device_id, device_id)
        report = scan_device(device_id, name, queries, api_key)
        reports.append(report)

    return reports
