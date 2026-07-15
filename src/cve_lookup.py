"""NIST NVD CVE lookup module.

Queries the NVD REST API v2.0 to find CVEs for devices/services
based on CPE strings or keyword searches.
"""

import os
import re
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
    cpe_matches: list[dict] = field(default_factory=list)
    compatibility_status: str = "indeterminate"
    compatibility_reason: str = "Not evaluated against a software query"
    matched_cpes: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class CVECompatibility:
    status: str
    reason: str
    matched_cpes: list[dict] = field(default_factory=list)


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
        cpe_matches=_extract_vulnerable_cpe_matches(cve.get("configurations", [])),
    )


_PRODUCT_ALIASES: dict[str, set[tuple[str, str]]] = {
    "apache": {("apache", "http server")},
    "apache httpd": {("apache", "http server")},
    "openssh": {("openbsd", "openssh")},
    "dropbear": {("dropbear ssh project", "dropbear ssh")},
    "mosquitto": {("eclipse", "mosquitto")},
    "nginx": {("f5", "nginx"), ("nginx", "nginx")},
    "opensuse leap": {("opensuse", "leap")},
    "routeros": {("mikrotik", "routeros")},
    "apache http server": {("apache", "http server")},
    "tomcat": {("apache", "tomcat")},
    "mariadb": {("mariadb", "mariadb")},
    "mysql": {("oracle", "mysql"), ("mysql", "mysql")},
    "postgresql": {("postgresql", "postgresql")},
    "redis": {("redis", "redis"), ("redislabs", "redis")},
    "samba": {("samba", "samba")},
    "wordpress": {("wordpress", "wordpress")},
    "proftpd": {("proftpd", "proftpd")},
    "vsftpd": {("vsftpd project", "vsftpd")},
}
_VERSION_RE = re.compile(
    r"(?<![A-Za-z0-9])v?(\d+(?:[._-]\d+)+(?:[A-Za-z]+\d*)?)",
    re.IGNORECASE,
)
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _normalize_name(value: str) -> str:
    value = value.replace("\\/", "/").replace("_", "-").lower()
    return " ".join(re.findall(r"[a-z0-9]+", value))


def _parse_cpe(criteria: str) -> tuple[str, str, str] | None:
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return (
        _normalize_name(parts[3]),
        _normalize_name(parts[4]),
        parts[5].replace("\\", ""),
    )


def _extract_vulnerable_cpe_matches(configurations: list[dict]) -> list[dict]:
    """Flatten vulnerable CPE matches from arbitrary NVD configuration trees."""
    matches: list[dict] = []

    def visit(node: dict, inherited_conditional: bool = False) -> None:
        conditional = inherited_conditional or node.get("operator") == "AND"
        for match in node.get("cpeMatch", []):
            if match.get("vulnerable") is True and match.get("criteria"):
                flattened = {
                    key: match[key]
                    for key in (
                        "criteria", "versionStartIncluding", "versionStartExcluding",
                        "versionEndIncluding", "versionEndExcluding",
                    )
                    if key in match
                }
                if conditional:
                    flattened["conditional"] = True
                matches.append(flattened)
        for child in node.get("nodes", []):
            if isinstance(child, dict):
                visit(child, conditional)

    for configuration in configurations:
        if isinstance(configuration, dict):
            visit(configuration)
    return matches


def _query_product_version(query: str) -> tuple[str, str | None, bool]:
    """Return normalized product, version, and whether query is an exact CPE."""
    if query.lower().startswith("cpe:2.3:"):
        parsed = _parse_cpe(query)
        if parsed is None:
            return "", None, True
        vendor, product, version = parsed
        return f"{vendor} {product}".strip(), version if version not in {"*", "-"} else None, True

    normalized = _normalize_name(query)
    version_match = _VERSION_RE.search(query)
    version = version_match.group(1) if version_match else None
    prefix = query[:version_match.start()] if version_match else query
    product = _normalize_name(re.sub(r"\bversion\b", " ", prefix, flags=re.IGNORECASE))
    for alias in sorted(_PRODUCT_ALIASES, key=len, reverse=True):
        if alias in normalized:
            product = alias
            break
    return product, version, False


def query_requires_compatibility_filter(query: str) -> bool:
    """Whether a query contains enough product/version structure to verify."""
    if _CVE_ID_RE.fullmatch(query.strip()):
        return False
    _, version, is_cpe = _query_product_version(query)
    return is_cpe or version is not None


def _version_tokens(value: str) -> list[tuple[int, int | str]]:
    tokens: list[tuple[int, int | str]] = []
    for token in re.findall(r"\d+|[A-Za-z]+", value.lower()):
        tokens.append((0, int(token)) if token.isdigit() else (1, token))
    return tokens


def _compare_versions(left: str, right: str) -> int:
    left_tokens = _version_tokens(left)
    right_tokens = _version_tokens(right)
    size = max(len(left_tokens), len(right_tokens))
    padding = (0, 0)
    for index in range(size):
        left_token = left_tokens[index] if index < len(left_tokens) else padding
        right_token = right_tokens[index] if index < len(right_tokens) else padding
        if left_token < right_token:
            return -1
        if left_token > right_token:
            return 1
    return 0


def _product_matches(query_product: str, vendor: str, product: str) -> bool:
    aliases = _PRODUCT_ALIASES.get(query_product)
    if aliases is not None:
        return (vendor, product) in aliases
    candidate = f"{vendor} {product}".strip()
    return (
        bool(query_product)
        and (
            query_product == product
            or query_product == candidate
            or product in query_product.split()
        )
    )


def _version_matches(version: str | None, cpe_version: str, match: dict) -> bool:
    if version is None:
        return True
    if cpe_version not in {"*", "-"}:
        return _compare_versions(version, cpe_version) == 0
    has_bounds = any(
        key.startswith("versionStart") or key.startswith("versionEnd")
        for key in match
    )
    if cpe_version == "-" and not has_bounds:
        return False
    bounds = (
        ("versionStartIncluding", lambda value: _compare_versions(version, value) >= 0),
        ("versionStartExcluding", lambda value: _compare_versions(version, value) > 0),
        ("versionEndIncluding", lambda value: _compare_versions(version, value) <= 0),
        ("versionEndExcluding", lambda value: _compare_versions(version, value) < 0),
    )
    return all(check(str(match[key])) for key, check in bounds if key in match)


def classify_cve_compatibility(query: str, cpe_matches: list[dict]) -> CVECompatibility:
    """Classify a candidate without hiding it from the model.

    ``incompatible`` is reserved for explicit NVD contradictions. Missing CPE
    data, unknown aliases, product-only searches, and identifier-only searches
    remain ``indeterminate`` so a capable model can investigate further.
    """
    if _CVE_ID_RE.fullmatch(query.strip()):
        return CVECompatibility(
            "indeterminate",
            "CVE identifier lookup has no observed product/version context",
        )
    query_product, version, is_cpe = _query_product_version(query)
    if not query_requires_compatibility_filter(query):
        return CVECompatibility(
            "indeterminate",
            "Product-only query: a detected version is required for verification",
        )
    if not cpe_matches:
        return CVECompatibility(
            "indeterminate",
            "NVD provides no vulnerable CPE configuration for deterministic verification",
        )

    product_matches: list[dict] = []
    compatible_matches: list[dict] = []
    for match in cpe_matches:
        parsed = _parse_cpe(str(match.get("criteria", "")))
        if parsed is None:
            continue
        vendor, product, cpe_version = parsed
        if not _product_matches(query_product, vendor, product):
            continue
        product_matches.append(match)
        if _version_matches(version, cpe_version, match):
            compatible_matches.append(match)

    if compatible_matches:
        if any(not match.get("conditional") for match in compatible_matches):
            return CVECompatibility(
                "compatible",
                "NVD product and vulnerable version range match the observed software",
                compatible_matches,
            )
        return CVECompatibility(
            "conditional",
            "Product/version match, but NVD requires additional platform or runtime conditions",
            compatible_matches,
        )

    if product_matches:
        return CVECompatibility(
            "incompatible",
            "Product matches, but the observed version is outside every vulnerable NVD range",
            product_matches,
        )

    if is_cpe or query_product in _PRODUCT_ALIASES:
        return CVECompatibility(
            "incompatible",
            "NVD affected products explicitly differ from the observed product",
        )
    return CVECompatibility(
        "indeterminate",
        "No reliable product alias maps the observed banner to the affected NVD CPEs",
    )


def cve_matches_query(query: str, cpe_matches: list[dict]) -> bool:
    """Backward-compatible predicate: only explicit incompatibility is False."""
    return classify_cve_compatibility(query, cpe_matches).status != "incompatible"


_COMPATIBILITY_ORDER = {
    "compatible": 0,
    "conditional": 1,
    "indeterminate": 2,
    "incompatible": 3,
}


def classify_cve_results(query: str, results: list[CVEResult]) -> list[CVEResult]:
    """Annotate and rank every candidate; never discard one."""
    for result in results:
        assessment = classify_cve_compatibility(query, result.cpe_matches)
        result.compatibility_status = assessment.status
        result.compatibility_reason = assessment.reason
        result.matched_cpes = assessment.matched_cpes
    return sorted(
        results,
        key=lambda result: _COMPATIBILITY_ORDER.get(
            result.compatibility_status, _COMPATIBILITY_ORDER["indeterminate"]
        ),
    )


def filter_compatible_cves(query: str, results: list[CVEResult]) -> list[CVEResult]:
    """Compatibility alias retained for callers; candidates are now annotated, not filtered."""
    return classify_cve_results(query, results)


def query_nvd(query: str, api_key: str | None = None) -> list[CVEResult]:
    """Query NVD by CPE name or keyword. Auto-detects query type."""
    if query.startswith("cpe:"):
        params = {"cpeName": query, "resultsPerPage": 50}
    elif _CVE_ID_RE.fullmatch(query.strip()):
        params = {"cveId": query.upper(), "resultsPerPage": 1}
    else:
        params = {"keywordSearch": query, "resultsPerPage": 50}

    data = _nvd_get(params, api_key)
    parsed = [_parse_cve_item(v) for v in data.get("vulnerabilities", [])]
    return classify_cve_results(query, parsed)


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
    by_id: dict[str, CVEResult] = {}

    for q in queries:
        try:
            results = query_nvd(q, api_key)
            for cve in results:
                previous = by_id.get(cve.cve_id)
                if previous is None or _COMPATIBILITY_ORDER.get(
                    cve.compatibility_status, _COMPATIBILITY_ORDER["indeterminate"]
                ) < _COMPATIBILITY_ORDER.get(
                    previous.compatibility_status, _COMPATIBILITY_ORDER["indeterminate"]
                ):
                    by_id[cve.cve_id] = cve
        except requests.RequestException as e:
            report.error = f"Query '{q}' failed: {e}"

    report.cves = sorted(
        by_id.values(),
        key=lambda c: (
            _COMPATIBILITY_ORDER.get(
                c.compatibility_status, _COMPATIBILITY_ORDER["indeterminate"]
            ),
            -(c.cvss_score or 0),
        ),
    )
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
