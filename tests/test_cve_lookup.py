"""Tests for NVD CVE lookup module (mocked HTTP, no real API calls)."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.cve_lookup import (
    CVEResult,
    DeviceCVEReport,
    _parse_cve_item,
    classify_cve_compatibility,
    classify_cve_results,
    cve_matches_query,
    load_cpe_mapping,
    query_nvd,
    scan_device,
)

CPE_MAPPING_PATH = (
    Path(__file__).resolve().parent.parent / "infrastructure" / "cpe_mapping.yaml"
)

ROUTEROS_CONFIGURATIONS = [{
    "nodes": [{
        "operator": "OR",
        "cpeMatch": [{
            "vulnerable": True,
            "criteria": "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "7.0",
            "versionEndExcluding": "7.19",
        }],
    }],
}]

SAMPLE_CVE_ITEM = {
    "cve": {
        "id": "CVE-2023-12345",
        "descriptions": [
            {"lang": "en", "value": "A test vulnerability in RouterOS."}
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                        "attackVector": "NETWORK",
                    }
                }
            ]
        },
        "configurations": ROUTEROS_CONFIGURATIONS,
    }
}

SAMPLE_CVE_ITEM_NO_METRICS = {
    "cve": {
        "id": "CVE-2024-99999",
        "descriptions": [
            {"lang": "en", "value": "A CVE with no CVSS score yet."}
        ],
        "metrics": {},
        "configurations": ROUTEROS_CONFIGURATIONS,
    }
}

SAMPLE_NVD_RESPONSE = {
    "resultsPerPage": 2,
    "startIndex": 0,
    "totalResults": 2,
    "vulnerabilities": [SAMPLE_CVE_ITEM, SAMPLE_CVE_ITEM_NO_METRICS],
}


class TestParseCVEItem:
    def test_parse_with_cvss31(self):
        result = _parse_cve_item(SAMPLE_CVE_ITEM)
        assert result.cve_id == "CVE-2023-12345"
        assert result.cvss_score == 7.5
        assert result.severity == "HIGH"
        assert result.attack_vector == "NETWORK"
        assert "RouterOS" in result.description
        assert result.cpe_matches[0]["versionEndExcluding"] == "7.19"

    def test_parse_without_metrics(self):
        result = _parse_cve_item(SAMPLE_CVE_ITEM_NO_METRICS)
        assert result.cve_id == "CVE-2024-99999"
        assert result.cvss_score is None
        assert result.severity is None
        assert result.attack_vector is None

    def test_parse_cvss_v2_fallback(self):
        item = {
            "cve": {
                "id": "CVE-2020-11111",
                "descriptions": [{"lang": "en", "value": "Old CVE."}],
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "cvssData": {
                                "baseScore": 5.0,
                                "baseSeverity": "MEDIUM",
                                "attackVector": "NETWORK",
                            }
                        }
                    ]
                },
            }
        }
        result = _parse_cve_item(item)
        assert result.cvss_score == 5.0


class TestQueryNVD:
    @patch("src.cve_lookup._nvd_get")
    def test_query_by_cpe(self, mock_get):
        mock_get.return_value = SAMPLE_NVD_RESPONSE
        results = query_nvd("cpe:2.3:o:mikrotik:routeros:7.18.2:*:*:*:*:*:*:*")
        assert len(results) == 2
        assert results[0].cve_id == "CVE-2023-12345"
        mock_get.assert_called_once()
        call_params = mock_get.call_args[0][0]
        assert "cpeName" in call_params

    @patch("src.cve_lookup._nvd_get")
    def test_query_by_keyword(self, mock_get):
        mock_get.return_value = SAMPLE_NVD_RESPONSE
        results = query_nvd("TP-LINK EAP613")
        assert len(results) == 2
        call_params = mock_get.call_args[0][0]
        assert "keywordSearch" in call_params

    @patch("src.cve_lookup._nvd_get")
    def test_query_by_exact_cve_id_is_not_version_filtered(self, mock_get):
        mock_get.return_value = SAMPLE_NVD_RESPONSE
        results = query_nvd("CVE-2023-12345")
        assert len(results) == 2
        assert mock_get.call_args[0][0]["cveId"] == "CVE-2023-12345"


class TestCVECompatibility:
    @staticmethod
    def match(criteria: str, **bounds) -> list[dict]:
        return [{"criteria": criteria, **bounds}]

    def test_terrapin_matches_openssh_92_but_not_96(self):
        matches = self.match(
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            versionEndExcluding="9.6",
        )
        assert cve_matches_query("OpenSSH 9.2", matches)
        assert not cve_matches_query("OpenSSH 9.6", matches)

    def test_old_openssh_cve_is_rejected_for_modern_version(self):
        matches = self.match(
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            versionEndIncluding="2.9",
        )
        assert not cve_matches_query("OpenSSH 9.2", matches)

    def test_old_nginx_cve_is_rejected_for_nginx_122(self):
        matches = self.match(
            "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
            versionEndExcluding="1.14.1",
        )
        assert not cve_matches_query("nginx 1.22", matches)

    def test_product_mismatch_is_rejected(self):
        mysql_matches = self.match(
            "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
            versionEndIncluding="5.6",
        )
        assert not cve_matches_query("openSUSE Leap 5.6", mysql_matches)

    def test_exact_mosquitto_version_matches(self):
        matches = self.match(
            "cpe:2.3:a:eclipse:mosquitto:2.0.21:*:*:*:*:*:*:*"
        )
        assert cve_matches_query("mosquitto version 2.0.21", matches)
        assert not cve_matches_query("mosquitto version 2.0.20", matches)

    def test_common_apache_alias_matches_http_server_cpe(self):
        matches = self.match(
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            versionEndExcluding="2.4.50",
        )
        assert cve_matches_query("Apache 2.4.49", matches)

    def test_not_applicable_cpe_version_does_not_match_numeric_version(self):
        matches = self.match("cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*")
        assert not cve_matches_query("product 1.0", matches)

    def test_product_only_query_remains_available(self):
        assert cve_matches_query("OpenSSH", [])

    def test_product_only_and_missing_config_are_indeterminate(self):
        assert classify_cve_compatibility("OpenSSH", []).status == "indeterminate"
        assert classify_cve_compatibility("OpenSSH 9.2", []).status == "indeterminate"

    def test_conditional_match_is_not_promoted_to_unconditional(self):
        matches = self.match(
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            versionEndExcluding="9.6",
            conditional=True,
        )
        assert classify_cve_compatibility("OpenSSH 9.2", matches).status == "conditional"

    def test_classification_keeps_and_ranks_all_results(self):
        compatible = CVEResult(
            "CVE-2023-48795", "Terrapin", cpe_matches=self.match(
                "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                versionEndExcluding="9.6",
            )
        )
        incompatible = CVEResult(
            "CVE-2001-0572", "Old OpenSSH", cpe_matches=self.match(
                "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                versionEndIncluding="2.9",
            )
        )
        ranked = classify_cve_results("OpenSSH 9.2", [incompatible, compatible])
        assert ranked == [compatible, incompatible]
        assert compatible.compatibility_status == "compatible"
        assert incompatible.compatibility_status == "incompatible"


class TestScanDevice:
    @patch("src.cve_lookup.query_nvd")
    def test_deduplication(self, mock_query):
        cve1 = CVEResult("CVE-2023-12345", "desc1", 7.5, "HIGH", "NETWORK")
        cve2 = CVEResult("CVE-2024-99999", "desc2", 5.0, "MEDIUM", "LOCAL")
        # Both queries return the same CVE-2023-12345
        mock_query.side_effect = [[cve1, cve2], [cve1]]

        report = scan_device("mikrotik", "MikroTik RB5009", ["query1", "query2"])
        assert len(report.cves) == 2  # deduplicated
        assert report.device_id == "mikrotik"

    @patch("src.cve_lookup.query_nvd")
    def test_deduplication_keeps_best_compatibility_assessment(self, mock_query):
        incompatible = CVEResult(
            "CVE-2023-12345", "first", 9.8, compatibility_status="incompatible"
        )
        compatible = CVEResult(
            "CVE-2023-12345", "better evidence", 7.5,
            compatibility_status="compatible",
        )
        mock_query.side_effect = [[incompatible], [compatible]]

        report = scan_device("device", "Device", ["query1", "query2"])

        assert report.cves == [compatible]

    @patch("src.cve_lookup.query_nvd")
    def test_sorted_by_score(self, mock_query):
        cve_low = CVEResult("CVE-0001", "low", 2.0, "LOW", "LOCAL")
        cve_high = CVEResult("CVE-0002", "high", 9.8, "CRITICAL", "NETWORK")
        mock_query.return_value = [cve_low, cve_high]

        report = scan_device("test", "Test Device", ["query"])
        assert report.cves[0].cvss_score == 9.8
        assert report.cves[1].cvss_score == 2.0

    @patch("src.cve_lookup.query_nvd")
    def test_error_handling(self, mock_query):
        import requests as req
        mock_query.side_effect = req.RequestException("Connection refused")

        report = scan_device("test", "Test", ["query"])
        assert report.error is not None
        assert "failed" in report.error


class TestLoadCPEMapping:
    def test_loads_mapping_file(self):
        mapping = load_cpe_mapping(CPE_MAPPING_PATH)
        assert "mikrotik" in mapping
        assert isinstance(mapping["mikrotik"], list)
        assert mapping["mikrotik"][0].startswith("cpe:")

    def test_wisgate_has_multiple_entries(self):
        mapping = load_cpe_mapping(CPE_MAPPING_PATH)
        assert len(mapping["wisgate"]) == 2


class TestRateLimiter:
    @patch("src.cve_lookup.time")
    def test_rate_limit_sleeps_when_full(self, mock_time):
        from src.cve_lookup import _rate_limit, _request_timestamps

        _request_timestamps.clear()
        mock_time.time.return_value = 100.0
        mock_time.sleep = MagicMock()

        # Fill up the window (5 requests without API key)
        for _ in range(5):
            _request_timestamps.append(100.0)

        _rate_limit(has_api_key=False)
        mock_time.sleep.assert_called_once()
        _request_timestamps.clear()
