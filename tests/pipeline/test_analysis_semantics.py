"""Phase 3: finding semantics and rejection of unsupported claims."""
import json
from src.agent.exploit_evidence import (
    synthesize_exploit_result as _synthesize_exploit_result,
)
from src.agent.phases.analysis.evidence import (
    _enrich_finding_structure,
    _sanitize_suggested_tools,
)
from src.agent.finding_policy import (
    finding_semantic_issue as _finding_semantic_issue,
    normalise_full_finding_semantics as _normalise_full_finding_semantics,
)


def test_full_phase3_normalizes_nullable_schema_fields_without_changing_compact():
    compact_finding = {
        "service": "mysql",
        "protocol": "tcp",
        "endpoint": None,
        "product": "MariaDB",
        "version": "11.8",
    }
    _enrich_finding_structure(compact_finding)
    assert compact_finding["endpoint"] is None

    full_finding = dict(compact_finding)
    _enrich_finding_structure(full_finding, strict_schema=True)
    assert full_finding["endpoint"] == ""


def test_full_phase3_normalizes_application_protocol_to_transport():
    finding = {
        "service": "http",
        "protocol": "http",
        "endpoint": "/v1/devices/device-b",
        "product": "",
        "version": "",
    }
    _enrich_finding_structure(finding, strict_schema=True)
    assert finding["protocol"] == "tcp"


def test_s15_generic_api_fixture_is_not_a_model_finding():
    finding = {
        "type": "data_exposure",
        "service": "http",
        "port": 8080,
        "protocol": "tcp",
        "endpoint": "/credentials",
        "details": 'HTTP 200 body {"authentication":"enforced"} may expose credentials',
        "evidence": 'GET /credentials returned {"authentication":"enforced"}',
    }
    assert "generic API fixture" in _finding_semantic_issue(
        finding,
        source_kind="model",
        device_role="api_data_store",
    )


def test_s14_s19_profile_controls_and_role_mismatch_are_not_published():
    assert _finding_semantic_issue(
        {"type": "weak_cipher", "service": "ssh", "port": 22},
        source_kind="model", device_role="ssh_server", device_profile="hardened", scenario_id="S14",
    )
    assert "sparse contract" in _finding_semantic_issue(
        {"type": "weak_cipher", "service": "ssh", "port": 22},
        source_kind="model", device_role="ssh_server", device_profile="vulnerable", scenario_id="S14",
    )
    assert "non-SSH role" in _finding_semantic_issue(
        {"type": "weak_cipher", "service": "ssh", "port": 22},
        source_kind="model", device_role="mqtt_broker", scenario_id=19,
    )
    assert _finding_semantic_issue(
        {"type": "info_disclosure", "service": "bacnet", "port": 47808},
        source_kind="scanner_full", device_role="ot_bacnet_server", device_profile="hardened", scenario_id=19,
    )
    assert "Modbus role" in _finding_semantic_issue(
        {"type": "weak_cipher", "service": "ssh", "port": 22},
        source_kind="model", device_role="modbus_server", scenario_id=19,
    )


def test_s14_authenticated_redis_and_pki_metadata_are_rejected():
    redis_noauth = {
        "type": "no_auth", "service": "redis", "port": 6379,
        "details": "Redis PING returned -NOAUTH Authentication required",
    }
    assert "authentication" in _finding_semantic_issue(
        redis_noauth, source_kind="model", device_role="db_server_v2"
    )

    redis_data = {
        "type": "data_exposure", "service": "redis", "port": 6379,
        "details": "Unauthenticated Redis exposes credentials and secrets: database password and API keys",
    }
    assert "retrieved" in _finding_semantic_issue(
        redis_data, source_kind="model", device_role="db_server_v2"
    )

    pki_metadata = {
        "type": "info_disclosure", "service": "http", "port": 8080,
        "endpoint": "/identity/certificate",
        "details": "Device certificate is publicly accessible and reveals the public identity",
    }
    assert "PKI" in _finding_semantic_issue(
        pki_metadata, source_kind="model", device_role="pki_device"
    )


def test_suggested_tools_are_restricted_to_canonical_catalog_names():
    finding = {
        "suggested_tools": [
            "ssh-audit",
            "nmap ssh-vulnscan",
            "modbus-cli",
            "http_get",
            "mysql CLI client, sqlmap, Metasploit mysql_hashdump",
        ]
    }

    assert _sanitize_suggested_tools(
        finding, catalog_names={"ssh_audit", "http_get", "sqlmap"}
    ) == ["ssh_audit", "http_get", "sqlmap"]
    assert finding["suggested_tools"] == ["ssh_audit", "http_get", "sqlmap"]


def test_no_auth_nmap_open_port_requires_protocol_evidence():
    vuln = {
        "type": "no_auth", "service": "unknown",
        "device_ip": "192.0.2.12", "port": 1234,
    }
    open_only = _synthesize_exploit_result(
        vuln, [{
            "tool": "nmap_scan",
            "args": {"target": "192.0.2.12", "ports": "1234"},
            "result": json.dumps({
                "stdout": "1234/tcp open mystery", "return_code": 0,
            }),
        }],
    )
    assert open_only["status"] == "FAILED"

    protocol = _synthesize_exploit_result(
        vuln, [{
            "tool": "nmap_scan",
            "args": {"target": "192.0.2.12", "ports": "1234"},
            "result": json.dumps({
                "stdout": "1234/tcp open mystery\nAnonymous login allowed",
                "return_code": 0,
            }),
        }],
    )
    assert protocol["status"] == "EXPLOITED"


def test_model_finding_metadata_rejects_non_http_header_claims():
    assert "requires an HTTP" in _finding_semantic_issue({
        "type": "missing_header", "service": "telnet", "port": 23,
    })
    assert _finding_semantic_issue({
        "type": "missing_header", "service": "http", "port": 80,
    }) == ""


def test_semantic_contract_rejects_cross_family_findings():
    assert "plain HTTP" in _finding_semantic_issue({
        "type": "weak_cipher", "service": "http", "port": 80,
    })
    assert "not SSH or HTTP" in _finding_semantic_issue({
        "type": "insecure_protocol", "service": "ssh", "port": 22,
    })
    assert "intentional upload" in _finding_semantic_issue({
        "type": "directory_listing", "service": "http", "port": 80,
        "endpoint": "/uploads/",
    })
    assert "firmware binaries" in _finding_semantic_issue({
        "type": "data_exposure", "service": "http", "port": 80,
        "details": "firmware.bin is downloadable",
    })


def test_full_semantic_filters_reject_contradictory_claims():
    assert "contradicted" in _finding_semantic_issue(
        {
            "type": "no_auth",
            "service": "http",
            "port": 80,
            "details": "LuCI login returns HTTP 403 and requires authentication",
            "evidence": "HTTP 403",
        }
    )
    assert "speculative" in _finding_semantic_issue(
        {
            "type": "misconfiguration",
            "service": "ssh",
            "port": 22,
            "details": "Bastion may allow unrestricted TCP forwarding; no evidence of AllowTcpForwarding=no",
            "evidence": "SSH is open",
        }
    )
    assert "protocol properties" in _finding_semantic_issue(
        {
            "type": "insecure_protocol",
            "service": "modbus",
            "port": 502,
            "details": "Modbus protocol specification lacks authentication; traffic is plaintext and unauthenticated",
            "evidence": "Modbus protocol description",
        }
    )
    assert "platform fingerprint" in _finding_semantic_issue(
        {
            "type": "info_disclosure",
            "service": "network",
            "port": 0,
            "details": "MAC address identifies a Proxmox virtual machine",
            "evidence": "BC:24:11",
        }
    )


def test_full_semantic_normalization_preserves_precise_claim_types():
    listing = {
        "device_ip": "192.0.2.40",
        "type": "directory_listing",
        "service": "http",
        "port": 80,
        "endpoint": "/backup/",
        "details": "Directory listing enabled on /backup/",
        "evidence": "'Index of' found at /backup/",
    }
    exposure = {
        "device_ip": "192.0.2.40",
        "type": "data_exposure",
        "service": "http",
        "port": 80,
        "endpoint": "/backup/db.sql",
        "details": "SQL backup contains credentials",
        "evidence": "password=secret",
    }
    _normalise_full_finding_semantics(listing, [listing, exposure])
    assert listing["type"] == "data_exposure"

    coap = {
        "device_ip": "192.0.2.41",
        "type": "insecure_protocol",
        "service": "coap",
        "port": 5683,
        "details": "CoAP is accessible without DTLS",
    }
    _normalise_full_finding_semantics(coap, [coap])
    assert coap["type"] == "misconfiguration"

    mqtt = {
        "device_ip": "192.0.2.42",
        "type": "no_auth",
        "service": "mqtt",
        "port": 1883,
        "details": "MQTT accepts weak default credentials test:test",
    }
    _normalise_full_finding_semantics(mqtt, [mqtt])
    assert mqtt["type"] == "default_credentials"


def test_full_semantic_filter_rejects_redundant_claims_and_keeps_real_contracts():
    assert _finding_semantic_issue(
        {
            "type": "broken_access_control",
            "service": "http",
            "details": "API key exposed in a static configuration file",
        }
    ).startswith("broken_access_control requires")
    assert _finding_semantic_issue(
        {
            "type": "misconfiguration",
            "service": "ssh",
            "details": "ssh-auth-methods returned Not allowed at this time",
        }
    ).startswith("blocked or rate-limited")
    assert _finding_semantic_issue(
        {
            "type": "data_exposure",
            "service": "coap",
            "endpoint": "/sensor/data",
            "details": "sensor telemetry is available without encryption",
        }
    ).startswith("generic sensor telemetry")
    assert _finding_semantic_issue(
        {
            "type": "missing_header",
            "service": "http",
            "port": 80,
        },
        device_role="iot_gateway",
    ).startswith("generic gateway headers")
    assert _finding_semantic_issue(
        {
            "type": "info_disclosure",
            "service": "ssh",
            "details": "NIST P-256 elliptic curve suspected as backdoored",
        }
    ).startswith("SSH algorithm properties")


def test_full_semantic_filters_run_artifact_noise_without_losing_contracts():
    http_default = {
        "type": "default_credentials",
        "service": "http",
        "port": 80,
        "details": "Admin panel displays default creds admin:admin",
        "evidence": "GET /admin returned the text 'default creds admin:admin'",
    }
    assert "successful credential" in _finding_semantic_issue(http_default)

    http_success = {
        **http_default,
        "details": "Login with admin:admin succeeded",
        "evidence": "credential accepted and authenticated session returned",
    }
    assert _finding_semantic_issue(http_success) == ""

    ftp_default = {
        "type": "default_credentials",
        "service": "ftp",
        "port": 21,
        "details": "Anonymous FTP login allows access without authentication",
        "evidence": "FTP code 230",
    }
    assert "anonymous FTP" in _finding_semantic_issue(ftp_default)

    ftp_firmware = {
        "type": "insecure_update",
        "service": "ftp",
        "port": 21,
        "details": "Firmware directory is downloadable through anonymous FTP",
        "evidence": "firmware.bin listed in the directory",
    }
    assert "not an update mechanism" in _finding_semantic_issue(ftp_firmware)

    speculative_redis = {
        "type": "data_exposure",
        "service": "redis",
        "port": 6379,
        "details": "Stored keys may contain sensitive credentials and tokens",
        "evidence": "Redis is accessible without authentication",
    }
    assert "speculative data exposure" in _finding_semantic_issue(speculative_redis)

    modbus_noise = {
        "type": "insecure_protocol",
        "service": "modbus",
        "port": 502,
        "device_ip": "192.0.2.10",
        "details": "Modbus has no built-in encryption or authentication",
        "evidence": "502/tcp open",
    }
    modbus_auth = {
        "type": "no_auth",
        "service": "modbus",
        "port": 502,
        "device_ip": "192.0.2.10",
    }
    assert "proven no_auth" in _finding_semantic_issue(
        modbus_noise, context_findings=[modbus_noise, modbus_auth]
    )

    redis_bind = {
        "type": "misconfiguration",
        "service": "redis",
        "port": 6379,
        "device_ip": "192.0.2.11",
        "details": "Redis bind address: 0.0.0.0",
    }
    redis_auth = {
        "type": "no_auth",
        "service": "redis",
        "port": 6379,
        "device_ip": "192.0.2.11",
    }
    assert "proven no_auth" in _finding_semantic_issue(
        redis_bind, context_findings=[redis_bind, redis_auth]
    )

    assert "platform fingerprint" in _finding_semantic_issue({
        "type": "info_disclosure",
        "service": "modbus",
        "port": 502,
        "details": "Slave ID Pymodbus reveals implementation details",
    })

    listing = {
        "type": "directory_listing",
        "service": "http",
        "port": 80,
        "device_ip": "192.0.2.12",
        "endpoint": "/firmware/",
        "details": "Directory listing enabled on /firmware/; firmware files have no .sig or .sha256 sidecar",
        "evidence": "Index of found at /firmware/ and no signature files were listed",
    }
    _normalise_full_finding_semantics(
        listing, [listing], device_role="iot_gateway"
    )
    assert listing["type"] == "insecure_update"
    assert listing["severity"] == "HIGH"

    unproven_listing = {
        "type": "directory_listing",
        "service": "http",
        "port": 80,
        "device_ip": "192.0.2.13",
        "endpoint": "/firmware/",
        "details": "Directory listing enabled on /firmware/",
        "evidence": "Index of found at /firmware/",
    }
    _normalise_full_finding_semantics(
        unproven_listing, [unproven_listing], device_role="iot_gateway"
    )
    assert unproven_listing["type"] == "directory_listing"
    assert "lacks proof" in _finding_semantic_issue(
        unproven_listing, device_role="iot_gateway"
    )

    ssh_crypto = {
        "type": "misconfiguration",
        "service": "ssh",
        "port": 22,
        "details": "Terrapin mitigation still permits CBC ciphers and hmac-sha1",
    }
    _normalise_full_finding_semantics(ssh_crypto, [ssh_crypto])
    assert ssh_crypto["type"] == "weak_cipher"
