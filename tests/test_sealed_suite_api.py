from __future__ import annotations

import base64
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routes import sealed
from src.benchmark.contracts import (
    ContractError,
    SealedDataPolicy,
    SealedDeletionAttestation,
    SealedRunnerIdentity,
    SealedSuiteSummary,
)
from src.benchmark.controller import ControllerError, SealedControllerClient


SUITE_ID = "12345678-1234-5678-9234-567812345678"
RUNNER_IMAGE_DIGEST = "sha256:" + "a" * 64
HEADERS = {"X-Sealed-Launch-Token": "dashboard-secret"}
DATA_POLICY = {
    "inference_retention": "zero-data-retention",
    "improvement_use": "prohibited",
    "raw_artifact_retention": "delete-after-scoring",
    "feedback_visibility": "suite-aggregate-only",
}
DELETION_ATTESTATION = {
    "status": "deleted",
    "evidence_digest": "sha256:" + "e" * 64,
}


def _summary(status: str = "queued") -> SealedSuiteSummary:
    complete = status == "complete"
    terminal = status in {"complete", "failed", "cancelled", "expired"}
    return SealedSuiteSummary.from_dict(
        {
            "schema_version": "1",
            "suite_id": SUITE_ID,
            "benchmark_version": "2.0.0",
            "runner": {
                "model": "vendor/model-3b",
                "provider": "openrouter",
                "git_commit": "c" * 40,
                "runner_image_digest": RUNNER_IMAGE_DIGEST,
                "model_digest": "sha256:" + "d" * 64,
                "runner_image_digest": RUNNER_IMAGE_DIGEST,
            },
            "status": status,
            "score_visibility": "suite-aggregate",
            "data_policy": DATA_POLICY,
            "deletion_attestation": DELETION_ATTESTATION if terminal else None,
            "metrics": {"overall_score": 0.75, "f1": 0.7, "cost_usd": 1.25}
            if complete
            else None,
            "signature": "controller-signature" if terminal else None,
        }
    )


def _unsigned_complete_summary() -> SealedSuiteSummary:
    return SealedSuiteSummary(
        suite_id=SUITE_ID,
        benchmark_version="2.0.0",
        runner=SealedRunnerIdentity(
            model="vendor/model-3b",
            provider="openrouter",
            git_commit="c" * 40,
            model_digest="sha256:" + "d" * 64,
            runner_image_digest=RUNNER_IMAGE_DIGEST,
        ),
        status="complete",
        data_policy=SealedDataPolicy(),
        deletion_attestation=SealedDeletionAttestation(
            status="deleted",
            evidence_digest="sha256:" + "e" * 64,
        ),
        metrics={"overall_score": 0.75, "f1": 0.7, "cost_usd": 1.25},
        signature=None,
    )


def _signed_summary(
    private_key: Ed25519PrivateKey,
    status: str = "complete",
) -> SealedSuiteSummary:
    summary = (
        _unsigned_complete_summary()
        if status == "complete"
        else replace(_summary(status), signature=None)
    )
    signature = private_key.sign(summary.signature_payload())
    return replace(summary, signature=base64.b64encode(signature).decode("ascii"))


@pytest.fixture
def signing_key():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def configured_env(monkeypatch, signing_key):
    public_key = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    monkeypatch.setenv("SEALED_CONTROLLER_URL", "https://sealed-controller.internal")
    monkeypatch.setenv("SEALED_CONTROLLER_TOKEN", "controller-secret")
    monkeypatch.setenv("SEALED_LAUNCH_TOKEN", "dashboard-secret")
    monkeypatch.setenv("SEALED_ZERO_RETENTION_PROVIDERS", "openrouter, local-zdr")
    monkeypatch.setenv("SEALED_RUNNER_COMMIT", "c" * 40)
    monkeypatch.setenv("SEALED_RUNNER_IMAGE_DIGEST", RUNNER_IMAGE_DIGEST)
    monkeypatch.setenv(
        "SEALED_CONTROLLER_PUBLIC_KEY",
        base64.b64encode(public_key).decode("ascii"),
    )
    return signing_key


@pytest.fixture
def api_client():
    app = FastAPI()
    app.include_router(sealed.router, prefix="/api/sealed")
    return TestClient(app)


class _FakeController:
    instances: list["_FakeController"] = []
    returned_summary = _summary()
    fail_with: str | None = None

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url
        self.token = token
        self.calls: list[tuple] = []
        self.closed = False
        type(self).instances.append(self)

    def close(self):
        self.closed = True

    def _maybe_fail(self):
        if type(self).fail_with:
            raise ControllerError(type(self).fail_with)

    def create_suite(self, **kwargs):
        self._maybe_fail()
        self.calls.append(("create", kwargs))
        return type(self).returned_summary

    def get_suite(self, suite_id: str):
        self._maybe_fail()
        self.calls.append(("get", suite_id))
        return replace(type(self).returned_summary, suite_id=suite_id)

    def cancel_suite(self, suite_id: str):
        self._maybe_fail()
        self.calls.append(("cancel", suite_id))


@pytest.fixture
def fake_controller(monkeypatch):
    _FakeController.instances = []
    _FakeController.returned_summary = _summary()
    _FakeController.fail_with = None
    monkeypatch.setattr(sealed, "SealedControllerClient", _FakeController)
    return _FakeController


def test_suite_contract_is_exact_and_suite_aggregate_only():
    parsed = _summary("complete")
    assert parsed.to_dict() == {
        "schema_version": "1",
        "suite_id": SUITE_ID,
        "benchmark_version": "2.0.0",
        "runner": {
            "model": "vendor/model-3b",
            "provider": "openrouter",
            "git_commit": "c" * 40,
            "model_digest": "sha256:" + "d" * 64,
            "runner_image_digest": RUNNER_IMAGE_DIGEST,
        },
        "status": "complete",
        "score_visibility": "suite-aggregate",
        "data_policy": DATA_POLICY,
        "deletion_attestation": DELETION_ATTESTATION,
        "metrics": {"overall_score": 0.75, "f1": 0.7, "cost_usd": 1.25},
        "signature": "controller-signature",
    }

    for forbidden in ("scenario_id", "progress", "logs", "events", "error"):
        payload = parsed.to_dict()
        payload[forbidden] = "oracle-canary"
        with pytest.raises(ContractError, match="forbidden/unknown"):
            SealedSuiteSummary.from_dict(payload)

    leaked_runner = parsed.to_dict()
    leaked_runner["runner"]["scenario_id"] = "20"
    with pytest.raises(ContractError, match="forbidden/unknown"):
        SealedSuiteSummary.from_dict(leaked_runner)

    uncommitted_model = parsed.to_dict()
    uncommitted_model["runner"]["model_digest"] = "unknown"
    with pytest.raises(ContractError, match="sha256 digest"):
        SealedSuiteSummary.from_dict(uncommitted_model)

    mutable_runner_image = parsed.to_dict()
    mutable_runner_image["runner"]["runner_image_digest"] = "runner:latest"
    with pytest.raises(ContractError, match="OCI sha256 digest"):
        SealedSuiteSummary.from_dict(mutable_runner_image)


def test_unsigned_complete_suite_has_byte_exact_interoperable_signing_payload():
    unsigned = _unsigned_complete_summary()

    assert unsigned.signature is None
    assert unsigned.signature_payload() == (
        b'["iotchainbench.sealed-suite.ed25519.v1","1",'
        b'"12345678-1234-5678-9234-567812345678","2.0.0",'
        b'"dmVuZG9yL21vZGVsLTNi","b3BlbnJvdXRlcg",'
        b'"cccccccccccccccccccccccccccccccccccccccc",'
        b'"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",'
        b'"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"complete","suite-aggregate",'
        b'["zero-data-retention","prohibited","delete-after-scoring",'
        b'"suite-aggregate-only"],'
        b'["deleted",'
        b'"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"],'
        b'[["cost_usd","3ff4000000000000"],["f1","3fe6666666666666"],'
        b'["overall_score","3fe8000000000000"]]]'
    )


def test_signature_payload_normalizes_equivalent_json_numbers():
    integer_payload = _summary("complete").to_dict()
    integer_payload["metrics"] = {"overall_score": 1}
    float_payload = _summary("complete").to_dict()
    float_payload["metrics"] = {"overall_score": 1.0}

    integer_summary = SealedSuiteSummary.from_dict(integer_payload)
    float_summary = SealedSuiteSummary.from_dict(float_payload)

    assert integer_summary.signature_payload() == float_summary.signature_payload()


def test_complete_suite_requires_exact_data_policy_and_deletion_attestation():
    missing_receipt = _summary("complete").to_dict()
    missing_receipt["deletion_attestation"] = None
    with pytest.raises(ContractError, match="deletion attestation"):
        SealedSuiteSummary.from_dict(missing_receipt)

    changed_policy = _summary("complete").to_dict()
    changed_policy["data_policy"]["improvement_use"] = "allowed"
    with pytest.raises(ContractError, match="improvement_use"):
        SealedSuiteSummary.from_dict(changed_policy)


@pytest.mark.parametrize("status", ["queued", "running"])
def test_active_suite_never_exposes_terminal_attestation(status):
    payload = _summary(status).to_dict()
    payload["signature"] = "too-early"
    payload["deletion_attestation"] = DELETION_ATTESTATION
    with pytest.raises(ContractError, match="must not expose"):
        SealedSuiteSummary.from_dict(payload)


@pytest.mark.parametrize("status", ["failed", "cancelled", "expired"])
def test_non_complete_terminal_suite_requires_signed_deletion_and_no_metrics(status):
    terminal = _summary(status)
    assert terminal.metrics is None
    assert terminal.deletion_attestation is not None
    assert terminal.signature == "controller-signature"

    leaked_metrics = terminal.to_dict()
    leaked_metrics["metrics"] = {"overall_score": 0.1}
    with pytest.raises(ContractError, match="only complete"):
        SealedSuiteSummary.from_dict(leaked_metrics)

    missing_receipt = terminal.to_dict()
    missing_receipt["deletion_attestation"] = None
    with pytest.raises(ContractError, match="deletion attestation"):
        SealedSuiteSummary.from_dict(missing_receipt)

    missing_signature = terminal.to_dict()
    missing_signature["signature"] = None
    with pytest.raises(ContractError, match="sealed suite signature"):
        SealedSuiteSummary.from_dict(missing_signature)


@pytest.mark.parametrize("status", ["failed", "cancelled", "expired"])
def test_terminal_signature_payload_binds_status_and_has_empty_metrics(signing_key, status):
    unsigned = replace(
        _unsigned_complete_summary(),
        status=status,
        metrics=None,
    )
    payload = unsigned.signature_payload()
    assert payload.endswith(b",[]]")

    signature = signing_key.sign(payload)
    signed = replace(
        unsigned,
        signature=base64.b64encode(signature).decode("ascii"),
    )
    parsed = SealedSuiteSummary.from_dict(signed.to_dict())
    signing_key.public_key().verify(signature, parsed.signature_payload())


def test_launch_is_authenticated_allowlisted_stateless_and_no_store(
    api_client, configured_env, fake_controller
):
    response = api_client.post(
        "/api/sealed/suites",
        headers=HEADERS,
        json={
            "model": "vendor/model-3b",
            "provider": "OpenRouter",
        },
    )

    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.json() == _summary().to_dict()
    serialized = response.text
    assert all(term not in serialized for term in ("scenario_id", "progress", "logs", "events"))
    assert len(fake_controller.instances) == 1
    instance = fake_controller.instances[0]
    assert instance.base_url == "https://sealed-controller.internal"
    assert instance.token == "controller-secret"
    assert instance.calls == [
        (
            "create",
                {
                    "model": "vendor/model-3b",
                    "provider": "openrouter",
                    "git_commit": "c" * 40,
                    "runner_image_digest": RUNNER_IMAGE_DIGEST,
                },
        )
    ]
    assert instance.closed is True


def test_poll_and_cancel_create_fresh_clients_without_local_state(
    api_client, configured_env, fake_controller
):
    fake_controller.returned_summary = _signed_summary(configured_env)

    poll = api_client.get(f"/api/sealed/suites/{SUITE_ID}", headers=HEADERS)
    cancel = api_client.delete(f"/api/sealed/suites/{SUITE_ID}", headers=HEADERS)

    assert poll.status_code == 200
    assert poll.json()["score_visibility"] == "suite-aggregate"
    assert poll.json()["metrics"]["overall_score"] == 0.75
    assert cancel.status_code == 202
    assert cancel.json() == {"status": "cancellation-requested"}
    assert len(fake_controller.instances) == 2
    assert fake_controller.instances[0].calls == [("get", SUITE_ID)]
    assert fake_controller.instances[1].calls == [("cancel", SUITE_ID)]
    assert all(instance.closed for instance in fake_controller.instances)


@pytest.mark.parametrize(
    "missing",
    [
        "SEALED_CONTROLLER_URL",
        "SEALED_CONTROLLER_TOKEN",
        "SEALED_LAUNCH_TOKEN",
        "SEALED_ZERO_RETENTION_PROVIDERS",
        "SEALED_RUNNER_COMMIT",
        "SEALED_RUNNER_IMAGE_DIGEST",
        "SEALED_CONTROLLER_PUBLIC_KEY",
    ],
)
def test_api_is_disabled_fail_closed_when_configuration_is_missing(
    api_client, configured_env, fake_controller, monkeypatch, missing
):
    monkeypatch.delenv(missing)
    response = api_client.get(f"/api/sealed/suites/{SUITE_ID}", headers=HEADERS)
    assert response.status_code == 503
    assert response.json() == {"detail": "Sealed evaluation is unavailable"}
    assert fake_controller.instances == []


def test_auth_and_zero_retention_provider_allowlist_are_enforced(
    api_client, configured_env, fake_controller
):
    missing_auth = api_client.get(f"/api/sealed/suites/{SUITE_ID}")
    wrong_auth = api_client.get(
        f"/api/sealed/suites/{SUITE_ID}",
        headers={"X-Sealed-Launch-Token": "wrong"},
    )
    denied_provider = api_client.post(
        "/api/sealed/suites",
        headers=HEADERS,
        json={"model": "vendor/model", "provider": "retaining-provider"},
    )

    assert missing_auth.status_code == wrong_auth.status_code == 401
    assert denied_provider.status_code == 400
    assert denied_provider.json() == {
        "detail": "Provider is not approved for sealed evaluation"
    }
    assert fake_controller.instances == []


def test_wildcard_provider_allowlist_disables_api(
    api_client, configured_env, fake_controller, monkeypatch
):
    monkeypatch.setenv("SEALED_ZERO_RETENTION_PROVIDERS", "*")
    response = api_client.post(
        "/api/sealed/suites",
        headers=HEADERS,
        json={"model": "vendor/model", "provider": "anything"},
    )
    assert response.status_code == 503
    assert fake_controller.instances == []


def test_controller_public_key_accepts_pem_and_base64_raw(signing_key):
    public_key = signing_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    message = b"sealed-attestation-test"
    signature = signing_key.sign(message)

    sealed._load_ed25519_public_key(pem).verify(signature, message)
    sealed._load_ed25519_public_key(base64.b64encode(raw).decode("ascii")).verify(
        signature, message
    )


def test_controller_errors_are_generic_and_never_echo_oracle_data(
    api_client, configured_env, fake_controller
):
    fake_controller.fail_with = "oracle-canary hidden topology and raw logs"
    response = api_client.get(f"/api/sealed/suites/{SUITE_ID}", headers=HEADERS)
    assert response.status_code == 502
    assert response.json() == {
        "detail": "Sealed evaluation controller is unavailable"
    }
    assert "oracle-canary" not in response.text


def test_unverified_complete_score_is_never_exposed(
    api_client, configured_env, fake_controller
):
    fake_controller.returned_summary = _summary("complete")
    response = api_client.get(f"/api/sealed/suites/{SUITE_ID}", headers=HEADERS)
    assert response.status_code == 502
    assert response.json() == {
        "detail": "Sealed evaluation controller is unavailable"
    }
    assert "overall_score" not in response.text
    assert "controller-signature" not in response.text


@pytest.mark.parametrize("status", ["failed", "cancelled", "expired"])
def test_every_terminal_status_requires_a_valid_signature_and_deletion(
    api_client, configured_env, fake_controller, status
):
    fake_controller.returned_summary = _summary(status)
    rejected = api_client.get(f"/api/sealed/suites/{SUITE_ID}", headers=HEADERS)
    assert rejected.status_code == 502
    assert "evidence_digest" not in rejected.text

    fake_controller.returned_summary = _signed_summary(configured_env, status)
    accepted = api_client.get(f"/api/sealed/suites/{SUITE_ID}", headers=HEADERS)
    assert accepted.status_code == 200
    assert accepted.json()["status"] == status
    assert accepted.json()["metrics"] is None
    assert accepted.json()["deletion_attestation"]["status"] == "deleted"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("git_commit", "b" * 40),
        ("runner_image_digest", "sha256:" + "b" * 64),
        ("provider", "retaining-provider"),
    ],
)
def test_poll_rejects_a_signed_result_for_another_runner_identity(
    api_client, configured_env, fake_controller, field, value
):
    signed = _signed_summary(configured_env)
    fake_controller.returned_summary = replace(
        signed,
        runner=replace(signed.runner, **{field: value}),
    )

    response = api_client.get(f"/api/sealed/suites/{SUITE_ID}", headers=HEADERS)
    assert response.status_code == 502
    assert "overall_score" not in response.text


def test_deletion_attestation_is_bound_by_signature(
    api_client, configured_env, fake_controller
):
    signed = _signed_summary(configured_env)
    fake_controller.returned_summary = replace(
        signed,
        deletion_attestation=SealedDeletionAttestation(
            status="deleted",
            evidence_digest="sha256:" + "f" * 64,
        ),
    )

    response = api_client.get(f"/api/sealed/suites/{SUITE_ID}", headers=HEADERS)

    assert response.status_code == 502
    assert response.json() == {
        "detail": "Sealed evaluation controller is unavailable"
    }
    assert "overall_score" not in response.text
    assert "evidence_digest" not in response.text


def test_client_cannot_spoof_trusted_runner_commit(
    api_client, configured_env, fake_controller
):
    response = api_client.post(
        "/api/sealed/suites",
        headers=HEADERS,
        json={
            "model": "vendor/model",
            "provider": "openrouter",
            "git_commit": "d" * 40,
        },
    )
    assert response.status_code == 422
    assert fake_controller.instances == []


class _Response:
    headers: dict[str, str] = {}

    def __init__(self, payload, status_code=201):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class _RecordingSession:
    def __init__(self, payload, status_code=201):
        self.payload = payload
        self.status_code = status_code
        self.requests: list[dict] = []
        self.closed = False

    def request(self, method, url, **kwargs):
        self.requests.append({"method": method, "url": url, **kwargs})
        return _Response(self.payload, self.status_code)

    def close(self):
        self.closed = True


def test_controller_suite_launch_commits_aggregate_and_zero_retention_policies():
    initial = replace(
        _summary(),
        runner=replace(_summary().runner, git_commit="b" * 40),
    )
    session = _RecordingSession(initial.to_dict())
    client = SealedControllerClient(
        "https://sealed-controller.internal",
        "controller-secret",
        session=session,
    )
    try:
        result = client.create_suite(
            model="vendor/model-3b",
            provider="openrouter",
            git_commit="b" * 40,
            runner_image_digest=RUNNER_IMAGE_DIGEST,
        )
    finally:
        client.close()

    assert result == initial
    request = session.requests[0]
    assert request["method"] == "POST"
    assert request["url"] == "https://sealed-controller.internal/v1/suites"
    assert request["json"] == {
        "benchmark_version": "2.0.0",
        "runner": {
            "model": "vendor/model-3b",
            "provider": "openrouter",
            "git_commit": "b" * 40,
            "runner_image_digest": RUNNER_IMAGE_DIGEST,
        },
        "score_visibility": "suite-aggregate",
        "data_policy": DATA_POLICY,
    }
    assert request["headers"]["Cache-Control"] == "no-store"
    assert request["headers"]["Authorization"] == "Bearer controller-secret"
    assert request["allow_redirects"] is False


def test_controller_requires_and_matches_immutable_runner_image_digest():
    initial = _summary()
    session = _RecordingSession(initial.to_dict())
    client = SealedControllerClient(
        "https://sealed-controller.internal",
        "controller-secret",
        session=session,
    )
    try:
        with pytest.raises(ControllerError, match="OCI sha256 digest"):
            client.create_suite(
                model="vendor/model-3b",
                provider="openrouter",
                git_commit="c" * 40,
                runner_image_digest="runner:latest",
            )

        with pytest.raises(ControllerError, match="mismatched sealed runner identity"):
            client.create_suite(
                model="vendor/model-3b",
                provider="openrouter",
                git_commit="c" * 40,
                runner_image_digest="sha256:" + "b" * 64,
            )
    finally:
        client.close()

    assert len(session.requests) == 1


def test_controller_rejects_detailed_suite_response():
    payload = _summary().to_dict()
    payload["progress"] = {"scenario": "S20", "percent": 50}
    session = _RecordingSession(payload)
    client = SealedControllerClient(
        "https://sealed-controller.internal",
        "controller-secret",
        session=session,
    )
    try:
        with pytest.raises(ControllerError, match="invalid sealed suite summary"):
            client.create_suite(
                model="vendor/model-3b",
                provider="openrouter",
                git_commit="c" * 40,
                runner_image_digest=RUNNER_IMAGE_DIGEST,
            )
    finally:
        client.close()


def test_controller_poll_and_cancel_use_suite_level_endpoints_only():
    poll_session = _RecordingSession(_summary("complete").to_dict(), status_code=200)
    poll_client = SealedControllerClient(
        "https://sealed-controller.internal",
        "controller-secret",
        session=poll_session,
    )
    try:
        assert poll_client.get_suite(SUITE_ID) == _summary("complete")
    finally:
        poll_client.close()
    assert poll_session.requests[0]["method"] == "GET"
    assert poll_session.requests[0]["url"].endswith(f"/v1/suites/{SUITE_ID}")

    cancel_session = _RecordingSession({}, status_code=204)
    cancel_client = SealedControllerClient(
        "https://sealed-controller.internal",
        "controller-secret",
        session=cancel_session,
    )
    try:
        cancel_client.cancel_suite(SUITE_ID)
    finally:
        cancel_client.close()
    assert cancel_session.requests[0]["method"] == "DELETE"
    assert cancel_session.requests[0]["url"].endswith(f"/v1/suites/{SUITE_ID}")
