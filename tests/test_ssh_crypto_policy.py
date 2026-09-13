from src.agent.evidence.ssh import SSH_CRYPTO_POLICY_VERSION, assess_ssh_crypto


def test_historical_removal_annotation_does_not_erase_observed_server_algorithm():
    result = assess_ssh_crypto(
        "(key) ssh-rsa -- [warn] disabled in OpenSSH 8.8"
    )
    assert result["status"] == "policy_violation"
    assert result["disallowed_algorithms"][0]["name"] == "ssh-rsa"


def test_assess_exact_observed_rows_and_policy_violation():
    result = assess_ssh_crypto(
        "\n".join([
            "(kex) diffie-hellman-group14-sha1",
            "(key) ssh-rsa",
            "(enc) aes128-ctr",
            "(mac) hmac-sha1",
            "(mac) hmac-md5-96",
        ])
    )

    assert result["policy_version"] == SSH_CRYPTO_POLICY_VERSION
    assert result["observed_algorithms"] == [
        {"category": "kex", "name": "diffie-hellman-group14-sha1"},
        {"category": "key", "name": "ssh-rsa"},
        {"category": "enc", "name": "aes128-ctr"},
        {"category": "mac", "name": "hmac-sha1"},
        {"category": "mac", "name": "hmac-md5-96"},
    ]
    assert result["status"] == "policy_violation"
    assert {item["name"] for item in result["disallowed_algorithms"]} == {
        "diffie-hellman-group14-sha1", "ssh-rsa", "hmac-md5-96",
    }
    assert all(item["reason"] for item in result["disallowed_algorithms"])


def test_casefolds_categories_names_and_strips_ansi():
    result = assess_ssh_crypto(
        "\x1b[1m(KEX) DIFFIE-HELLMAN-GROUP1-SHA1\x1b[0m\n"
        "\x1b[32m(MAC) HMAC-SHA1\x1b[0m"
    )

    assert result["observed_algorithms"] == [
        {"category": "kex", "name": "diffie-hellman-group1-sha1"},
        {"category": "mac", "name": "hmac-sha1"},
    ]
    assert result["status"] == "policy_violation"


def test_accepts_ssh_audit_annotations_and_structured_key_size():
    result = assess_ssh_crypto(
        "\n".join([
            "(enc) aes128-cbc -- [warn] weak cipher mode",
            "(key) ssh-rsa (2048-bit) -- [fail] SHA-1 signature",
            "(kex) diffie-hellman-group14-sha1 -- [fail] deprecated",
        ])
    )

    assert result["observed_algorithms"] == [
        {"category": "enc", "name": "aes128-cbc"},
        {"category": "key", "name": "ssh-rsa"},
        {"category": "kex", "name": "diffie-hellman-group14-sha1"},
    ]
    assert result["status"] == "policy_violation"


def test_hmac_sha1_alone_is_observed_not_a_violation():
    result = assess_ssh_crypto("(mac) hmac-sha1")

    assert result["status"] == "observed"
    assert result["disallowed_algorithms"] == []


def test_ignores_warnings_recommendations_prose_and_non_exact_bad_names():
    result = assess_ssh_crypto(
        "\n".join([
            "[warn] (enc) aes128-cbc",
            "(rec) disable aes128-cbc",
            "Recommendations: disable 3des-cbc and ssh-rsa",
            "The server may use diffie-hellman-group1-sha1",
            "(enc) aes128-cbc-extra",
            "(mac) hmac-md5-96x",
        ])
    )

    assert result["status"] == "observed"
    assert result["observed_algorithms"] == [
        {"category": "enc", "name": "aes128-cbc-extra"},
        {"category": "mac", "name": "hmac-md5-96x"},
    ]
    assert result["disallowed_algorithms"] == []


def test_rejects_unstructured_negating_annotation():
    result = assess_ssh_crypto("(enc) aes128-cbc -- not supported")

    assert result["status"] == "unverifiable"
    assert result["observed_algorithms"] == []
    assert result["disallowed_algorithms"] == []


def test_exact_category_boundaries_and_finite_policy():
    result = assess_ssh_crypto(
        "\n".join([
            "(kex) diffie-hellman-group14-sha1x",
            "(key) ssh-rsa-cert-v01@openssh.com",
            "(enc) arcfour128",
            "(mac) hmac-md5",
            "(key) nistp256",
        ])
    )

    assert result["status"] == "policy_violation"
    assert result["disallowed_algorithms"] == [
        {"category": "enc", "name": "arcfour128", "reason": "disallowed cipher"},
        {"category": "mac", "name": "hmac-md5", "reason": "disallowed MAC algorithm"},
    ]


def test_no_observation_is_unverifiable_and_does_not_infer_crypto_failure():
    result = assess_ssh_crypto(
        "[fail] NSA/NIST curves are suspect; use modern cryptography instead"
    )

    assert result == {
        "policy_version": SSH_CRYPTO_POLICY_VERSION,
        "observed_algorithms": [],
        "disallowed_algorithms": [],
        "status": "unverifiable",
    }


def test_truncated_server_output_does_not_infer_absent_secure_algorithms():
    result = assess_ssh_crypto("Server: SSH-2.0-OpenSSH_8.8\n(kex) curve25519-sha256")

    assert result["status"] == "observed"
    assert result["observed_algorithms"] == [
        {"category": "kex", "name": "curve25519-sha256"},
    ]
    assert "secure_algorithms_absent" not in result
