"""Strict, non-executing SSH crypto evidence assessment.

Only ssh-audit algorithm rows from the server's observed output are evidence:
``(kex) ALGORITHM``, ``(key) ALGORITHM``, ``(enc) ALGORITHM`` and
``(mac) ALGORITHM``.  Warnings, recommendations and prose are deliberately
ignored.  The finite policy is a configuration of findings, not an execution
or exploit claim.

Methodological references:
* RFC 9142: https://www.rfc-editor.org/rfc/rfc9142
* OpenSSH 8.8 release notes: https://www.openssh.org/txt/release-8.8
* NIST SP 800-186: https://doi.org/10.6028/NIST.SP.800-186
"""
from __future__ import annotations

import re
from typing import Final


SSH_CRYPTO_POLICY_VERSION: Final[str] = "ssh-crypto-policy-v1"

_ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_OBSERVED_ROW = re.compile(
    r"^\((kex|key|enc|mac)\)\s+([^\s()]+)"
    r"(?:\s+\(\d+-bit\))?"
    r"(?:\s+--\s+\[(?:warn|fail|info)\](?:\s+.*)?)?$",
    re.IGNORECASE,
)
_NEGATIVE_ROW = re.compile(
    r"\b(?:not\s+(?:supported|offered|enabled)|"
    r"(?:disabled|removed|absent)\s+(?:on|from)\s+(?:this|the)\s+server)\b",
    re.IGNORECASE,
)

# This is intentionally finite and exact.  It is not a catalogue of all
# historically weak, deprecated, or potentially vulnerable cryptography.
_DISALLOWED: Final[dict[tuple[str, str], str]] = {
    ("kex", "diffie-hellman-group1-sha1"): "disallowed KEX algorithm",
    ("kex", "diffie-hellman-group14-sha1"): "disallowed KEX algorithm",
    ("kex", "diffie-hellman-group-exchange-sha1"): "disallowed KEX algorithm",
    ("key", "ssh-rsa"): "disallowed signature algorithm",
    ("key", "ssh-dss"): "disallowed signature algorithm",
    ("enc", "3des-cbc"): "disallowed cipher",
    ("enc", "arcfour"): "disallowed cipher",
    ("enc", "arcfour128"): "disallowed cipher",
    ("enc", "arcfour256"): "disallowed cipher",
    ("enc", "aes128-cbc"): "disallowed cipher",
    ("enc", "aes192-cbc"): "disallowed cipher",
    ("enc", "aes256-cbc"): "disallowed cipher",
    ("mac", "hmac-md5"): "disallowed MAC algorithm",
    ("mac", "hmac-md5-96"): "disallowed MAC algorithm",
}


def assess_ssh_crypto(text: str) -> dict:
    """Assess exact server-observation rows against the versioned SSH policy.

    The parser accepts surrounding whitespace and ANSI CSI styling, and
    normalizes category and algorithm names to lowercase.  A row may carry
    ssh-audit's structured bit-length and ``[warn]``/``[fail]``/``[info]``
    annotation suffixes; an unstructured suffix is not parsed.  No inference
    is made from absent rows or from unrelated text.
    """
    observed: list[dict[str, str]] = []
    if isinstance(text, str):
        for raw_line in text.splitlines():
            line = _ANSI_CSI.sub("", raw_line).strip()
            match = _OBSERVED_ROW.fullmatch(line)
            if match and not _NEGATIVE_ROW.search(line):
                observed.append({
                    "category": match.group(1).casefold(),
                    "name": match.group(2).casefold(),
                })

    disallowed: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for algorithm in observed:
        identity = (algorithm["category"], algorithm["name"])
        reason = _DISALLOWED.get(identity)
        if reason is not None and identity not in seen:
            disallowed.append({
                "category": algorithm["category"],
                "name": algorithm["name"],
                "reason": reason,
            })
            seen.add(identity)

    if disallowed:
        status = "policy_violation"
    elif observed:
        status = "observed"
    else:
        status = "unverifiable"
    return {
        "policy_version": SSH_CRYPTO_POLICY_VERSION,
        "observed_algorithms": observed,
        "disallowed_algorithms": disallowed,
        "status": status,
    }
