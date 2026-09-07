"""Reject report narrative that contradicts recorded intrusion evidence."""


def _local_report_memo_contradicts_context(text: str, context: dict) -> bool:
    lower = (text or "").lower()
    if "do not re-list individual vulns" in lower:
        return True
    intrusion = context.get("intrusion", {}) if isinstance(context, dict) else {}
    summary = intrusion.get("summary", {}) if isinstance(intrusion, dict) else {}
    compromised = intrusion.get("compromised_devices", []) if isinstance(intrusion, dict) else []
    try:
        compromised_count = int(summary.get("devices_compromised", len(compromised)) or 0)
    except (TypeError, ValueError):
        compromised_count = len(compromised) if isinstance(compromised, list) else 0
    if compromised_count == 0 and any(marker in lower for marker in (
        "confirmed compromise",
        "confirmed to be compromised",
        "compromised devices:",
    )):
        return True
    return False
