"""Fixed read-only protocol probes shared by verification and intrusion."""
from __future__ import annotations


_SNMP_V1_GET_SYS_DESCR_HEX = (
    "302602010004067075626c6963a019020101020100020100300e"
    "300c06082b060102010101000500"
)


_COAP_GET_CORE_HEX = "44011234deadbeefbb2e77656c6c2d6b6e6f776e04636f7265"


_S7COMM_COTP_CR_HEX = "0300001611e00000000100c1020100c2020102c0010a"


_ENIP_LIST_IDENTITY_HEX = "630000000000000000000000000000000000000000000000"


def _udp_service_for_port(value: object) -> str:
    """Map the bounded UDP entry-point probes to their service family."""
    try:
        return {161: "snmp", 5683: "coap"}.get(int(value), "")
    except (TypeError, ValueError):
        return ""


def _compact_udp_entry_action(target: str, service: str) -> tuple[str, dict] | None:
    """Build a read-only UDP probe for a supported compact entry point."""
    probes = {
        "snmp": (161, _SNMP_V1_GET_SYS_DESCR_HEX),
        "coap": (5683, _COAP_GET_CORE_HEX),
    }
    port_payload = probes.get(str(service or "").casefold())
    if port_payload is None:
        return None
    port, payload = port_payload
    return "udp_send", {
        "host": target,
        "port": port,
        "payload": payload,
        "encoding": "hex",
        "recv_bytes": 4096,
        "timeout": 5,
    }
