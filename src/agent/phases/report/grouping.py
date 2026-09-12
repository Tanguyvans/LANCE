"""Conservative, presentation-only grouping of report findings.

This module deliberately does not alter findings or participate in Phase 3/4
identity, scoring, or evidence decisions.  A group is only a review hint:
``possible_duplicate`` is not a claim that the members are equivalent.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable
import math
import json


_SERVICE_ALIASES = {
    "mqtt_websocket": "mqtt-ws",
    "mqtt-websocket": "mqtt-ws",
    "mqttws": "mqtt-ws",
    "mqtt-ws": "mqtt-ws",
    "websocket": "mqtt-ws",
    "ws": "mqtt-ws",
}
_HTTP_SERVICES = {"http", "https"}
_MQTT_WS_TYPES = {"no_auth", "network_exposure", "networkexposure"}
_UNKNOWN_MARKERS = {"", "?", "-", "na", "n/a", "none", "null", "unknown"}
_EXPLICIT_FIELDS = (
    (("conditions", "condition"), False),
    (("parameters", "parameter"), False),
    (("vector", "attack_vector"), False),
    (("claim", "claim_id"), False),
    (("cve_ids", "cves", "cve"), True),
)


def _nonempty_text(value: object) -> str:
    """Return a scalar as trimmed text, or an empty string for missing data."""

    if value is None or isinstance(value, (dict, list, tuple, set, frozenset)):
        return ""
    text = str(value).strip()
    return text


def _known_text(value: object) -> str:
    text = _nonempty_text(value)
    return "" if text.casefold() in _UNKNOWN_MARKERS else text


def _one_value(finding: dict, singular: str, plural: str) -> str:
    """Read a scalar field, accepting a one-item collection conservatively."""

    value = finding.get(singular)
    if value in (None, "") and plural in finding:
        value = finding.get(plural)
    if isinstance(value, (list, tuple, set, frozenset)):
        values = {_nonempty_text(item) for item in value}
        values.discard("")
        return next(iter(values)) if len(values) == 1 else ""
    return _nonempty_text(value)


def _values(value: object, *, fold_case: bool = True) -> frozenset[str]:
    """Convert a scalar or collection into a nonempty, immutable value set."""

    if isinstance(value, (list, tuple, set, frozenset)):
        raw_values: Iterable[object] = value
    else:
        raw_values = (value,)
    result: set[str] = set()
    for raw in raw_values:
        if isinstance(raw, dict):
            # Explicit structured conditions must not disappear as "missing".
            text = json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        else:
            text = _known_text(raw) if fold_case else _nonempty_text(raw)
        if fold_case:
            text = text.casefold()
        if text:
            result.add(text)
    return frozenset(result)


def _field_values(
    finding: dict,
    names: tuple[str, ...],
    *,
    fold_case: bool = True,
) -> frozenset[str]:
    """Preserve values from every populated alias, including explicit conflicts."""
    combined: set[str] = set()
    for name in names:
        if name in finding:
            combined.update(_values(finding.get(name), fold_case=fold_case))
    return frozenset(combined)


def _valid_port(finding: dict) -> int | None:
    """Return a single valid TCP/UDP port; ambiguous collections are invalid."""

    value = finding.get("port")
    if value in (None, "") and "ports" in finding:
        value = finding.get("ports")
    if isinstance(value, (list, tuple, set, frozenset)):
        values = list(value)
        if len(values) != 1:
            return None
        value = values[0]
    if isinstance(value, bool):
        return None
    if isinstance(value, float):
        if not math.isfinite(value) or not value.is_integer():
            return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def _raw_endpoints(finding: dict) -> tuple[str, ...]:
    """Union primary and plural endpoints, without parsing or rewriting."""

    collected: list[str] = []
    for field in ("endpoint", "endpoints"):
        value = finding.get(field)
        if isinstance(value, (list, tuple, set, frozenset)):
            raw_values: Iterable[object] = value
        else:
            raw_values = (value,)
        for item in raw_values:
            text = _nonempty_text(item)
            if text and text not in collected:
                collected.append(text)
    return tuple(collected)


def _target(finding: dict) -> str:
    """Use the observed IP first, falling back to the device identifier."""

    return _known_text(finding.get("device_ip")) or _known_text(
        finding.get("device_id")
    )


def _service(finding: dict) -> str:
    service = _known_text(_one_value(finding, "service", "services")).casefold()
    return _SERVICE_ALIASES.get(service, service)


def _type(finding: dict) -> str:
    return _known_text(_one_value(finding, "type", "types")).casefold()


def _protocol(finding: dict) -> str:
    return _known_text(_one_value(finding, "protocol", "protocols")).casefold()


@dataclass(frozen=True)
class _FindingView:
    index: int
    target: str
    finding_type: str
    service: str
    port: int | None
    protocol: str
    endpoints: frozenset[str]
    explicit: tuple[frozenset[str], ...]
    product: frozenset[str]
    version: frozenset[str]

    @property
    def structurally_groupable(self) -> bool:
        return bool(
            self.target
            and self.finding_type
            and self.service
            and self.port is not None
        )

    @property
    def primary_key(self) -> tuple[object, ...]:
        return (
            self.target,
            self.finding_type,
            self.service,
            self.port,
            self.protocol,
        )

    @property
    def base_key(self) -> tuple[object, ...]:
        return self.primary_key + (self.endpoints, self.explicit)


def _product_version_compatible(left: _FindingView, right: _FindingView) -> bool:
    """Allow missing product/version metadata, but reject conflicting values."""

    for left_values, right_values in (
        (left.product, right.product),
        (left.version, right.version),
    ):
        if left_values and right_values and left_values != right_values:
            return False
    return True


def _canonical_endpoints(
    view: _FindingView,
) -> frozenset[str]:
    endpoints = set(view.endpoints)

    # A trailing colon is a presentation-only duplicate for HTTP only when
    # the exact unsuffixed resource is present in this same declaration.
    if view.service in _HTTP_SERVICES:
        known = view.endpoints
        endpoints = {
            endpoint[:-1]
            if endpoint.endswith(":") and endpoint[:-1] in known
            else endpoint
            for endpoint in endpoints
        }

    # MQTT-over-WebSocket implementations commonly report the root as either
    # an empty endpoint or "/".  This narrow rule applies only to the two
    # requested presentation finding types.
    if (
        view.service == "mqtt-ws"
        and view.finding_type in _MQTT_WS_TYPES
        and endpoints <= {"/"}
    ):
        endpoints = {"/"}
    return frozenset(endpoints)


def _metadata_signature(view: _FindingView) -> tuple[frozenset[str], frozenset[str]]:
    return view.product, view.version


def _compatible_group(view: _FindingView, members: list[_FindingView]) -> bool:
    return all(_product_version_compatible(view, member) for member in members)


def _groups_for_base(views: list[_FindingView]) -> list[list[_FindingView]]:
    """Partition one fully structural key without allowing unknown bridges."""

    # Exact metadata signatures are the initial, order-independent groups.
    by_signature: dict[tuple[frozenset[str], frozenset[str]], list[_FindingView]] = {}
    for view in views:
        by_signature.setdefault(_metadata_signature(view), []).append(view)
    initial = list(by_signature.values())

    # A signature with at least one known product/version value is a possible
    # anchor.  An incomplete signature may join exactly one compatible anchor;
    # if there are two, it remains separate instead of bridging them.  Parent
    # selection is directional (more-specific wins, then earlier wins), so two
    # incomplete signatures can never attach to each other in a cycle.
    known_indices = [
        index
        for index, members in enumerate(initial)
        if members[0].product or members[0].version
    ]
    parent: dict[int, int] = {}

    def specificity(members: list[_FindingView]) -> int:
        representative = members[0]
        return int(bool(representative.product)) + int(bool(representative.version))

    for index, members in enumerate(initial):
        representative = members[0]
        if representative.product and representative.version:
            continue
        candidates = [
            candidate_index
            for candidate_index in known_indices
            if candidate_index != index
            and _compatible_group(representative, initial[candidate_index])
        ]
        if len(candidates) != 1:
            continue
        candidate_index = candidates[0]
        candidate_specificity = specificity(initial[candidate_index])
        current_specificity = specificity(members)
        if (
            candidate_specificity > current_specificity
            or (
                candidate_specificity == current_specificity
                and candidate_index < index
            )
        ):
            parent[index] = candidate_index

    def root(index: int) -> int:
        while index in parent:
            index = parent[index]
        return index

    grouped: dict[int, list[_FindingView]] = {}
    for index, members in enumerate(initial):
        grouped.setdefault(root(index), []).extend(members)
    return [sorted(members, key=lambda view: view.index) for members in grouped.values()]


def group_findings_for_report(findings: list[dict]) -> list[dict]:
    """Return deterministic report-only duplicate hypotheses.

    Every input index appears exactly once in the result, including structurally
    incomplete or ID-less findings. A multi-member group is only a ``possible_duplicate``
    hypothesis and must not be used as a unique vulnerability count.
    """

    views: list[_FindingView] = []
    for index, finding in enumerate(findings):
        views.append(_FindingView(
            index=index,
            target=_target(finding),
            finding_type=_type(finding),
            service=_service(finding),
            port=_valid_port(finding),
            protocol=_protocol(finding),
            endpoints=frozenset(_raw_endpoints(finding)),
            explicit=tuple(
                _field_values(finding, names, fold_case=fold_case)
                for names, fold_case in _EXPLICIT_FIELDS
            ),
            product=_field_values(finding, ("products", "product")),
            version=_field_values(finding, ("versions", "version")),
        ))

    canonical_views: list[_FindingView] = []
    for view in views:
        canonical_views.append(_FindingView(
            index=view.index,
            target=view.target,
            finding_type=view.finding_type,
            service=view.service,
            port=view.port,
            protocol=view.protocol,
            endpoints=_canonical_endpoints(view),
            explicit=view.explicit,
            product=view.product,
            version=view.version,
        ))

    invalid_groups = [[view] for view in canonical_views if not view.structurally_groupable]
    valid_by_base: dict[tuple[object, ...], list[_FindingView]] = {}
    for view in canonical_views:
        if view.structurally_groupable:
            valid_by_base.setdefault(view.base_key, []).append(view)

    groups = invalid_groups + [
        group
        for base_views in valid_by_base.values()
        for group in _groups_for_base(base_views)
    ]
    groups.sort(key=lambda group: min(view.index for view in group))

    output: list[dict] = []
    for group_number, group in enumerate(groups, start=1):
        indices = sorted(view.index for view in group)
        output.append({
            "group_id": f"RG-{group_number:04d}",
            "member_ids": [
                _nonempty_text(findings[index].get("id"))
                for index in indices
                if _nonempty_text(findings[index].get("id"))
            ],
            "member_indices": indices,
            "possible_duplicate": len(indices) > 1,
        })
    return output


__all__ = ["group_findings_for_report"]
