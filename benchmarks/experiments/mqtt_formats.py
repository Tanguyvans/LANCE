"""H2 fidelity of interpretation over frozen MQTT dossiers (offline core).

H2 asks whether a model reads presentations that no declared parser covers.
The dossier is frozen: no broker, no network transition, no collection. Both
arms receive the same bytes and answer one verdict per message plus one
conclusion; the private oracle says which verdict is demonstrable from what
the arm could actually access.

The rules arm is competent on the schema the contract declares and has no
means for a schema outside it. That is the measured property, not an injected
flaw: the contrast is fixed before any fixture.

The registry metric is M-I, "proportion de conclusions conformes au dossier,
abstention correcte incluse". The per-message verdicts are the evidence the
conclusion rests on; they are recounted from the journal, never trusted.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

CONTRACT = "mqtt-formats-interpretation-v1"
SCENARIO = "s_mqtt_formats"
METRIC = "M-I"
VIEWS = ("raw", "normalized")
SCHEMAS = ("reference", "variant")
# Only the reference schema is inscribed in the contract. A variant is a real
# presentation with no declared parser; that is the point of the family.
DECLARED_SCHEMAS = ("reference",)
VERDICTS = ("exposed", "not_exposed", "abstain")
READINGS = ("temperature_c", "humidity_pct")
CANONICAL_KEYS = ("device_id", "temperature_c", "humidity_pct", "status")
FIXTURE_TYPES = tuple(f"{SCENARIO}_t0{index}" for index in range(1, 9))
# The declared parser, written once in the contract. A variant renames and
# re-nests these fields, so this map simply does not apply to it.
REFERENCE_SCHEMA = {"dev_id": "device_id", "temp_c": "temperature_c",
                    "rh_pct": "humidity_pct", "state": "status"}
MAX_MESSAGES = 12
PUBLIC_FIELDS = {"schema_version", "scenario_id", "fixture_type", "instance_id",
                 "view", "schema", "question", "messages"}
ORACLE_FIELDS = {"schema_version", "contract", "dossier_sha256", "conclusion", "verdicts"}
MESSAGE_FIELDS = {"message_id", "topic", "qos", "retain", "payload", "encoding", "fields"}
ANSWER_FIELDS = {"schema_version", "contract", "decision_policy", "dossier_sha256",
                 "verdicts", "conclusion"}
# A dossier carries a presentation, never a label. Any of these keys nested
# anywhere in it would hand the answer to the arm.
ORACLE_KEYS = {"verdict", "verdicts", "expected", "expected_verdict", "carries",
               "ground_truth", "oracle", "label", "truth"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


def _nested_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _nested_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _nested_keys(item)


def _topic_is_literal(topic):
    return isinstance(topic, str) and topic and "/" in topic \
        and not any(char in topic for char in "#+") and " " not in topic


def _canonical_scalar(value):
    return value is None or isinstance(value, (str, int, float, bool))


def _validate_message(message, view):
    if not isinstance(message, dict) or not set(message) <= MESSAGE_FIELDS:
        raise ValueError("Message must carry only the public presentation fields")
    if not isinstance(message.get("message_id"), str) or not message["message_id"]:
        raise ValueError("Message needs a non-empty identifier")
    if not _topic_is_literal(message.get("topic")):
        raise ValueError("Message topic must be literal")
    if type(message.get("qos")) is not int or message["qos"] not in (0, 1, 2):
        raise ValueError("Message QoS must be 0, 1 or 2")
    if type(message.get("retain")) is not bool:
        raise ValueError("Message retain must be a boolean")
    if view == "raw":
        if not isinstance(message.get("payload"), str):
            raise ValueError("Raw message needs a payload string")
        if message.get("encoding") not in ("utf-8", "base64"):
            raise ValueError("Raw message encoding must be utf-8 or base64")
        if "fields" in message:
            raise ValueError("Raw message must not carry decoded fields")
    else:
        fields = message.get("fields")
        if not isinstance(fields, dict) or not fields:
            raise ValueError("Normalized message needs decoded fields")
        if any(not isinstance(key, str) or not key for key in fields):
            raise ValueError("Normalized field names must be non-empty strings")
        if any(not _canonical_scalar(value) for value in fields.values()):
            raise ValueError("Normalized field values must be scalars")
        if "payload" in message or "encoding" in message:
            raise ValueError("Normalized message must not carry raw bytes")


def validate_dossier(raw):
    """Accept only a frozen public dossier: no label anywhere, no wildcard topic."""
    if not isinstance(raw, dict) or set(raw) != PUBLIC_FIELDS:
        raise ValueError("Dossier must carry the public fields and nothing else")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
        raise ValueError("Unsupported dossier schema version")
    if raw["scenario_id"] != SCENARIO:
        raise ValueError("Dossier belongs to another scenario")
    if raw["fixture_type"] not in FIXTURE_TYPES:
        raise ValueError("Dossier fixture type is not declared in the corpus")
    if not isinstance(raw["instance_id"], str) or not raw["instance_id"]:
        raise ValueError("Dossier needs a non-empty instance identifier")
    if raw["view"] not in VIEWS or raw["schema"] not in SCHEMAS:
        raise ValueError("Dossier view or schema is not declared")
    question = raw["question"]
    if not isinstance(question, dict) or set(question) != {"property", "device_id"}:
        raise ValueError("Question must name one property and one device")
    if question["property"] not in READINGS:
        raise ValueError("Question property must be a reading")
    if not isinstance(question["device_id"], str) or not question["device_id"]:
        raise ValueError("Question device must be a non-empty string")
    messages = raw["messages"]
    if not isinstance(messages, list) or not 1 <= len(messages) <= MAX_MESSAGES:
        raise ValueError(f"Dossier requires 1 to {MAX_MESSAGES} messages")
    for message in messages:
        _validate_message(message, raw["view"])
    identifiers = [message["message_id"] for message in messages]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("Message identifiers must be unique")
    leaked = sorted(ORACLE_KEYS.intersection(key.lower() for key in _nested_keys(raw)))
    if leaked:
        raise ValueError(f"Public dossier must not carry a label field: {leaked}")
    return raw


def presented(message, view):
    """What the arm can actually read for one message."""
    body = {"message_id": message["message_id"], "topic": message["topic"],
            "qos": message["qos"], "retain": message["retain"]}
    if view == "raw":
        body.update({"payload": message["payload"], "encoding": message["encoding"]})
    else:
        body["fields"] = message["fields"]
    return body


class Journal:
    """Every read is journaled by the harness; the arm never writes a record."""

    def __init__(self, dossier, view):
        self.dossier_sha256 = digest(dossier)
        self.view = view
        self.messages = {message["message_id"]: message for message in dossier["messages"]}
        self.records = []

    def read(self, message_id):
        if message_id not in self.messages:
            raise ValueError("Unknown message identifier")
        body = presented(self.messages[message_id], self.view)
        evidence_ref = hashlib.sha256(
            (self.dossier_sha256 + json.dumps(body, sort_keys=True,
                                              ensure_ascii=False)).encode()).hexdigest()
        self.records.append({"evidence_ref": evidence_ref, "message_id": message_id,
                             "dossier_sha256": self.dossier_sha256})
        return evidence_ref, body

    def replayed(self, records):
        """Reattach a recorded journal; a record of another dossier is refused."""
        for record in records:
            if not isinstance(record, dict) or record.get("dossier_sha256") != self.dossier_sha256:
                raise ValueError("Journal record belongs to another dossier")
            if record.get("message_id") not in self.messages:
                raise ValueError("Journal record names an unknown message")
            self.records.append({"evidence_ref": record["evidence_ref"],
                                 "message_id": record["message_id"],
                                 "dossier_sha256": record["dossier_sha256"]})
        return self


def oracle_for(dossier, verdicts, conclusion):
    """Private oracle: one demonstrable verdict per message, bound to the dossier."""
    public = validate_dossier(dossier)
    identifiers = [message["message_id"] for message in public["messages"]]
    if not isinstance(verdicts, dict) or set(verdicts) != set(identifiers):
        raise ValueError("Oracle must decide every message and nothing else")
    if any(verdict not in VERDICTS for verdict in verdicts.values()):
        raise ValueError("Oracle verdict is not declared")
    if conclusion not in VERDICTS:
        raise ValueError("Oracle conclusion is not declared")
    return {"schema_version": 1, "contract": CONTRACT, "dossier_sha256": digest(public),
            "conclusion": conclusion, "verdicts": dict(verdicts)}


def _decode_reference(message):
    """Declared parser of the reference schema: decode, map, nothing else."""
    if message["encoding"] == "base64":
        try:
            text = base64.b64decode(message["payload"], validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    else:
        text = message["payload"]
    try:
        decoded = json.loads(text)
    except (TypeError, ValueError):
        return None
    if not isinstance(decoded, dict):
        return None
    mapped = {}
    for key, value in decoded.items():
        if key not in REFERENCE_SCHEMA or REFERENCE_SCHEMA[key] in mapped:
            return None
        mapped[REFERENCE_SCHEMA[key]] = value
    return mapped


def _decide(fields, question):
    """Shared exposure rule: does this message carry the asked reading?

    A message that does not name its device leaves the question open: the rule
    abstains instead of guessing. A named message that does not carry the asked
    reading is demonstrably not an exposure of that reading. Returning ``None``
    is a documented abstention, not a failure.
    """
    device = fields.get("device_id")
    if device is None:
        return None
    if device != question["device_id"]:
        return "not_exposed"
    if fields.get(question["property"]) is None:
        return "not_exposed"
    return "exposed"


def _conclude(verdicts):
    """One conclusion per dossier, derived only from what the arm decided."""
    decided = list(verdicts.values())
    if "exposed" in decided:
        return "exposed"
    if decided and all(verdict == "not_exposed" for verdict in decided):
        return "not_exposed"
    return "abstain"


def run_rules(dossier, journal):
    """Rules interpreter: declared parser or an explicit abstention."""
    public = validate_dossier(dossier)
    declared = public["schema"] in DECLARED_SCHEMAS
    verdicts = {}
    for message in public["messages"]:
        evidence_ref, body = journal.read(message["message_id"])
        if public["view"] == "normalized":
            fields = body["fields"]
        elif declared:
            fields = _decode_reference(body)
        else:
            fields = None
        verdict = _decide(fields, public["question"]) if fields is not None else None
        verdicts[message["message_id"]] = {"verdict": verdict or "abstain",
                                           "evidence_ref": evidence_ref}
    return {"schema_version": 1, "contract": CONTRACT, "decision_policy": "rules",
            "dossier_sha256": journal.dossier_sha256, "verdicts": verdicts,
            "conclusion": _conclude({key: entry["verdict"] for key, entry in verdicts.items()})}


def _validate_answer(answer, public, journal):
    if not isinstance(answer, dict) or set(answer) != ANSWER_FIELDS:
        raise ValueError("Answer must carry exactly the declared fields")
    if answer["schema_version"] != 1 or answer["contract"] != CONTRACT:
        raise ValueError("Answer belongs to another contract")
    if answer["decision_policy"] not in ("rules", "llm"):
        raise ValueError("Answer decision policy is not declared")
    if answer["dossier_sha256"] != journal.dossier_sha256:
        raise ValueError("Answer is bound to another dossier")
    if answer["conclusion"] not in VERDICTS:
        raise ValueError("Answer conclusion is not declared")
    verdicts = answer["verdicts"]
    if not isinstance(verdicts, dict):
        raise ValueError("Answer verdicts must be a mapping")
    expected = {message["message_id"] for message in public["messages"]}
    if set(verdicts) != expected:
        raise ValueError("Answer must decide every message and nothing else")
    journaled = {}
    for record in journal.records:
        journaled.setdefault(record["message_id"], set()).add(record["evidence_ref"])
    for message_id, entry in verdicts.items():
        if not isinstance(entry, dict) or set(entry) != {"verdict", "evidence_ref"}:
            raise ValueError("Verdict must carry a decision and one evidence reference")
        if entry["verdict"] not in VERDICTS:
            raise ValueError("Verdict is not declared")
        if entry["evidence_ref"] not in journaled.get(message_id, set()):
            raise ValueError("Verdict must cite a read of its own message")
    return answer


def evaluate(dossier, oracle, answer, journal):
    """Recount from the journal: per-message correctness, conclusion, coherence."""
    public = validate_dossier(dossier)
    if not isinstance(oracle, dict) or set(oracle) != ORACLE_FIELDS \
            or oracle.get("contract") != CONTRACT or oracle.get("schema_version") != 1 \
            or oracle.get("dossier_sha256") != digest(public):
        raise ValueError("Oracle must bind this dossier")
    answer = _validate_answer(answer, public, journal)
    identifiers = [message["message_id"] for message in public["messages"]]
    correct, wrong, abstained = 0, [], 0
    for message_id in identifiers:
        observed = answer["verdicts"][message_id]["verdict"]
        expected = oracle["verdicts"][message_id]
        if observed == "abstain":
            abstained += 1
        if observed == expected:
            correct += 1
        else:
            wrong.append(message_id)
    # Abstention never contradicts the oracle; the two affirmative verdicts do.
    contradiction = answer["conclusion"] != "abstain" \
        and oracle["conclusion"] != "abstain" \
        and answer["conclusion"] != oracle["conclusion"]
    conclusion_correct = answer["conclusion"] == oracle["conclusion"]
    total = len(identifiers)
    return {"schema_version": 1, "contract": CONTRACT, "scenario_id": SCENARIO,
            "metric": METRIC, "fixture_type": public["fixture_type"],
            "view": public["view"], "schema": public["schema"],
            "decision_policy": answer["decision_policy"],
            "conclusion": answer["conclusion"],
            "expected_conclusion": oracle["conclusion"],
            "conclusion_correct": conclusion_correct,
            "contradiction": contradiction,
            # A right conclusion read from wrong verdicts is not an étayée one.
            "success": conclusion_correct and not contradiction and not wrong,
            "messages": total, "correct": correct, "wrong": wrong,
            "abstained": abstained, "coverage": correct / total,
            "mt_admissible": False, "measurement_status": "evidence_only_not_admitted",
            "scope": "Frozen dossier interpretation; no collection, no autonomy claim"}


def aggregate(results):
    """Group success by (schema, view), the split the prediction rests on."""
    groups = {}
    for result in results:
        key = f"{result['schema']}/{result['view']}"
        group = groups.setdefault(key, {"dossiers": 0, "successes": 0,
                                        "messages": 0, "correct": 0})
        group["dossiers"] += 1
        group["successes"] += 1 if result["success"] else 0
        group["messages"] += result["messages"]
        group["correct"] += result["correct"]
    for group in groups.values():
        group["success_rate"] = group["successes"] / group["dossiers"]
        group["coverage"] = group["correct"] / group["messages"]
    return {"metric": METRIC, "acceptable": False,
            "reading": "H2 compares groups, never a single dossier",
            "groups": dict(sorted(groups.items()))}


def main(argv=None):
    """Offline recount over one recorded dossier trial."""
    parser = argparse.ArgumentParser(description="H2 interpretation recount")
    parser.add_argument("directory", type=Path,
                        help="trial directory with dossier/oracle/journal/answer")
    args = parser.parse_args(argv)
    try:
        def read(name):
            return json.loads((args.directory / name).read_text(encoding="utf-8"))

        public = validate_dossier(read("dossier.json"))
        journal = Journal(public, public["view"]).replayed([
            json.loads(line) for line in
            (args.directory / "journal.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()])
        evaluation = evaluate(public, read("oracle.json"), read("answer.json"), journal)
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(evaluation, indent=2, ensure_ascii=False, sort_keys=True))
    return 0 if evaluation["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
