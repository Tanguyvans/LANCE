"""H2 offline core: frozen dossiers, the private oracle, both arms, the recount."""
import base64
import json
from copy import deepcopy
from pathlib import Path

import pytest

from benchmarks.experiments import mqtt_formats as formats

ROOT = Path(__file__).resolve().parents[1]
OWNER = "sensor-a"


def raw_message(message_id, topic, payload, encoding="utf-8", qos=0, retain=False):
    return {"message_id": message_id, "topic": topic, "qos": qos, "retain": retain,
            "payload": payload, "encoding": encoding}


def normalized_message(message_id, topic, fields):
    return {"message_id": message_id, "topic": topic, "qos": 0, "retain": False,
            "fields": fields}


def reference_payload(device=OWNER, reading=21.5):
    return json.dumps({"dev_id": device, "temp_c": reading, "state": "ok"})


def dossier(view="raw", schema="reference", messages=None, fixture="s_mqtt_formats_t01"):
    if messages is None:
        messages = [raw_message("m1", "site/plant/a", reference_payload()),
                    raw_message("m2", "site/plant/b",
                                json.dumps({"dev_id": "sensor-b", "temp_c": 19.0}))]
    return {"schema_version": 1, "scenario_id": formats.SCENARIO, "fixture_type": fixture,
            "instance_id": "h2-01", "view": view, "schema": schema,
            "question": {"property": "temperature_c", "device_id": OWNER},
            "messages": messages}


def normalized_dossier(schema="variant", fixture="s_mqtt_formats_t04"):
    return dossier(view="normalized", schema=schema, fixture=fixture, messages=[
        normalized_message("m1", "site/plant/a",
                           {"device_id": OWNER, "temperature_c": 21.5}),
        normalized_message("m2", "site/plant/b",
                           {"device_id": "sensor-b", "temperature_c": 19.0})])


def run(dossier_value):
    public = formats.validate_dossier(dossier_value)
    journal = formats.Journal(public, public["view"])
    answer = formats.run_rules(public, journal)
    return public, journal, answer


def oracle_two_exposures(public, exposed=("m1",)):
    return formats.oracle_for(public, {message["message_id"]:
                                       "exposed" if message["message_id"] in exposed
                                       else "not_exposed"
                                       for message in public["messages"]},
                              "exposed")


def test_the_reference_dossier_is_accepted():
    public = formats.validate_dossier(dossier())
    assert public["scenario_id"] == "s_mqtt_formats"
    assert public["view"] == "raw" and public["schema"] == "reference"


@pytest.mark.parametrize("change", [
    lambda value: value.pop("question"),
    lambda value: value.update({"verdict": "exposed"}),
    lambda value: value.update({"schema_version": 2}),
    lambda value: value.update({"scenario_id": "s_mqtt_lecture"}),
    lambda value: value.update({"fixture_type": "s_mqtt_formats_t09"}),
    lambda value: value.update({"view": "decoded"}),
    lambda value: value.update({"schema": "vendor"}),
    lambda value: value.update({"question": {"property": "status", "device_id": OWNER}}),
    lambda value: value.update({"question": {"property": "temperature_c"}}),
    lambda value: value.update({"messages": []}),
    lambda value: value.update({"messages": [raw_message("m", "site/#", "{}")]}),
    lambda value: value.update({"messages": [raw_message("m", "siteplant", "{}")]}),
    lambda value: value.update({"messages": [raw_message("m", "site/p", "{}", qos=True)]}),
    lambda value: value.update({"messages": [raw_message("m", "site/p", "{}", encoding="utf-16")]}),
    lambda value: value.update({"messages": [raw_message("m", "site/p", "{}")] * 13}),
    lambda value: value.update({"messages": [
        raw_message("m", "site/p", "{}"), raw_message("m", "site/q", "{}")]}),
    lambda value: value.update({"messages": [normalized_message(
        "m", "site/p", {"device_id": OWNER, "verdict": "exposed"})]}),
])
def test_a_dossier_that_is_not_publicly_readable_is_refused(change):
    value = dossier()
    change(value)
    with pytest.raises(ValueError):
        formats.validate_dossier(value)


def test_a_raw_message_may_not_carry_decoded_fields():
    value = dossier(messages=[raw_message("m", "site/p", "{}")])
    value["messages"][0]["fields"] = {"device_id": OWNER}
    with pytest.raises(ValueError, match="must not carry decoded fields"):
        formats.validate_dossier(value)


def test_a_normalized_message_may_not_carry_raw_bytes():
    value = normalized_dossier()
    value["messages"][0]["payload"] = "{}"
    with pytest.raises(ValueError, match="must not carry raw bytes"):
        formats.validate_dossier(value)


def test_a_normalized_field_value_must_be_a_scalar():
    value = normalized_dossier()
    value["messages"][0]["fields"]["temperature_c"] = {"value": 21.5}
    with pytest.raises(ValueError, match="must be scalars"):
        formats.validate_dossier(value)


def test_the_arm_reads_only_the_presentation_the_view_declares():
    _, _, raw = run(dossier())
    assert "fields" not in formats.presented(
        formats.validate_dossier(dossier())["messages"][0], "raw")
    assert raw["verdicts"]["m1"]["verdict"] == "exposed"


def test_every_read_is_journaled_with_its_own_reference():
    public, journal, _ = run(dossier())
    assert len(journal.records) == len(public["messages"])
    references = {record["evidence_ref"] for record in journal.records}
    assert len(references) == len(public["messages"])
    assert all(record["dossier_sha256"] == journal.dossier_sha256
               for record in journal.records)


def test_an_unknown_message_cannot_be_read():
    public, journal, _ = run(dossier())
    with pytest.raises(ValueError, match="Unknown message"):
        journal.read("m404")


def test_the_oracle_decides_every_message_and_nothing_else():
    public = formats.validate_dossier(dossier())
    assert formats.oracle_for(public, {"m1": "exposed", "m2": "abstain"},
                              "exposed")["verdicts"]["m2"] == "abstain"
    with pytest.raises(ValueError, match="every message"):
        formats.oracle_for(public, {"m1": "exposed"}, "exposed")
    with pytest.raises(ValueError, match="every message"):
        formats.oracle_for(public, {"m1": "exposed", "m2": "exposed", "m3": "abstain"},
                           "exposed")
    with pytest.raises(ValueError, match="not declared"):
        formats.oracle_for(public, {"m1": "leak", "m2": "abstain"}, "exposed")
    with pytest.raises(ValueError, match="not declared"):
        formats.oracle_for(public, {"m1": "exposed", "m2": "abstain"}, "leak")


def test_an_oracle_does_not_travel_to_another_dossier():
    public, journal, answer = run(dossier())
    oracle = oracle_two_exposures(public)
    changed = deepcopy(public)
    changed["messages"][0]["payload"] = reference_payload(reading=99.0)
    other = formats.validate_dossier(changed)
    other_journal = formats.Journal(other, other["view"])
    other_answer = formats.run_rules(other, other_journal)
    with pytest.raises(ValueError, match="Oracle must bind this dossier"):
        formats.evaluate(changed, oracle, other_answer, other_journal)


def test_the_rules_arm_reads_the_declared_schema():
    public, journal, answer = run(dossier())
    assert answer["verdicts"]["m1"]["verdict"] == "exposed"
    assert answer["verdicts"]["m2"]["verdict"] == "not_exposed"
    assert answer["conclusion"] == "exposed"
    result = formats.evaluate(public, oracle_two_exposures(public), answer, journal)
    assert result["success"] is True and result["coverage"] == 1.0
    assert result["metric"] == "M-I" and result["mt_admissible"] is False


def test_the_rules_arm_decodes_a_base64_payload():
    encoded = base64.b64encode(reference_payload().encode()).decode()
    public, journal, answer = run(dossier(messages=[
        raw_message("m1", "site/plant/a", encoded, encoding="base64")]))
    assert answer["verdicts"]["m1"]["verdict"] == "exposed"
    assert formats.evaluate(public, formats.oracle_for(public, {"m1": "exposed"}, "exposed"),
                            answer, journal)["success"] is True


def test_the_rules_arm_abstains_on_a_payload_it_cannot_parse():
    public, journal, answer = run(dossier(messages=[
        raw_message("m1", "site/plant/a", "not json"),
        raw_message("m2", "site/plant/b", json.dumps({"dev_id": "sensor-b",
                                                      "temp_c": 19.0}))]))
    assert answer["verdicts"]["m1"]["verdict"] == "abstain"
    assert answer["verdicts"]["m2"]["verdict"] == "not_exposed"
    assert answer["conclusion"] == "abstain"


def test_the_rules_arm_reads_a_message_without_the_asked_reading_as_not_exposed():
    public, journal, answer = run(dossier(messages=[
        raw_message("m1", "site/plant/a", json.dumps({"dev_id": OWNER, "state": "ok"}))]))
    assert answer["verdicts"]["m1"]["verdict"] == "not_exposed"
    assert answer["conclusion"] == "not_exposed"


def test_the_rules_arm_abstains_when_the_message_does_not_name_its_device():
    public, journal, answer = run(dossier(messages=[
        raw_message("m1", "site/plant/a", json.dumps({"temp_c": 21.5}))]))
    assert answer["verdicts"]["m1"]["verdict"] == "abstain"
    assert answer["conclusion"] == "abstain"


def test_the_rules_arm_has_no_means_for_an_undeclared_schema():
    public, journal, answer = run(dossier(schema="variant", fixture="s_mqtt_formats_t03"))
    assert {entry["verdict"] for entry in answer["verdicts"].values()} == {"abstain"}
    assert answer["conclusion"] == "abstain"
    result = formats.evaluate(public, oracle_two_exposures(public), answer, journal)
    assert result["success"] is False and result["coverage"] == 0.0
    assert result["conclusion_correct"] is False and result["contradiction"] is False


def test_the_normalized_view_makes_both_schemas_equal_for_the_rules_arm():
    for schema, fixture in (("reference", "s_mqtt_formats_t02"),
                            ("variant", "s_mqtt_formats_t04")):
        public, journal, answer = run(normalized_dossier(schema=schema, fixture=fixture))
        result = formats.evaluate(public, oracle_two_exposures(public), answer, journal)
        assert result["success"] is True
        assert result["coverage"] == 1.0


def test_a_verdict_must_cite_a_read_of_its_own_message():
    public, journal, answer = run(dossier())
    oracle = oracle_two_exposures(public)
    swapped = deepcopy(answer)
    swapped["verdicts"]["m1"]["evidence_ref"] = answer["verdicts"]["m2"]["evidence_ref"]
    with pytest.raises(ValueError, match="cite a read of its own message"):
        formats.evaluate(public, oracle, swapped, journal)
    invented = deepcopy(answer)
    invented["verdicts"]["m1"]["evidence_ref"] = "0" * 64
    with pytest.raises(ValueError, match="cite a read of its own message"):
        formats.evaluate(public, oracle, invented, journal)


@pytest.mark.parametrize("change", [
    lambda value: value.pop("decision_policy"),
    lambda value: value.update({"contract": "another"}),
    lambda value: value.update({"dossier_sha256": "0" * 64}),
    lambda value: value.update({"conclusion": "leak"}),
    lambda value: value.update({"verdicts": {"m1": {"verdict": "exposed",
                                                    "evidence_ref": "0" * 64}}}),
    lambda value: value["verdicts"]["m1"].update({"verdict": "leak"}),
    lambda value: value["verdicts"]["m1"].update({"confidence": 0.9}),
])
def test_an_answer_that_does_not_bind_the_journal_is_refused(change):
    public, journal, answer = run(dossier())
    oracle = oracle_two_exposures(public)
    value = deepcopy(answer)
    change(value)
    with pytest.raises(ValueError):
        formats.evaluate(public, oracle, value, journal)


def test_a_right_conclusion_read_from_a_wrong_verdict_is_not_a_success():
    public = formats.validate_dossier(dossier(messages=[
        raw_message("m1", "site/plant/a", reference_payload()),
        raw_message("m2", "site/plant/c", reference_payload(device="sensor-c"))]))
    journal = formats.Journal(public, public["view"])
    answer = formats.run_rules(public, journal)
    oracle = formats.oracle_for(public, {"m1": "exposed", "m2": "exposed"}, "exposed")
    damaged = deepcopy(answer)
    damaged["verdicts"]["m2"]["verdict"] = "not_exposed"
    result = formats.evaluate(public, oracle, damaged, journal)
    assert result["conclusion_correct"] is True
    assert result["wrong"] == ["m2"] and result["success"] is False
    assert result["coverage"] == 0.5


def test_an_affirmative_conclusion_against_the_oracle_is_a_contradiction():
    public = formats.validate_dossier(dossier(messages=[
        raw_message("m1", "site/plant/b", json.dumps({"dev_id": "sensor-b",
                                                      "temp_c": 19.0}))]))
    journal = formats.Journal(public, public["view"])
    answer = formats.run_rules(public, journal)
    oracle = formats.oracle_for(public, {"m1": "exposed"}, "exposed")
    result = formats.evaluate(public, oracle, answer, journal)
    assert result["conclusion"] == "not_exposed"
    assert result["contradiction"] is True and result["success"] is False


def test_an_abstention_never_contradicts_the_oracle():
    public, journal, answer = run(dossier(schema="variant", fixture="s_mqtt_formats_t03"))
    oracle = oracle_two_exposures(public)
    result = formats.evaluate(public, oracle, answer, journal)
    assert result["contradiction"] is False
    assert result["abstained"] == 2


def test_the_aggregate_splits_by_schema_and_view():
    trials = []
    for schema, fixture, view in (("reference", "s_mqtt_formats_t01", "raw"),
                                  ("variant", "s_mqtt_formats_t03", "raw")):
        public, journal, answer = run(dossier(view=view, schema=schema, fixture=fixture))
        trials.append(formats.evaluate(public, oracle_two_exposures(public),
                                       answer, journal))
    summary = formats.aggregate(trials)
    assert summary["metric"] == "M-I" and summary["acceptable"] is False
    assert summary["groups"]["reference/raw"]["success_rate"] == 1.0
    assert summary["groups"]["variant/raw"]["success_rate"] == 0.0
    assert summary["groups"]["variant/raw"]["coverage"] == 0.0


def test_a_recorded_trial_is_recounted_from_its_files(tmp_path):
    public, journal, answer = run(dossier())
    (tmp_path / "dossier.json").write_text(json.dumps(public), encoding="utf-8")
    (tmp_path / "oracle.json").write_text(json.dumps(oracle_two_exposures(public)),
                                          encoding="utf-8")
    (tmp_path / "answer.json").write_text(json.dumps(answer), encoding="utf-8")
    (tmp_path / "journal.jsonl").write_text(
        "\n".join(json.dumps(record) for record in journal.records) + "\n",
        encoding="utf-8")
    assert formats.main([str(tmp_path)]) == 0


def test_a_journal_record_of_another_dossier_is_refused():
    public, journal, _ = run(dossier())
    other = dossier(messages=[raw_message("m1", "site/plant/a", reference_payload(23.0)),
                              raw_message("m2", "site/plant/b", "{}")])
    other_public = formats.validate_dossier(other)
    with pytest.raises(ValueError, match="another dossier"):
        formats.Journal(other_public, other_public["view"]).replayed(journal.records)


def test_the_family_declares_eight_fixtures():
    assert len(formats.FIXTURE_TYPES) == 8
    assert formats.FIXTURE_TYPES[0] == "s_mqtt_formats_t01"
    assert formats.DECLARED_SCHEMAS == ("reference",)


# --- the LLM arm, the frozen corpus and the runner -------------------------

from types import SimpleNamespace

from openai.types.chat import ChatCompletion

from benchmarks.experiments import mqtt_formats_live as live
from benchmarks.experiments import mqtt_formats_llm as formats_llm
from benchmarks.experiments.ssh_reference_llm import RecordingClient, _message
from src.agent.provider import LLMProvider


class ScriptedInterpreter:
    """Follow a tool schedule: ``read:<id>`` reads, ``finish`` closes.

    A close cites the references the harness handed out for each message, so
    the schedule alone decides what the arm has actually read.
    """

    base_url = "http://development.invalid/v1"

    def __init__(self, schedule, verdicts, conclusion):
        self.schedule = schedule
        self.verdicts = verdicts
        self.conclusion = conclusion
        self.requests = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def with_options(self, **kwargs):
        return self

    def create(self, **kwargs):
        self.requests.append({**kwargs, "messages": [_message(item)
                                                     for item in kwargs["messages"]]})
        index = len(self.requests) - 1
        action = self.schedule[min(index, len(self.schedule) - 1)]
        if action.startswith("read:"):
            return self.reply("read_message", {"message_id": action.split(":", 1)[1]}, index)
        refs = self.evidence()
        verdicts = {key: {"verdict": value, "evidence_ref": refs.get(key, "0" * 64)}
                    for key, value in self.verdicts.items()}
        return self.reply("finish_interpretation",
                          {"verdicts": verdicts, "conclusion": self.conclusion}, index)

    def evidence(self):
        found = {}
        for item in self.requests[-1]["messages"]:
            if item["role"] != "tool":
                continue
            try:
                body = json.loads(item["content"])
            except (TypeError, ValueError):
                continue
            if isinstance(body, dict) and "message_id" in body and "evidence_ref" in body:
                found[body["message_id"]] = body["evidence_ref"]
        return found

    def refusals(self):
        found = []
        for request in self.requests:
            for item in request["messages"]:
                if item["role"] != "tool":
                    continue
                try:
                    body = json.loads(item["content"])
                except (TypeError, ValueError):
                    continue
                if isinstance(body, dict) and body.get("ok") is False:
                    found.append(body.get("error_kind"))
        return found

    @staticmethod
    def reply(name, arguments, index):
        return ChatCompletion.model_validate({
            "id": f"completion-{index}", "object": "chat.completion", "created": 1,
            "model": "development-model",
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None, "reasoning_content": "NOT_ARCHIVED",
                "tool_calls": [{"id": f"tool-{index}", "type": "function",
                                "function": {"name": name,
                                             "arguments": json.dumps(arguments)}}]}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
        })


def llm_setup(tmp_path, monkeypatch, max_calls=13, max_turns=formats_llm.MAX_TURNS):
    monkeypatch.setattr("src.agent.cost_tracker.get_dynamic_pricing", lambda _: None)
    args = SimpleNamespace(max_tool_calls=max_calls, max_duration_s=60, max_turns=max_turns,
                           max_cost_usd=1, model="development-model",
                           provider="ollama-umons")
    return live.new_run(tmp_path, "llm", args)


def interpreter(tmp_path, monkeypatch, public, client):
    run_obj = llm_setup(tmp_path, monkeypatch)
    provider = object.__new__(LLMProvider)
    provider.provider, provider.model = "ollama-umons", "development-model"
    provider.client = RecordingClient(client, tmp_path)
    return formats_llm.run_llm(public, run_obj, provider)


def test_the_llm_arm_reads_the_same_dossier_and_closes(tmp_path, monkeypatch):
    public, journal, _ = run(dossier())
    oracle = oracle_two_exposures(public)
    client = ScriptedInterpreter(["read:m1", "read:m2", "finish"],
                                 oracle["verdicts"], "exposed")
    decision = interpreter(tmp_path, monkeypatch, public, client)
    assert decision["status"] == "completed" and decision["conclusion"] == "exposed"
    answer = {"schema_version": 1, "contract": formats.CONTRACT, "decision_policy": "llm",
              "dossier_sha256": journal.dossier_sha256,
              "verdicts": decision["verdicts"], "conclusion": decision["conclusion"]}
    recorded = formats.Journal(public, public["view"]).replayed(
        [json.loads(line) for line in
         (tmp_path / "journal.jsonl").read_text().splitlines() if line.strip()])
    assert formats.evaluate(public, oracle, answer, recorded)["success"] is True


def test_the_llm_arm_prompt_carries_no_oracle(tmp_path, monkeypatch):
    public, _, _ = run(dossier())
    oracle = oracle_two_exposures(public)
    client = ScriptedInterpreter(["read:m1", "read:m2", "finish"],
                                 oracle["verdicts"], "exposed")
    interpreter(tmp_path, monkeypatch, public, client)
    prompt = json.loads((tmp_path / "prompt.json").read_text())
    assert [tool["name"] for tool in prompt["tools"]] == ["read_message",
                                                          "finish_interpretation"]
    assert "oracle" not in json.dumps(prompt["user"]).lower()
    wire = (tmp_path / "provider-wire.jsonl").read_text()
    assert oracle["dossier_sha256"] not in wire and "NOT_ARCHIVED" not in wire


def test_the_llm_arm_refuses_a_verdict_it_did_not_read_then_recovers(tmp_path, monkeypatch):
    public, _, _ = run(dossier())
    verdicts = {"m1": "exposed", "m2": "not_exposed"}
    client = ScriptedInterpreter(["read:m1", "finish", "read:m2", "finish"], verdicts,
                                 "exposed")
    decision = interpreter(tmp_path, monkeypatch, public, client)
    assert "unbound_evidence" in client.refusals()
    assert decision["status"] == "completed"
    assert set(decision["verdicts"]) == {"m1", "m2"}


def test_the_llm_arm_cannot_close_on_a_partial_dossier(tmp_path, monkeypatch):
    public, _, _ = run(dossier())
    client = ScriptedInterpreter(["read:m1", "finish", "read:m2", "finish"],
                                 {"m1": "exposed"}, "exposed")
    decision = interpreter(tmp_path, monkeypatch, public, client)
    assert "incomplete_interpretation" in client.refusals()
    # A partial verdict map is refused every time it is sent, so the arm ends
    # without a terminal decision rather than with a truncated interpretation.
    assert decision["status"] != "completed" and not decision["verdicts"]


def test_a_budget_that_cannot_read_and_close_the_dossier_is_refused():
    assert formats_llm.check_budget(2, 3, 11)["required_calls"] == 3
    with pytest.raises(ValueError, match="cannot read the dossier"):
        formats_llm.check_budget(4, 4, 20)
    with pytest.raises(ValueError, match="routing slack"):
        formats_llm.check_budget(4, 5, 12)
    with pytest.raises(ValueError, match="1 to"):
        formats_llm.check_budget(0, 5, 20)


def test_the_shipped_corpus_covers_the_eight_declared_fixtures():
    fixtures = live.load_corpus()
    assert len(fixtures) == 8
    assert {item["dossier"]["fixture_type"] for item in fixtures} \
        == set(formats.FIXTURE_TYPES)
    assert all(item["oracle"]["dossier_sha256"] == formats.digest(item["dossier"])
               for item in fixtures)
    kinds = {(item["dossier"]["schema"], item["dossier"]["view"]) for item in fixtures}
    assert kinds == {("reference", "raw"), ("reference", "normalized"),
                     ("variant", "raw"), ("variant", "normalized")}


def test_the_declared_parsers_cover_every_group_but_the_raw_variant():
    fixtures = live.load_corpus()
    groups = {}
    for item in fixtures:
        public = item["dossier"]
        journal = formats.Journal(public, public["view"])
        answer = formats.run_rules(public, journal)
        result = formats.evaluate(public, item["oracle"], answer, journal)
        groups.setdefault(f"{public['schema']}/{public['view']}", []).append(result["success"])
    assert groups["reference/raw"] == [True] * 2
    assert groups["reference/normalized"] == [True] * 2
    assert groups["variant/normalized"] == [True] * 2
    assert groups["variant/raw"] == [False] * 2


def test_the_prediction_is_read_from_both_arms_never_from_one():
    def case(policy, schema, view, success):
        return {"policy": policy, "evaluation": {"schema": schema, "view": view,
                                                 "success": success}}

    refuted = live.prediction_check([
        case("rules", "variant", "raw", False), case("llm", "variant", "raw", False),
        case("rules", "variant", "normalized", True), case("llm", "variant", "normalized", True)])
    assert refuted["raw_gain"] is False and refuted["holds"] is False
    assert refuted["reading"] == "equality in the raw view refutes H2"
    holds = live.prediction_check([
        case("rules", "variant", "raw", False), case("llm", "variant", "raw", True),
        case("rules", "variant", "normalized", True), case("llm", "variant", "normalized", True)])
    assert holds["holds"] is True
    semantic = live.prediction_check([
        case("rules", "variant", "raw", False), case("llm", "variant", "raw", True),
        case("rules", "variant", "normalized", False), case("llm", "variant", "normalized", True)])
    assert semantic["holds"] is False
    assert semantic["reading"] == "a gain in the normalized view would be H4, not H2"


def test_the_job_log_projection_carries_no_dossier_content(tmp_path):
    fixtures = live.load_corpus()
    case = {"repetition": 1, "policy": "rules", "fixture_type": "s_mqtt_formats_t01",
            "evaluation": {"success": True, "status": "completed", "conclusion": "exposed",
                           "expected_conclusion": "exposed", "conclusion_correct": True,
                           "contradiction": False, "messages": 4, "correct": 4,
                           "abstained": 0, "coverage": 1.0},
            "spend": {"tool_calls": 4, "wall_clock_s": 0.1, "cost_usd": 0.0},
            "routing": None}
    (tmp_path / "results.json").write_text(json.dumps({
        "contract": formats.CONTRACT, "scenario_id": formats.SCENARIO, "metric": "M-I",
        "repetitions": 1, "arms": ["rules", "llm"], "cases": [case], "failures": []}))
    summary = live.public_summary(tmp_path)
    blob = json.dumps(summary)
    assert "payload" not in blob and "temp_c" not in blob and "dossier_sha256" not in blob
    assert summary["cases"][0]["coverage"] == 1.0
    for item in fixtures:
        assert item["dossier"]["instance_id"] not in blob


def test_the_runner_is_manual_and_targets_only_dev_two():
    import yaml
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "mqtt-formats.yml")
                              .read_text(encoding="utf-8"))
    assert list(workflow[True]) == ["workflow_dispatch"]
    job = workflow["jobs"]["mqtt-formats"]
    assert job["runs-on"] == ["self-hosted", "nato-master"]
    steps = {step["name"]: step for step in job["steps"]}
    run = steps["Execute both arms under the shared laboratory lock"]["run"]
    assert 'require "${GITHUB_REF:-}" refs/heads/dev/2 "trigger ref"' in run
    assert 'require "${RUNNER_NAME:-}" nato-master "runner name"' in run
    # The declared budgets must match the arm: 13 calls, 21 turns.
    assert "--max-tool-calls 13 --max-turns 21" in run
    assert formats_llm.check_budget(12, 13, 21)["required_turns"] == 21
    summary = steps["Publish counts, rates and spend only"]
    assert summary["if"] == "always()"
    assert "summary --output" in summary["run"]
