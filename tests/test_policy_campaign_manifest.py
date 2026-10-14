"""Pilot manifest calibration: the LLM arm needs budgets coherent with
observed model latency. On S1 (2026-10-14) the 600 s run budget and the
240 s per-device deadline made completion structurally impossible
(phase 3 alone can take 4 x 240 s serially), so the run died in
phase 4 and the pair was discarded instead of measured.
"""
import json
from pathlib import Path

from src.benchmark.policy_campaign import load_manifest

PILOT = (
    Path(__file__).parents[1]
    / "benchmarks/experiments/policy-comparison/pilot-2026-10.json"
)


def test_pilot_manifest_budgets_fit_observed_latency():
    manifest = load_manifest(PILOT)
    configuration = manifest["configuration"]
    assert configuration["max_duration_s"] == 1800
    assert configuration["phase3_device_timeout_s"] == 600


def test_manifest_rejects_non_numeric_device_timeout(tmp_path):
    manifest = json.loads(PILOT.read_text())
    manifest["configuration"]["phase3_device_timeout_s"] = "600"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    try:
        load_manifest(path)
    except ValueError:
        return
    raise AssertionError("non-numeric phase3_device_timeout_s must be rejected")


def test_every_trial_resolves_to_existing_files():
    """The campaign workflow deploys by instance and scores against the
    trial ground truth; both files must exist for all 12 trials."""
    manifest = load_manifest(PILOT)
    root = PILOT.parents[3]
    assert len(manifest["trials"]) == 12
    scenario_files = {"s1": "S1.yaml", "s14": "S14.yaml", "s15": "S15.yaml", "s1h": "S1h.yaml"}
    for trial in manifest["trials"]:
        gt = (PILOT.parent / trial["ground_truth"]).resolve()
        assert gt.is_file(), trial["trial_id"]
        scenario = root / "benchmarks/scenarios/dev" / scenario_files[trial["instance_id"]]
        assert scenario.is_file(), trial["trial_id"]
        assert trial["order"] in (["rules", "llm"], ["llm", "rules"])
