"""Exercise the shared batch summary formatter without running the browser app."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


def test_batch_summary_separates_groups_and_supports_historical_results():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the UI formatter test")
    source = (Path(__file__).resolve().parents[1] / "src/static/app.js").read_text()
    formatter = source.split("function batchSummaryText(ev) {", 1)[1].split("\nfunction _formatErrDetail", 1)[0]
    events = [
        {"aggregate": {"mixed_splits": True, "per_split": {
            "dev-public": {"macro_positive_f1": 1, "macro_positive_recall": 1, "macro_scenario_score_pct": 100},
            "test-public": {"macro_positive_f1": 0, "macro_positive_recall": 0, "macro_scenario_score_pct": None},
        }}},
        {"aggregate": {"avg_f1": 0.5, "avg_recall": 1, "avg_score_pct": 50}},
        {},
    ]
    script = "function batchSummaryText(ev) {" + formatter
    script += "\nconsole.log(JSON.stringify(" + json.dumps(events) + ".map(batchSummaryText)));"
    result = subprocess.run([node, "-e", script], check=True, capture_output=True, text=True)
    mixed, historical, empty = json.loads(result.stdout)
    assert "dev-public: F1=1.000 Recall=1.000 Score=100.0%" in mixed
    assert "test-public: F1=0.000 Recall=0.000 Score=N/A" in mixed
    assert "Avg" not in mixed
    assert "Avg F1=0.500" in historical
    assert empty == "Batch terminé — Total $0.0000"
    assert source.count("message:batchSummaryText(ev)") == 1
    assert source.count("text = batchSummaryText(ev)") == 1
