from __future__ import annotations

import pytest

datasets = pytest.importorskip("datasets")
pytest.importorskip("trl")

from datasets import Dataset, concatenate_datasets

from training.train_qlora_3b import (
    estimate_total_update_steps,
    normalize_chat_features,
    resolve_num_train_epochs,
)


def test_two_vuln_epochs_produce_expected_update_count() -> None:
    assert estimate_total_update_steps(
        7427,
        per_device_batch_size=1,
        gradient_accumulation_steps=32,
        num_train_epochs=2,
    ) == 466


def test_num_train_epochs_can_be_overridden_by_expert() -> None:
    training = {
        "num_train_epochs": 2,
        "num_train_epochs_by_expert": {"secretary": 1, "exploit": 1},
    }

    assert resolve_num_train_epochs(training, "secretary") == 1
    assert resolve_num_train_epochs(training, "exploit") == 1
    assert resolve_num_train_epochs(training, "recon") == 2


def test_normalize_chat_features_preserves_heterogeneous_tool_calls() -> None:
    base = Dataset.from_list([{
        "messages": [
            {"role": "system", "content": "Analyze the evidence."},
            {"role": "assistant", "content": "No tool call is required."},
        ],
        "tools": [],
        "metadata": {"completion_mode": "memo_only"},
    }])
    feedback = Dataset.from_list([{
        "messages": [
            {"role": "system", "content": "Correct the deliverable."},
            {
                "role": "assistant",
                "content": "Saving the correction.",
                "tool_calls": [{
                    "id": "feedback-1",
                    "type": "function",
                    "function": {
                        "name": "save_deliverable",
                        "arguments": {
                            "filename": "03_device.json",
                            "content": "{\"vulnerabilities\":[]}",
                        },
                    },
                }],
            },
        ],
        "tools": [{
            "type": "function",
            "function": {
                "name": "save_deliverable",
                "description": "Save a deliverable.",
                "parameters": {"type": "object"},
            },
        }],
        "metadata": {"source": "accepted-feedback"},
    }])

    merged = concatenate_datasets([
        normalize_chat_features(base),
        normalize_chat_features(feedback),
    ])

    assert len(merged) == 2
    assert merged[0]["messages"][-1]["content"] == "No tool call is required."
    tool_call = merged[1]["messages"][-1]["tool_calls"][0]
    assert tool_call["function"]["name"] == "save_deliverable"
    assert tool_call["function"]["arguments"]["filename"] == "03_device.json"
