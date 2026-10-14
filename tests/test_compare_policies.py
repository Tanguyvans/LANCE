"""Unit tests for the paired-comparison completeness gate.

The phase-3 artifact status preserves scanner/device errors as
information ("completed_with_device_errors"), while the run verdict in
src/agent/phases/analysis/context.py only degrades when work is left
undone. The comparator must follow the verdict semantics: an arm whose
devices were all analyzed, with none failed, is complete even when a
redundant scanner probe recorded an error.
"""
from types import SimpleNamespace

import pytest

from src.benchmark.compare_policies import _analysis_complete


def _result(status, total=4, analyzed=4, failed=0):
    return SimpleNamespace(
        phase3_status=status,
        phase3_devices_total=total,
        phase3_devices_analyzed=analyzed,
        phase3_devices_failed=failed,
    )


@pytest.mark.parametrize("status", ["completed", "completed_with_device_errors"])
def test_all_devices_analyzed_none_failed_is_complete(status):
    assert _analysis_complete(_result(status))


def test_device_errors_with_failed_device_is_incomplete():
    assert not _analysis_complete(
        _result("completed_with_device_errors", analyzed=3, failed=1)
    )


def test_completed_status_with_failed_device_is_incomplete():
    assert not _analysis_complete(_result("completed", analyzed=3, failed=1))


@pytest.mark.parametrize("status", ["partial", "failed", "skipped", None])
def test_other_statuses_are_incomplete(status):
    assert not _analysis_complete(_result(status))


def test_no_devices_is_incomplete():
    assert not _analysis_complete(_result("completed", total=0, analyzed=0))
