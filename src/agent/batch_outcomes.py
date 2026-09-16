"""Shared CLI/dashboard batch lifecycle and cost accounting, independent of scores."""
from __future__ import annotations

import json
import math
from pathlib import Path

from src.agent.results import run_status


def batch_run_status(run_dir: Path, results: dict, *, phase5_status: str, evaluated: bool) -> str:
    try:
        metadata = json.loads((Path(run_dir) / 'run_meta.json').read_text())
        if not isinstance(metadata, dict):
            metadata = {}
    except (OSError, ValueError):
        metadata = {}
    status = metadata.get('status')
    terminal = {'completed', 'partial', 'failed', 'stopped', 'blocked', 'skipped', 'budget_exceeded'}
    if not isinstance(status, str) or status not in terminal:
        status = run_status(results)
    if metadata.get('evidence_integrity') is False:
        status = 'failed'
    elif status == 'completed' and (metadata.get('cleanup_status') == 'failed' or metadata.get('usage_status') == 'incomplete'):
        status = 'partial'
    if status != 'completed':
        return status
    if phase5_status == 'incomplete':
        return 'phase5_incomplete'
    return 'ok' if evaluated else 'evaluation_failed'


def batch_cost_summary(results: list[dict]) -> dict:
    """Each attempted run contributes once, even without evaluation metrics."""
    known = 0.0
    missing = 0
    for result in results:
        metrics = result.get('metrics') or {}
        # An explicit unknown cost must not fall back to a possibly stale score.
        cost = result.get('cost_usd') if 'cost_usd' in result else metrics.get('total_cost_usd')
        if isinstance(cost, (int, float)) and not isinstance(cost, bool) and math.isfinite(cost) and cost >= 0:
            known += cost
        else:
            missing += 1
    return {'total_cost_usd': known if missing == 0 else None,
            'known_cost_usd': known, 'cost_missing_attempts': missing,
            'cost_attempts': len(results)}
