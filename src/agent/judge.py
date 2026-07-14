"""LLM-as-a-judge for evaluating pentest runs."""
from __future__ import annotations

import json
from pathlib import Path
import yaml

from src.agent.provider import LLMProvider
from src.benchmark.evaluator import _load_llm_findings

SYSTEM_PROMPT = """You are an expert cybersecurity auditor. Your task is to evaluate the findings produced by an AI pentester against a ground truth dataset of known vulnerabilities.
You will be provided with:
1. GROUND TRUTH: A list of actual vulnerabilities present in the target environment.
2. LLM FINDINGS: A list of vulnerabilities reported by the AI pentester.

Your goal is to perform a SEMANTIC VALIDATION of the LLM's findings and match them to the ground truth.
CRITICAL RULES FOR SEMANTIC VALIDATION:
- Do NOT simply match based on CVE IDs or keywords. You must read the 'details', 'proof_of_concept', and 'remediation' provided by the AI.
- Ensure the AI's sentences actually make technical sense. If the AI claims to have found a vulnerability but its explanation is contradictory, physically impossible in the given context, or nonsensical, you MUST reject it as a False Positive (hallucination), EVEN IF the CVE ID or vulnerability type matches the ground truth.
- A match is valid ONLY IF the description and proof provided by the AI semantically demonstrate that it actually discovered and understood the underlying flaw.
- If an LLM finding does not match any ground truth vulnerability, OR if its semantic description is invalid/hallucinated, it is a False Positive.
- If a ground truth vulnerability is not matched by any valid LLM finding, it is a False Negative.
- A single ground truth vulnerability might be matched by multiple valid LLM findings. That's fine, map them all.

Additionally, provide two overall qualitative scores for the AI pentester's findings (from 1 to 5):
- 'overall_clarity_score' (1-5): How clear, understandable, and professional are the 'details' and 'proof_of_concept'? (1=Nonsense/Incomprehensible, 5=Clear, professional, and well-structured).
- 'overall_remediation_score' (1-5): How accurate and actionable are the proposed 'remediation' steps? (1=Completely wrong or absent, 5=Highly accurate and actionable).

Return ONLY a JSON object (no markdown formatting, just raw JSON) matching this schema:
{
  "matches": [
    {
      "llm_finding_id": <int index of the llm finding>,
      "gt_vuln_id": <int index of the ground truth vuln>,
      "reasoning": "<short explanation why this is a match>"
    }
  ],
  "false_positives": [
    {
      "llm_finding_id": <int index>,
      "reasoning": "<why this doesn't match anything>"
    }
  ],
  "overall_clarity_score": <int 1-5>,
  "overall_remediation_score": <int 1-5>
}
"""

def evaluate_with_llm(run_dir: Path, gt_file: Path, model: str, provider_name: str) -> dict:
    gt_data = yaml.safe_load(gt_file.read_text())
    gt_vulns = gt_data.get("vulnerabilities", [])
    try:
        llm_findings = _load_llm_findings(run_dir)
    except FileNotFoundError:
        llm_findings = []

    if not gt_vulns and not llm_findings:
        return {"matches": [], "false_positives": [], "model": model}

    # Prepare data for prompt
    gt_json = json.dumps([
        {
            "id": i,
            "title": v.get("title", ""),
            "cve": v.get("cve", ""),
            "ip": v.get("ip", ""),
            "category": v.get("category", "")
        }
        for i, v in enumerate(gt_vulns)
    ], indent=2)

    findings_json = json.dumps([
        {
            "id": i,
            "title": f.get("title") or f.get("name") or f.get("type", ""),
            "cve_ids": f.get("cve_ids", []),
            "device_ip": f.get("device_ip", ""),
            "details": f.get("details", ""),
            "proof_of_concept": f.get("proof_of_concept", ""),
            "remediation": f.get("remediation", "")
        }
        for i, f in enumerate(llm_findings)
    ], indent=2)

    user_message = f"GROUND TRUTH:\n{gt_json}\n\nLLM FINDINGS:\n{findings_json}"

    provider = LLMProvider(provider=provider_name, model=model)
    
    if provider.provider == "anthropic":
        response = provider.client.messages.create(
            model=model,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
            max_tokens=2048,
            temperature=0.0
        )
        content = response.content[0].text.strip()
    else:
        response = provider.client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message}
            ],
            temperature=0.0
        )
        content = response.choices[0].message.content.strip()

    if content.startswith("```json"):
        content = content[7:-3]
    elif content.startswith("```"):
        content = content[3:-3]

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        raise ValueError(f"LLM Judge did not return valid JSON: {content[:200]}")

    # Compute additional metrics
    tp = len({m["gt_vuln_id"] for m in parsed.get("matches", [])})
    false_positives = len(parsed.get("false_positives", []))
    
    clarity_score = parsed.get("overall_clarity_score", None)
    remediation_score = parsed.get("overall_remediation_score", None)
    
    total_gt = len(gt_vulns)

    precision = tp / (tp + false_positives) if (tp + false_positives) > 0 else 0.0
    recall = tp / total_gt if total_gt > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "model": model,
        "true_positives": tp,
        "false_positives": false_positives,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "clarity_score": clarity_score,
        "remediation_score": remediation_score,
        "matches": parsed.get("matches", []),
        "false_positives_list": parsed.get("false_positives", [])
    }
