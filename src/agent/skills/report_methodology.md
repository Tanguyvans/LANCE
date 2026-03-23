---
name: report_methodology
description: Pentest report writing methodology with status classification and evidence rules
version: 1.0.0
tags: [report, methodology, pentest, classification]
tools: [read_deliverable, list_deliverables, save_deliverable]
device_types: []
cpe_patterns: []
---

# Skill: Pentest Report Methodology

## Overview
This skill defines the rules for writing a professional IoT pentest report. It covers vulnerability status classification, evidence handling, and report structure to ensure findings are accurately represented without downgrading confirmed exploits.

## Methodology

### Status Classification Rules
When compiling findings from previous phases into the final report, the following status mapping MUST be applied:

| Phase 4 Status | Report Status | Rationale |
|----------------|--------------|-----------|
| CONFIRMED | Confirmed | Exploit succeeded — NEVER downgrade to Potential |
| NOT_EXPLOITABLE | Not Exploitable | Test ran but exploit failed |
| ERROR | Inconclusive | Tool error, needs manual retest |
| *(not tested)* | Potential (untested) | Phase 3 finding without Phase 4 validation |
| *(CVE match only)* | Potential (CVE-based) | Known CVE from NVD, no active test performed |

**Critical rule:** A vulnerability confirmed by Phase 4 exploitation MUST remain "Confirmed" in the report. Downgrading a confirmed finding to "Potential" is a report integrity violation.

### Evidence Levels
Each finding should include its evidence level:

- **Level 1 — Detected**: Vulnerability exists based on version banner or configuration check
- **Level 2 — Validated**: Successful interaction proving the vulnerability (e.g., MQTT messages received without auth)
- **Level 3 — Exploited**: Sensitive data extracted or system state modified

### Report Structure Best Practices
1. **Executive Summary**: 5-10 lines max, focus on business impact and immediate actions
2. **Vulnerability Table**: Must include Status and Evidence columns
3. **Exploitation Section**: Reference Phase 4 JSON deliverable for raw evidence
4. **Remediation**: Prioritize by severity AND exploitability (confirmed > potential)
5. **Data Source Priority**: Phase 2 (real scans) overrides Phase 1 (YAML model) for service information

## Tools & Commands

### Reading Phase Data
```bash
# List all available deliverables
list_deliverables()

# Read Phase 4 exploitation results (JSON format)
read_deliverable("04_exploitation.json")

# Read Phase 3 vulnerability queue
read_deliverable("03_vuln_analysis.json")
```

### Report Quality Checks
- Every confirmed finding must have evidence text from Phase 4
- Every finding must have a status from the classification table above
- Remediation priority must match: Confirmed HIGH > Potential HIGH > Confirmed MEDIUM
