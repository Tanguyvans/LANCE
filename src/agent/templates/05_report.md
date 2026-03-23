# Pentest Report — NATO Smart City IoT Lab

**Date:** {{run_date}}
**Model:** {{model}}
**Subnet:** 192.168.88.0/24

---

## 1. Executive Summary

| Metric | Value |
|--------|-------|
| Devices scanned | |
| Vulnerabilities found | |
| Confirmed exploitable | |
| Overall risk level | |

<!-- 5-10 lines: scope, key findings, overall risk, immediate actions required -->

## 2. Scope and Methodology

- **Target subnet:** 192.168.88.0/24
- **Phases executed:** 1 (Graph) → 2 (Recon) → 3 (Vuln) → 4 (Exploit) → 5 (Report)
- **Tools used:**
- **Limitations:**

## 3. Topology and Attack Surface

### 3.1 Network Diagram (from Phase 1)

<!-- Describe the topology: perimeter, core, gateways, sensors -->

### 3.2 Declared vs Discovered Devices

| IP | YAML Device | Discovered | Status |
|----|-------------|------------|--------|
| 192.168.88.1 | mikrotik | | |
| 192.168.88.231 | iot_hub | | |
| 192.168.88.238 | wisgate | | |
| 192.168.88.247 | rpi5 | | |
| 192.168.88.248 | jetson | | |
| 192.168.88.251 | eap613 | | |
| 192.168.88.253 | nvr | | |

### 3.3 Undocumented Devices

| IP | MAC Address | Open Ports | Device Type (guess) |
|----|-------------|------------|---------------------|

## 4. Reconnaissance Results (Phase 2)

### 4.1 Services per Device

| Device | IP | Port | Service | Version (nmap) | Version (YAML) | Match? |
|--------|----|------|---------|----------------|----------------|--------|

### 4.2 Key Discrepancies

<!-- List Phase 1 vs Phase 2 differences with security impact -->

## 5. Discovered Vulnerabilities

| ID | Device | Type | Severity | Service | Status | Evidence |
|----|--------|------|----------|---------|--------|----------|

**Status legend:**
- **Confirmed** — Phase 4 exploitation succeeded
- **Not Exploitable** — Phase 4 test ran, exploit failed
- **Inconclusive** — Tool error, needs manual retest
- **Potential (untested)** — Phase 3 finding, no Phase 4 test
- **Potential (CVE-based)** — NVD match only, no active test

## 6. Exploitation Tests (Phase 4)

| Test ID | Device | Test Type | Tool Used | Status | Evidence Level | Evidence Excerpt |
|---------|--------|-----------|-----------|--------|----------------|------------------|

**Evidence levels:** 1=Detected, 2=Validated (interaction), 3=Exploited (data extracted)

## 7. Attack Paths

### 7.1 Critical Multi-Hop Chains

<!-- Format: Internet → Device A (CVE) → Device B (CVE) → Target
     Include path score and impact -->

### 7.2 Pivot Nodes

| Device | Betweenness | Role |
|--------|-------------|------|

## 8. Risk Scores

| Rank | Device | Risk Score | Max CVSS | Hops from Internet | Centrality |
|------|--------|------------|----------|---------------------|------------|

## 9. Remediation Recommendations

### 9.1 IMMEDIATE (Confirmed HIGH/CRITICAL)

| # | Device | Action | Rationale |
|---|--------|--------|-----------|

### 9.2 SHORT TERM (Potential HIGH + Confirmed MEDIUM)

| # | Device | Action | Rationale |
|---|--------|--------|-----------|

### 9.3 IMPROVEMENT (LOW + hardening)

| # | Device | Action | Rationale |
|---|--------|--------|-----------|

## 10. Appendices

### 10.1 Complete CVE List

| Device | CVE ID | CVSS | Severity | Description |
|--------|--------|------|----------|-------------|

### 10.2 Tool Outputs Reference

All raw tool outputs are saved in `tool_calls.jsonl` in the run directory.
