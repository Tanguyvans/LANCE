# Pentest Report — NATO Smart City IoT Lab

**Date:** {{run_date}}
**Model:** {{model}}
**Subnet:** (from topology)

---

## 1. Executive Summary

| Metric | Value |
|--------|-------|
| Devices scanned | |
| Vulnerabilities found | |
| Confirmed exploitable (Phase 4) | |
| Devices compromised (Phase 5) | |
| Credentials harvested (Phase 5) | |
| Crown jewels reached (Phase 5) | |
| Data exfiltrated (Level 3 evidence) | |
| Overall risk level | |

<!-- 5-10 lines: scope, key findings, overall risk, immediate actions required -->

## 2. Scope and Methodology

- **Target subnet:** (from Phase 1 topology)
- **Phases executed:** 1 (Graph) → 2 (Recon) → 3 (Vuln) → 4 (Exploit) → 5 (Report)
- **Tools used:**
- **Limitations:**

## 3. Topology and Attack Surface

### 3.1 Network Diagram (from Phase 1)

<!-- Describe the topology: perimeter, core, gateways, sensors -->

### 3.2 Declared vs Discovered Devices

| IP | Device ID | Discovered by nmap? | Open Ports | Status |
|----|-----------|---------------------|------------|--------|
<!-- Fill from Phase 1 topology + Phase 2 nmap results -->

### 3.3 Undocumented Devices

| IP | MAC Address | Open Ports | Device Type (guess) |
|----|-------------|------------|---------------------|

## 4. Reconnaissance Results (Phase 2)

### 4.1 Services per Device

| Device | IP | Port | Service | Version (nmap) | Version (YAML) | Match? |
|--------|----|------|---------|----------------|----------------|--------|

### 4.2 Key Discrepancies

<!-- List Phase 1 vs Phase 2 differences with security impact -->

{{SECTION_5_TABLE}}

*(Section 5 table is auto-generated — do not rewrite it)*

**Status legend:**
- **Confirmed** — Phase 4 exploitation succeeded
- **Not Exploitable** — Phase 4 test ran, exploit failed
- **Inconclusive** — Tool error, needs manual retest
- **Potential (untested)** — Phase 3 finding, no Phase 4 test
- **Potential (CVE-based)** — NVD match only, no active test

{{SECTION_6_TABLES}}

*(Section 6 tables are auto-generated — do not rewrite them)*

**Evidence levels:** 1=Detected (port open), 2=Exploited (logged in/connected), 3=Data exfiltrated (passwords/configs/PII retrieved)

## 7. Attack Paths

### 7.1 Critical Multi-Hop Chains

<!-- Format: Internet → Device A (CVE) → Device B (CVE) → Target
     Include path score and impact -->

### 7.2 Pivot Nodes

| Device | Betweenness | Role |
|--------|-------------|------|

### 7.3 Infiltration Campaign (Phase 5)

<!-- Fill from 05_intrusion.json. If Phase 5 was skipped, write "Phase 5 not executed." -->

**Campaign summary:**

| Metric | Value |
|--------|-------|
| Devices targeted | |
| Devices compromised | |
| Credentials harvested | |
| Crown jewels reached | |

**Compromised devices:**

| Device | IP | Access method | Credentials used | Data exfiltrated |
|--------|----|---------------|-----------------|-----------------|

**Credential harvest:**

| Username | Password | Service | Harvested from | Used to compromise |
|----------|----------|---------|---------------|-------------------|

**Attack chains:**

<!-- For each chain in 05_intrusion.json, write:
     Hop 1: entry_ip (method) → Hop 2: pivot_ip (method) → ... → Crown jewel
     Include the commands run and key output at each hop. -->

**Crown jewels reached:**

<!-- For each crown jewel: device, access method, data retrieved (passwords, configs, shadow, DB dump) -->

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
