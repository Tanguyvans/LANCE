---
name: mikrotik_routeros
description: MikroTik RouterOS security assessment for IoT edge routers
version: 1.0.0
tags: [router, mikrotik, routeros, winbox, edge, smart-city]
tools: [nmap_scan, ssh_audit, curl_headers, nvd_lookup]
device_types: [router]
cpe_patterns: ["cpe:2.3:o:mikrotik:routeros:*"]
---

# Skill: MikroTik RouterOS Security

## Overview
MikroTik routers are common in IoT deployments as edge routers. RouterOS has a history of critical CVEs (Winbox, SMB, web proxy). The hAP ac2/ac3 series is frequently found in smart city edge networks.

## Methodology

### 1. Version Detection
- `nmap -sV -p 21,22,23,53,80,443,2000,8291,8728,8729 <target>`
- Key ports: 8291 (Winbox), 8728/8729 (API), 80/443 (WebFig)
- RouterOS version visible in service banners
- Check against known CVE database

### 2. Service Exposure Assessment
- Winbox (TCP 8291): proprietary management — should not face untrusted networks
- WebFig (TCP 80/443): web management interface
- API (TCP 8728/8729): RouterOS API, often unprotected
- Telnet (TCP 23): plaintext, should be disabled
- FTP (TCP 21): file transfer, should be disabled
- DNS (TCP/UDP 53): if open, check for DNS amplification

### 3. Known CVE Patterns
- CVE-2018-14847 (Winbox): unauthenticated remote access, read credentials
- CVE-2023-30799: privilege escalation via web interface
- CVE-2019-3977: auto-upgrade mechanism directory traversal
- CVE-2018-7445: SMB buffer overflow (pre-auth RCE)
- Always check RouterOS version against NVD

### 4. Default Credentials
- Default: admin with empty password
- Check if password has been set: attempt login
- Verify if default user 'admin' still exists with full privileges

### 5. Firewall and NAT Assessment
- Check input chain rules (what's allowed to reach the router)
- Verify if management interfaces are restricted by IP
- Check NAT rules for unintended port forwards
- Look for permissive firewall rules (accept all)

## Tools & Commands
- `nmap -sV -p 8291,80,443,22,23,8728 <target>` — Service detection
- `ssh_audit <target>` — SSH configuration
- `curl_headers http://<target>` — WebFig headers
- `nvd_lookup 'cpe:2.3:o:mikrotik:routeros:*'` — CVE search

## Common Findings
- Outdated RouterOS with known CVEs (CVSS 9.0+)
- Winbox exposed to untrusted networks
- Default admin credentials
- Management services on all interfaces
- Weak or no firewall input rules
- DNS service open (amplification risk)

## Verification Steps
1. Identify RouterOS version from service banners
2. Check all management ports (8291, 80, 443, 8728, 22, 23)
3. Test default credentials (admin / empty)
4. Query NVD for version-specific CVEs
5. Assess firewall rules if access is obtained
