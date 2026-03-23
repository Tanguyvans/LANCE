# Phase 2: Reconnaissance — NATO Smart City IoT Lab

**Date:** {{run_date}}
**Source:** Active network scans (arp_scan, nmap_discovery, nmap_scan, ssh_audit, curl_headers, mqtt_listen)

---

## 1. Summary

| Metric | Value |
|--------|-------|
| Total live hosts (ARP) | |
| Total live hosts (nmap) | |
| YAML devices confirmed | |
| Undocumented devices | |
| Unreachable YAML devices | |

## 2. Subnet Discovery Results

### 2.1 ARP Table (Layer 2)

| IP | MAC Address | Vendor | Hostname | In YAML? |
|----|-------------|--------|----------|----------|

### 2.2 Nmap Discovery

| IP | Latency | In YAML? |
|----|---------|----------|

## 3. Discovered Services per Device

### 3.1 Known Devices (in YAML model)

| Device | IP | Port | Service | Version (nmap) | Version (YAML) | Match? |
|--------|----|------|---------|----------------|----------------|--------|

### 3.2 Undocumented Devices — Open Ports

| IP | MAC | Vendor | Port | Service | Version | Device Type (guess) |
|----|-----|--------|------|---------|---------|---------------------|

### 3.3 Undocumented Devices — No Open Ports (down/filtered)

| IP | MAC | Vendor | Nmap Result | Hypothesis |
|----|-----|--------|-------------|------------|

## 4. YAML Model vs Reality Discrepancies

| Device | IP | Discrepancy Type | YAML Value | Nmap Value | Security Impact |
|--------|----|------------------|------------|------------|-----------------|

## 5. Unreachable YAML Devices

| Device (YAML) | Expected IP | Scan Result | Hypothesis |
|---------------|-------------|-------------|------------|

## 6. Service Detail Scans

### 6.1 SSH Audit

| Device | IP | Version | Terrapin? | Weak Ciphers? | Notes |
|--------|----|---------|-----------|---------------|-------|

### 6.2 HTTP Headers

| Device | IP | Port | Server | Missing Headers | Notes |
|--------|----|------|--------|-----------------|-------|

### 6.3 MQTT Access

| Device | IP | Port | Anonymous? | Messages | Topics |
|--------|----|------|------------|----------|--------|

## 7. Recommendations for Phase 3

| Priority | Device | IP | Test Type | Rationale |
|----------|--------|----|-----------|-----------|
