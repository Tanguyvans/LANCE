---
name: firmware_analysis
description: IoT firmware extraction and vulnerability analysis
version: 1.0.0
tags: [firmware, binwalk, embedded, credentials, binary, smart-city]
tools: [nmap_scan, curl_headers]
device_types: [gateway, sensor, camera, ap, router]
cpe_patterns: []
---

# Skill: Firmware Analysis

## Overview
IoT firmware often contains hardcoded credentials, debug interfaces, and outdated libraries. For smart city devices operating at scale, a single firmware vulnerability affects every deployed unit.

## Methodology

### 1. Firmware Acquisition
- Check vendor support pages for downloadable firmware
- Capture via firmware update mechanism (HTTP/TFTP)
- Extract from flash memory (hardware access required)
- Common formats: .bin, .img, .tar.gz, .uf2

### 2. Filesystem Extraction
- Use binwalk for analysis: `binwalk -e firmware.bin`
- Identify filesystem type: SquashFS, JFFS2, CramFS, ext4
- Extract with appropriate tools: `unsquashfs`, `jefferson`
- Look for /etc/shadow, /etc/passwd, configuration files

### 3. Credential Discovery
- Search for hardcoded passwords: `grep -r "password\|passwd\|secret\|key" .`
- Check SSH keys: `find . -name "*.pem" -o -name "id_rsa" -o -name "authorized_keys"`
- Look for API tokens and certificates
- Default credentials in init scripts or web application code

### 4. Service Analysis
- Identify running services from init scripts (/etc/init.d/, systemd)
- Check for debug ports (telnet, serial console, JTAG)
- Look for development tools left in production firmware
- Analyze web server configuration for misconfigurations

### 5. Library Vulnerability Assessment
- List shared libraries: `find . -name "*.so*"`
- Identify versions and check against CVE databases
- Common vulnerable libraries: OpenSSL, libcurl, busybox
- Check for known vulnerable versions of web servers (lighttpd, uhttpd)

## Tools & Commands
- `binwalk -e <firmware>` — Extract firmware contents
- `strings <firmware> | grep -i pass` — Quick credential search
- `find . -name "*.conf" -exec grep -l password {} \;` — Config file search
- `checksec --dir=.` — Check binary protections

## Common Findings
- Hardcoded credentials in firmware (CVSS 9.0+)
- Outdated libraries with known CVEs
- Debug interfaces enabled in production
- Private keys embedded in firmware
- Writable firmware update without signature verification

## Verification Steps
1. Extract and examine filesystem contents
2. Search for credentials and keys
3. Identify and version all major libraries
4. Check for debug/development artifacts
5. Verify firmware update signing mechanism
