---
name: ssh_hardening
description: SSH security analysis for IoT devices and embedded systems
version: 1.0.0
tags: [ssh, hardening, terrapin, credentials, embedded, dropbear]
tools: [ssh_audit, nmap_scan]
device_types: [gateway, compute, router]
cpe_patterns: ["cpe:2.3:a:openbsd:openssh:*", "cpe:2.3:a:dropbear_ssh_project:dropbear:*"]
---

# Skill: SSH Security Analysis

## Overview
SSH is the primary remote management protocol for IoT gateways, compute nodes, and routers. Weak SSH configurations (default credentials, deprecated algorithms, Terrapin vulnerability) are common in embedded devices.

## Methodology

### 1. SSH Configuration Audit
- Run `ssh-audit <host>:<port>` for comprehensive analysis
- Check key exchange algorithms (reject diffie-hellman-group1-sha1)
- Check ciphers (reject CBC mode: aes128-cbc, 3des-cbc)
- Check MACs (reject MD5-based: hmac-md5)
- Check host key types (reject ssh-dss)

### 2. Terrapin Attack (CVE-2023-48795)
- Affects SSH implementations using ChaCha20-Poly1305 or CBC with Encrypt-then-MAC
- `ssh-audit` reports this automatically
- Mitigation: disable affected algorithms or update to patched versions
- Critical for IoT: many embedded devices run outdated Dropbear/OpenSSH

### 3. Default Credentials
- Common IoT defaults: admin/admin, root/root, pi/raspberry, ubnt/ubnt
- MikroTik default: admin/(empty password)
- RAK WisGate default: root/root
- Test with: `ssh -o StrictHostKeyChecking=no user@host`

### 4. Key-Based Authentication
- Check if password authentication is enabled (`PasswordAuthentication yes`)
- Check if root login is allowed (`PermitRootLogin yes`)
- Verify authorized_keys are properly restricted

### 5. Version Detection
- `ssh -V` or banner grabbing via nmap
- Dropbear < 2022.83: multiple CVEs
- OpenSSH < 9.0: various vulnerabilities
- MikroTik SSH: tied to RouterOS version

## Tools & Commands
- `ssh-audit <host>` — Full SSH configuration audit
- `nmap -sV -p 22 <target>` — SSH version detection
- `ssh -o StrictHostKeyChecking=no -o BatchMode=yes user@host` — Credential testing

## Common Findings
- Terrapin vulnerability (CVE-2023-48795) — very common in IoT
- Default credentials on gateways and routers
- Password authentication enabled (should be key-only)
- Root login permitted
- Outdated SSH implementations (Dropbear, OpenSSH)
- Weak key exchange and cipher algorithms

## Verification Steps
1. Run ssh-audit, document vulnerable algorithms
2. Test default credentials (authorized scope only)
3. Check Terrapin exposure on all SSH-enabled devices
4. Verify if password-only auth is exposed to network
