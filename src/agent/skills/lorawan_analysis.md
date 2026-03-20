---
name: lorawan_analysis
description: LoRaWAN network security analysis for smart city sensor deployments
version: 1.0.0
tags: [lorawan, lora, sensor, gateway, rak, chirpstack, smart-city]
tools: [nmap_scan, curl_headers, mqtt_listen, hackrf_capture]
device_types: [gateway, sensor]
cpe_patterns: []
---

# Skill: LoRaWAN Security Analysis

## Overview
LoRaWAN is widely used in smart city sensor networks (environmental monitoring, metering, parking). Security depends on activation mode (OTAA vs ABP), key management, and network server configuration.

## Methodology

### 1. Activation Mode Assessment
- **OTAA (Over-The-Air Activation)**: preferred, keys derived per session
- **ABP (Activation By Personalization)**: static keys, replay-vulnerable
- Check gateway configuration for which mode sensors use
- ABP with static DevAddr and session keys is a critical finding

### 2. Key Management
- AppKey (OTAA root key): must be unique per device
- NwkSKey / AppSKey (session keys): derived in OTAA, static in ABP
- Check if keys are hardcoded in firmware or config files
- Default/shared keys across devices = critical vulnerability

### 3. Replay Attack Assessment
- ABP devices: frame counter reset on reboot enables replay
- Check if frame counter validation is enforced on network server
- LoRaWAN 1.0.x: single frame counter, easier to replay
- LoRaWAN 1.1+: separate uplink/downlink counters

### 4. Gateway Security
- WisGate / RAK gateways often expose web interface (port 80/443)
- Check for default credentials on gateway admin panel
- Verify packet forwarder configuration (Semtech UDP vs MQTT)
- Gateway compromise = all downstream sensor data at risk

### 5. Network Server Assessment
- ChirpStack, TTN, or proprietary network server
- Check API authentication and access controls
- Verify if device provisioning is secured
- Check for unencrypted gRPC/REST API endpoints

## Tools & Commands
- `nmap -p 80,443,1700,8080 <gateway>` — Gateway port scan
- `curl_headers http://<gateway>` — Check web interface
- Gateway admin panel — Review LoRaWAN configuration
- `mqtt_listen` on gateway MQTT — Capture forwarded packets

## Common Findings
- ABP activation with static keys (CVSS 6.5+)
- Default gateway admin credentials
- Frame counter validation disabled
- Shared AppKey across multiple devices
- Unencrypted gateway-to-server communication
- Gateway web interface without HTTPS

## Verification Steps
1. Identify activation mode (OTAA vs ABP) for each sensor
2. Check if gateway web interface uses default credentials
3. Verify frame counter enforcement on network server
4. Check gateway-to-network-server encryption
