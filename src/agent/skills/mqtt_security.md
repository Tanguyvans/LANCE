---
name: mqtt_security
description: MQTT broker security testing for IoT smart city deployments
version: 1.0.0
tags: [mqtt, broker, iot, protocol, smart-city, mosquitto]
tools: [nmap_scan, mqtt_listen, curl_headers]
device_types: [gateway, compute]
cpe_patterns: ["cpe:2.3:a:eclipse:mosquitto:*"]
---

# Skill: MQTT Security Testing

## Overview
MQTT (Message Queuing Telemetry Transport) is the dominant IoT protocol. Misconfigurations — especially anonymous access and lack of TLS — are the #1 IoT vulnerability in smart city deployments.

## Methodology

### 1. Anonymous Access Testing
- Connect without credentials: `mosquitto_sub -h <broker> -t '#' -C 5`
- If messages arrive, anonymous access is enabled (critical finding)
- Check for anonymous publish: `mosquitto_pub -h <broker> -t test -m "probe"`

### 2. Topic Enumeration
- Subscribe to wildcard: `mosquitto_sub -h <broker> -t '#' -v`
- Subscribe to system topics: `mosquitto_sub -h <broker> -t '$SYS/#' -v`
- Look for sensitive data: credentials, sensor readings, commands
- Common IoT topics: `device/+/telemetry`, `command/+/control`, `firmware/+/update`

### 3. ACL Bypass
- Try subscribing to admin topics from unprivileged client
- Test topic injection: `../admin/config` or `+/+/+`
- Check if write access is unrestricted (publish to control topics)

### 4. TLS Analysis
- Check if port 8883 (MQTT over TLS) is open alongside 1883 (plaintext)
- If only 1883: all traffic is in cleartext (critical for smart city sensors)
- Verify certificate validation: `mosquitto_sub -h <broker> -p 8883 --cafile ca.crt`

### 5. Message Injection
- Publish fake sensor data to test if downstream systems validate input
- Example: `mosquitto_pub -h <broker> -t sensor/temp -m '{"value": 999}'`
- Check if actuators respond to injected commands

## Tools & Commands
- `mosquitto_sub` / `mosquitto_pub` — MQTT client tools
- `nmap -p 1883,8883 <target>` — Check MQTT ports
- `mqtt_listen` tool — Automated message capture

## Common Findings
- Anonymous read/write access (CVSS 7.5+)
- Plaintext MQTT without TLS (CVSS 5.3)
- Sensitive data in topic payloads (PII, credentials)
- No input validation on actuator commands
- $SYS topic exposed (information disclosure)

## Verification Steps
1. Confirm anonymous access by capturing real messages
2. Document exposed topics and data types
3. Test if injected messages affect system behavior
4. Check if TLS is available and properly configured
