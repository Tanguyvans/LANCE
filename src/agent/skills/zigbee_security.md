---
name: zigbee_security
description: Zigbee/802.15.4 network security assessment for IoT smart city sensor deployments
version: 1.1.0
tags: [zigbee, z2m, zigbee2mqtt, iot, protocol, smart-city, wireless, 802.15.4, killerbee]
tools: [nmap_scan, mqtt_listen, curl_headers]
device_types: [gateway, sensor, compute]
cpe_patterns: []
---

# Skill: Zigbee Security Testing

## Overview
Zigbee (IEEE 802.15.4) is widely used in smart city sensor networks for low-power mesh communication. In typical deployments, a Zigbee coordinator (e.g., Zigbee2MQTT on Raspberry Pi) bridges Zigbee devices to an MQTT broker, creating a chain of trust exploitable at multiple points. Key risks include network key extraction, unauthenticated bridging, device impersonation, and Touchlink abuse. Even with Zigbee 3.0 encryption, passive eavesdroppers can identify device types and events from traffic patterns with 83-99% accuracy (ZLeaks, ACNS 2022).

## Methodology

### 1. Zigbee2MQTT Interface Discovery
- Scan for Zigbee2MQTT web UI: `nmap -sV -p 8080,8081,8443 <coordinator>`
- The Z2M frontend has **no built-in authentication by default** — anyone on the LAN can access it
- Access device list, network map, and configuration via the web UI
- Check REST API: `curl http://<coordinator>:8080/api/devices`
- Look for bridge configuration exposing `network_key` and `pan_id`

### 2. Network Key Extraction via MQTT
- Subscribe to Zigbee2MQTT config topics: `mosquitto_sub -h <broker> -t 'zigbee2mqtt/bridge/#' -v`
- Check `bridge/config` and `bridge/info` for network key disclosure, channel, PAN ID, extended PAN ID
- If MQTT is unauthenticated, the Zigbee network key is trivially extractable
- With the network key, an attacker has **total control**: join/remove devices, send arbitrary ZCL commands, decrypt all captured traffic

### 3. Network Key Extraction via RF Sniffing
- During device join, the network key is transmitted encrypted with the well-known Trust Center Link Key: `5A:69:67:42:65:65:41:6C:6C:69:61:6E:63:65:30:39` ("ZigBeeAlliance09")
- This default key **cannot be changed** due to backward compatibility (Zigbee specification requirement)
- Use CC2531 USB dongle + ZBOSS Sniffer or KillerBee's `zbdsniff` on the target channel (11-26)
- Trigger a device re-join (power cycle a sensor or enable permit join) and capture the Transport Key frame
- Zigbee 3.0 install codes can provide device-unique link keys, but most manufacturers still use the default

### 4. Device Enumeration and Message Interception
- List paired devices: subscribe to `zigbee2mqtt/bridge/devices`
- For each device note: IEEE address, model, manufacturer, power source, link quality (LQI)
- Capture sensor readings: `mosquitto_sub -h <broker> -t 'zigbee2mqtt/+' -v`
- Data includes: temperature, humidity, occupancy, vibration, door open/close, battery levels
- In smart city context: sensor data may reveal occupancy patterns, building usage, behavioral PII

### 5. Command Injection via MQTT
- Test actuator control: `mosquitto_pub -h <broker> -t 'zigbee2mqtt/<device>/set' -m '{"state":"ON"}'`
- Try OTA update trigger: publish to `zigbee2mqtt/<device>/ota_update/update`
- Force device removal: publish to `zigbee2mqtt/bridge/request/device/remove`
- Rename devices to cause confusion: publish to `zigbee2mqtt/bridge/request/device/rename`

### 6. Permit Join Exploitation
- Check join status: subscribe to `zigbee2mqtt/bridge/config`
- Force permit join remotely: `mosquitto_pub -h <broker> -t 'zigbee2mqtt/bridge/request/permit_join' -m '{"value":true}'`
- If successful, rogue devices (e.g., CC2531 with custom firmware) can join and receive the network key
- Monitor for unauthorized joins: `zigbee2mqtt/bridge/event`
- This is a **critical finding** (CVSS 8.8) as it allows full network compromise from the LAN

### 7. Touchlink Attacks (Zigbee 3.0)
- The Touchlink preconfigured link key was **leaked publicly in March 2015** and cannot be revoked
- A single Touchlink-enabled device is sufficient to compromise the entire network
- Attack range: passive eavesdropping from **130m**, active takeover from **190m**
- Using Z3sec framework:
  1. Scan for touchlink-enabled devices in range
  2. Send touchlink factory reset command (no authentication required)
  3. Device resets and enters commissioning mode
  4. Attacker commissions device onto their own malicious network
- Mitigation: disable touchlink on all devices if possible (most hubs allow this)

### 8. Protocol-Level Attacks (802.15.4)
- **Replay attacks**: Zigbee is particularly vulnerable due to weak replay protection. Captured ZCL commands can be retransmitted to re-trigger actuator actions (KillerBee `zbreplay`)
- **PAN ID conflict flood**: `zbpanidconflictflood` sends beacon frames with the target PAN ID, causing network collapse within seconds (requires 2 radio interfaces)
- **Selective jamming**: Target specific frames (e.g., only ACKs) on 2.4 GHz channels 11-26 to cause retransmission floods
- **ZCL fuzzing**: Malformed ZCL frames can crash device firmware (CVE-2020-27890, CVE-2020-27891, CVE-2020-27892 on TI CC2538 Z-Stack)

## Tools & Commands

### Software-Based (via MQTT/IP)
- `mosquitto_sub -h <broker> -t 'zigbee2mqtt/#' -v` — Monitor all Z2M traffic
- `mosquitto_pub -h <broker> -t 'zigbee2mqtt/bridge/request/permit_join' -m '{"value":true}'` — Force permit join
- `nmap -sV -p 8080 <coordinator>` — Find Z2M web interface
- `curl http://<coordinator>:8080/api/devices` — Z2M REST API

### RF-Based (requires hardware)
- **KillerBee** framework: `zbstumbler` (discovery), `zbdump` (capture), `zbdsniff` (key extraction), `zbreplay` (replay), `zbpanidconflictflood` (DoS)
- **Z3sec** framework: Touchlink factory reset, channel switching, device theft
- **Wireshark** with zigbee dissector: filter `zbee_nwk`, add network key for decryption
- **Hardware**: CC2531 USB dongle (~5 EUR), ApiMote, HackRF One

## Known CVEs
- **CVE-2020-27890** (CVSS 7.5): DoS via malformed ZCL frames on TI CC2538 Z-Stack 3.0.1
- **CVE-2020-27891** (CVSS 7.5): ZCL Read Reporting Configuration Response crash on TI CC2538
- **CVE-2020-27892** (CVSS 8.2): ZCL Discover Commands Response crash, freezes end device until restart
- **CVE-2025-1394** (High): Buffer management error in SiLabs EmberZNet stack (GSDK <= 4.4.5)
- **CVE-2025-8414** (High): Buffer overflow in Zigbee EZSP Host Applications via improper input validation

## Common Findings
- Zigbee network key exposed via unauthenticated MQTT (CVSS 8.1)
- Zigbee2MQTT web UI accessible without authentication (CVSS 7.5)
- Device command injection via unauthenticated MQTT publish (CVSS 7.4)
- Permit join can be forced remotely via MQTT (CVSS 8.8)
- Network key sniffable during device join using default Trust Center Link Key (CVSS 8.1)
- Sensor data leaking occupancy patterns and behavioral PII (CVSS 5.3)
- Legacy Zigbee devices without AES-128 encryption (CVSS 6.5)
- Touchlink factory reset attack from up to 190m range (CVSS 8.8)
- ZCL replay attacks due to weak replay protection (CVSS 7.4)

## Zigbee 3.0 vs Legacy Security
| Feature | Zigbee HA 1.2 / ZLL | Zigbee 3.0 |
|---------|---------------------|------------|
| Key Exchange | Well-known fallback keys only | Supports install codes for unique per-device link keys |
| Trust Center Link Key | Global default "ZigBeeAlliance09" | Can use device-unique keys (but rarely implemented) |
| Touchlink | Core feature in ZLL | Optional but still supported for backward compat |
| Network Key Transport | Encrypted with known TCLK | Can use install-code-derived key |

**Critical weakness**: backward compatibility requirements undermine Zigbee 3.0 security improvements. Most manufacturers still use default keys.

## Verification Steps
1. Confirm Zigbee2MQTT is running and accessible (web UI or MQTT topics)
2. Extract network key from bridge configuration via MQTT or configuration file
3. Enumerate all paired devices and their capabilities
4. Test command injection on at least one actuator/sensor
5. Verify whether permit join can be forced remotely
6. Document exposed sensor data and privacy implications
7. If RF hardware available: sniff network key during device re-join

## References
- "Living in the Dark: MQTT-Based Exploitation of IoT Security Vulnerabilities in ZigBee Networks" (MDPI 2024)
- "Insecure to the Touch: Attacking ZigBee 3.0 via Touchlink" (WiSec 2017)
- "Don't Kick Over the Beehive" — attacks without key knowledge (ACM CCS 2022)
- "ZLeaks: Passive Inference Attacks on Zigbee Smart Homes" (ACNS 2022)
- "A Comprehensive Analysis of Security Challenges in ZigBee 3.0 Networks" (Sensors 2025)
- Kaspersky Securelist — Zigbee Protocol Security Assessment
- KillerBee framework (github.com/riverloopsec/killerbee)
- Z3sec framework (github.com/IoTsec/Z3sec)
