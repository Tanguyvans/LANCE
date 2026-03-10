---
name: web_service_analysis
description: HTTP service and admin panel security analysis for IoT devices
version: 1.0.0
tags: [http, web, admin, headers, api, firmware-update]
tools: [curl_headers, nmap_scan]
device_types: [router, gateway, compute, camera, ap]
cpe_patterns: []
---

# Skill: Web Service & HTTP Analysis

## Overview
IoT devices frequently expose HTTP-based management interfaces (admin panels, REST APIs, firmware update endpoints). These are often the easiest attack vector due to default credentials and missing security headers.

## Methodology

### 1. HTTP Header Analysis
- Fetch headers: `curl -sI http://<target>`
- Check for missing security headers:
  - `X-Frame-Options` — clickjacking protection
  - `Content-Security-Policy` — XSS mitigation
  - `Strict-Transport-Security` — HTTPS enforcement
  - `X-Content-Type-Options` — MIME sniffing prevention
  - `X-XSS-Protection` — legacy XSS filter
- Check `Server` header for version disclosure

### 2. Admin Panel Discovery
- Common paths: `/`, `/admin`, `/login`, `/cgi-bin/`, `/webfig`
- Default ports: 80, 443, 8080, 8443, 8888
- Check for basic auth vs form-based login
- IoT admin panels rarely have CSRF protection

### 3. Default Credentials
- Test common pairs: admin/admin, root/root, admin/password
- Device-specific defaults (check vendor documentation)
- Many IoT devices ship with no password on admin interface

### 4. API Endpoint Discovery
- Check for REST API: `/api/`, `/v1/`, `/graphql`
- Test authentication requirements on API endpoints
- Look for unauthenticated data endpoints
- Check if API returns sensitive device configuration

### 5. Firmware Update Endpoints
- Look for `/firmware`, `/update`, `/upgrade`
- Check if firmware upload requires authentication
- Verify if firmware signature validation is enforced
- Unsigned firmware update = potential RCE vector

## Tools & Commands
- `curl_headers http://<target>` — Header analysis
- `nmap -sV -p 80,443,8080,8443 <target>` — Web service detection
- `curl -s http://<target>/api/ | head` — API probing

## Common Findings
- Missing security headers on all endpoints
- Default credentials on admin panels
- HTTP without TLS (plaintext management)
- Server version disclosure
- Unauthenticated API endpoints
- No CSRF protection on management actions

## Verification Steps
1. Fetch and document HTTP headers for all web services
2. Test default credentials on discovered admin panels
3. Check if HTTPS is available or enforced
4. Probe for API endpoints and test auth requirements
