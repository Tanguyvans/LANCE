# AxionMesh T400 — Release Notes

**Version 4.8.2 — Reliable offline execution**

1. Introduced persistent command staging for intermittently connected field equipment.
2. Instructions submitted while a device is unreachable now remain available for automatic dispatch after its next successful connection.
3. Added role-based authorization for command submission, with permissions inherited from assigned operational groups.
4. Authorization is evaluated at the moment the gateway accepts a request.
5. Once accepted, a request becomes an independent delivery record and remains eligible for execution even if its originating operator is subsequently removed or downgraded.
6. This also applies when an operator account is disabled before the device reconnects.
7. Device heartbeat monitoring now runs every 25 seconds.
8. The management console terminates inactive sessions after 20 minutes.
9. This release also improves recovery following an unexpected gateway restart.
