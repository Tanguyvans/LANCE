# EmberGrid SG-12 — Authorization and Queue Protection

*Format: Security guide*

1. The SG-12 gateway associates every submitted command with its authenticated originating principal.
2. Access decisions are recorded in the security audit log.
3. Administrators should review account assignments at regular intervals.
4. Device communication uses mutually authenticated TLS connections.
5. When a principal's authorization is withdrawn, its outstanding commands that have not reached their destinations are purged.
6. The gateway records the principal identifier and revocation timestamp in its audit history.
7. The default administrative session timeout is 15 minutes.
8. Certificate renewal reminders are issued 30 days before expiration.
