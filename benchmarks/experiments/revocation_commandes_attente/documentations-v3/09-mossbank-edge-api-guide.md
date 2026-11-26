# Mossbank Edge

*Format: API guide*

1. Mossbank Edge accepts deferred instructions through its MQTT command interface.
2. The broker assigns a unique message identifier and a fixed retention deadline when a command is accepted.
3. The retention deadline is calculated as the acceptance timestamp plus 1 day.
4. The broker stores a tenant-specific encryption key reference with each message.
5. Tenant administrators can deactivate individual operator accounts through the management portal.
6. On device reconnection, the broker compares the current time with the message's stored deadline.
7. Messages passing the time check undergo decryption using the tenant's configured key.
8. MQTT keep-alive intervals default to 90 seconds.
9. Management API access tokens expire after 45 minutes.
10. The gateway performs a clock-drift assessment every 20 minutes.
