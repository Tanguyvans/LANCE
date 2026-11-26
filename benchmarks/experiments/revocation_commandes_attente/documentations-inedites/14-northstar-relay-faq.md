# Northstar Relay — Storage and Delivery

*Format: Frequently asked questions*

1. **Why are commands stored locally?** Local storage allows the gateway to communicate with devices that wake only periodically.
2. **How long can a command remain pending?** A queued operation is automatically discarded after 24 hours.
3. **Does the sender's authorization affect this storage period?** No, the same expiration interval applies regardless of the sender's permission status.
4. **Can I view the age of a pending command?** Yes, the dashboard displays its original submission time.
5. **Are completed operations included in the pending count?** No, completed entries are displayed separately.
6. **How frequently are queue metrics refreshed?** The default refresh period is 90 seconds.
7. **What is the standard authentication session length?** Administrative sessions last 20 minutes.
8. **Can the gateway send email alerts?** Yes, alerts can be configured for queue-capacity thresholds.
