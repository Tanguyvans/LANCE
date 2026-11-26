# Birchstone Link

*Format: Quick-start guide*

1. Birchstone Link uses a command capsule to carry instructions across periods when a device is asleep.
2. The capsule is sealed using the gateway's hardware security module at the moment of submission.
3. The gateway stores the operator's account identifier in the separate submission history.
4. Administrators can deactivate accounts through the organization dashboard.
5. The device authenticates the capsule using the gateway's public key when it wakes.
6. A capsule contains a device identifier and an integrity-protected instruction body.
7. The gateway checks the device identifier against its local enrollment table before radio transmission.
8. The enrollment table is refreshed every 16 hours.
9. Hardware security module self-tests run every 8 hours.
10. The quick-start provisioning code expires after 30 minutes.
