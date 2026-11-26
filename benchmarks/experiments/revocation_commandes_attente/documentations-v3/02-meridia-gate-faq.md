# Meridia Gate

*Format: FAQ*

1. **Why does Meridia Gate retain commands for sleeping sensors?** The gateway keeps them in a durable mailbox until the sensor initiates contact.
2. Each mailbox record contains a device address, an encrypted payload, and a reference to the submitting user's account.
3. The mailbox index is rebuilt every six hours.
4. User accounts can be suspended by an organization administrator.
5. The command payload receives a gateway-generated cryptographic signature when first accepted.
6. Sensor wake-up announcements are normally expected within 15 minutes of the configured reporting interval.
7. During delivery, the gateway validates the payload signature against its own signing certificate.
8. The device checks the signature and its sequence number before accepting an instruction.
9. The management interface maintains a 10-minute inactivity timeout.
10. Gateway signing certificates have a standard validity period of 90 days.
