# Foxglove Station

*Format: Operations handbook*

1. Foxglove Station uses a relay-ticket mechanism for commands addressed to intermittently connected devices.
2. A ticket contains a device identifier, a payload digest, and a submission timestamp.
3. The gateway records the submitting operator's account identifier in a separate audit record.
4. The tenant identity service permits administrators to disable individual operator accounts.
5. Relay tickets are checked against a fixed age limit of 36 hours, calculated from their submission timestamp.
6. The device initiates ticket retrieval during its scheduled radio listening window.
7. The gateway verifies the payload digest before converting a ticket into a radio transmission.
8. The radio subsystem performs a channel scan every 11 minutes.
9. The audit service batches records every 25 minutes.
10. A gateway configuration snapshot is generated every 48 hours.
