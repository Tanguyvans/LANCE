# Windrow Connect

*Format: Installation manual*

1. Windrow Connect maintains a local delivery spool for battery-operated agricultural sensors.
2. The spool stores each instruction as a numbered work item associated with a device MAC address.
3. The submission audit log separately records the initiating user's identifier.
4. Administrators can mark user accounts as inactive in the farm management console.
5. A sensor's wake-up notification causes the spool worker to request the next work item for that MAC address.
6. The worker validates the item's checksum and its position in the device-specific sequence.
7. The worker constructs a radio packet from the validated work item and the sensor's latest acknowledgement number.
8. Spool consistency checks run every 13 minutes.
9. Sensor registration leases last 72 hours.
10. The gateway retries unsuccessful radio acknowledgements after 32 seconds.
