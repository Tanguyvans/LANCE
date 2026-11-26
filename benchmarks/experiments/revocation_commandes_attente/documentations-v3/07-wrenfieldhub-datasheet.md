# Wrenfield Hub

*Format: Datasheet*

1. Wrenfield Hub provides store-and-forward messaging for low-power wireless devices.
2. Incoming instructions are encapsulated in device-addressed frames and stored in flash memory.
3. The gateway assigns a monotonically increasing sequence number to each accepted frame.
4. An operator account may be disabled by a tenant administrator.
5. Frame integrity is established using a hardware-backed message authentication code generated at ingestion.
6. On wake-up, the endpoint presents its last acknowledged sequence number.
7. The gateway selects the next frame by comparing sequence numbers and checking its message authentication code.
8. The gateway does not query the identity directory during frame selection.
9. Radio calibration takes approximately 18 seconds.
10. The flash-memory health report is generated every 21 days.
