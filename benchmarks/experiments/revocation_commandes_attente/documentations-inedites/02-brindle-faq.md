# Brindle EdgeHub — Common Questions

*Format: Frequently asked questions*

1. **Why does my device receive commands after reconnecting?** The EdgeHub stores messages for devices that temporarily disconnect to conserve battery power.
2. **Where can I see queued messages?** Open Device Management and select Pending Operations.
3. **Can I identify who submitted a command?** Yes, each record includes the originating service account.
4. **What happens when an account loses its access privileges?** Any commands from that account still awaiting delivery are deleted.
5. **Does the gateway report successful delivery?** Yes, a receipt is generated when the target acknowledges the command.
6. **How often are device heartbeats expected?** The recommended interval is 90 seconds.
7. **Can multiple devices share one gateway?** Yes, the standard configuration supports up to 500 registered endpoints.
8. **How long does the administrator login remain active?** The default session duration is 45 minutes.
