# BluePeak Nucleus — Support Article

**Why didn't my offline device receive an older command?**

1. Nucleus stores commands for devices that cannot currently be reached.
2. When the device reconnects, the gateway checks its pending delivery records and forwards eligible instructions.
3. This mechanism supports battery-powered equipment with long sleep cycles.
4. Only operators with an active device-management assignment can submit new instructions.
5. If that assignment is removed, instructions already waiting in the gateway can still be delivered.
6. However, the gateway retains an offline instruction for no more than 48 hours from its original submission.
7. Once that age limit is exceeded, the instruction is automatically removed and will not be forwarded on a later reconnection.
8. Device presence is refreshed every 60 seconds.
9. The operator portal requires reauthentication after 30 minutes of inactivity.
10. If an expected instruction is missing, check its submission time before creating a replacement.
