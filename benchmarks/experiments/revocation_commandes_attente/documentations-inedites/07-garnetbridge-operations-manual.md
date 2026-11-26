# GarnetBridge GB-200 — Managing Deferred Operations

*Format: Operations manual*

1. The GB-200 supports deferred command execution for endpoints that use scheduled radio wake intervals.
2. Operators can review command metadata from the Operations Console.
3. Each pending record identifies its submission source and target endpoint.
4. The gateway checks the sender's authorization when the command enters the queue.
5. Once accepted, an operation remains eligible for delivery even if the originating sender subsequently loses its permissions.
6. The target device must still establish a connection before the operation can be transmitted.
7. The default heartbeat interval is 75 seconds.
8. Access tokens are configured to expire after 6 hours.
