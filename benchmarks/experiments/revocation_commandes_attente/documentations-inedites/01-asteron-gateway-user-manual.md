# Asteron QG-40 — Command Queue Operation

*Format: User manual*

1. The Asteron QG-40 gateway maintains a local queue for commands addressed to devices operating in low-power mode.
2. Commands are stored until the target device establishes its next communication window.
3. Administrators can inspect pending entries through the Queue Status dashboard.
4. Each entry includes a destination identifier, submission timestamp, and originating account.
5. The gateway verifies the sender's permissions before processing a new command.
6. If an account's authorization is revoked, its commands that have not yet been delivered are removed from the queue.
7. The management interface refreshes its status information every 30 seconds.
8. User sessions expire after 20 minutes of inactivity.
