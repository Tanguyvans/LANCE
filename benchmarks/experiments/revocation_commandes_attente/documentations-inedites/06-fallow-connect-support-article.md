# Fallow Connect — Troubleshooting Delayed Commands

*Format: Support article*

1. Some battery-powered devices remain offline for several hours between scheduled wake cycles.
2. The Fallow Connect gateway retains their commands in a pending queue.
3. Check the device's last-seen timestamp before investigating delivery failures.
4. Confirm that the destination identifier matches the registered device record.
5. If the original sender's access is revoked, any of its commands still waiting for delivery are automatically dropped.
6. The queue monitor displays the number of pending operations for each endpoint.
7. Diagnostic polling runs every 120 seconds by default.
8. Support console sessions expire after 30 minutes without activity.
