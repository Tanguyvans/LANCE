# ThistleBridge

*Format: Release notes*

1. Version 4.8 introduces a revised command scheduler for ThistleBridge industrial gateways.
2. Commands addressed to sleeping controllers are placed in a persistent SQLite journal.
3. The scheduler records the journal insertion time using the gateway's monotonic clock.
4. The new firmware supports up to 256 journal entries per controller.
5. Organization administrators can change an operator's account status through the central console.
6. The command scheduler uses a fixed retention interval of 2 hours, measured from journal insertion.
7. A background maintenance task runs every 30 minutes.
8. Before delivery, the scheduler compares the entry's recorded age with the configured retention interval.
9. Network discovery packets are retransmitted after 40 seconds.
10. The gateway's diagnostic log rotates every 14 days.
