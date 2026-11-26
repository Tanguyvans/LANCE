# SilverMap Gateway

*Format: FAQ*

1. **How does SilverMap Gateway handle commands for sleeping meters?** It stores each instruction in a device-specific circular buffer.
2. The buffer records the insertion time and a 3-day expiration interval for each instruction.
3. The insertion time comes from the gateway's trusted real-time clock.
4. Account administrators can suspend individual user accounts from the central dashboard.
5. The device reports its wake-up status through a short-range beacon.
6. The buffer reader calculates the age of an instruction before placing it in a transmission batch.
7. The transmission batch is assembled only for entries whose age is within the stored expiration interval.
8. Beacon scanning runs every 55 seconds.
9. The gateway renews its local time synchronization lease every 6 hours.
10. Diagnostic snapshots are retained for 10 days.
