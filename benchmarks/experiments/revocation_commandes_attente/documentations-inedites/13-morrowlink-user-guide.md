# MorrowLink ML-300 — Queue Maintenance

*Format: User guide*

1. The ML-300 gateway stores commands for endpoints that are temporarily unavailable.
2. Stored entries are processed when their destination becomes reachable.
3. Queue records include a creation timestamp for troubleshooting purposes.
4. The system automatically removes pending commands once they have been stored for two hours.
5. This cleanup behavior applies independently of the originating sender's current permission status.
6. Administrators can enable queue-depth alerts from the notification settings.
7. The standard device heartbeat interval is 40 seconds.
8. Administrator login sessions last 30 minutes by default.
