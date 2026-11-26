# Oakline OG-500 — Retention and Queue Administration

*Format: Administrator reference*

1. The OG-500 maintains a persistent queue for commands addressed to intermittently connected equipment.
2. Each entry stores its original creation timestamp and destination identifier.
3. The queue maintenance service evaluates pending records during scheduled housekeeping cycles.
4. An undelivered command is removed once its age reaches 36 hours, irrespective of whether its originating sender still has authorization.
5. This retention setting is applied uniformly across registered endpoint groups.
6. Administrators can inspect removal events in the maintenance audit report.
7. The default health-check interval is 150 seconds.
8. The administrator console refreshes its session authentication every 10 minutes.
