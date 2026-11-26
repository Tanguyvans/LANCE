# Cindervale LinkStation — Version 3.8

*Format: Release notes*

1. Version 3.8 introduces improved scheduling for commands addressed to intermittently connected sensors.
2. The queue processor now groups pending operations by destination identifier.
3. Administrators can export queue activity as a CSV file.
4. A new diagnostic field records the time of the most recent device wake event.
5. The authorization subsystem now removes outstanding, undelivered commands when their originating sender's permissions are revoked.
6. This change also applies to commands submitted through the management API.
7. The default telemetry reporting interval remains 60 seconds.
8. API access tokens continue to have a configurable lifetime of 12 hours.
