# IvoryPeak Gateway — Firmware 5.2

*Format: Release notes*

1. Firmware 5.2 adds support for batched command delivery to low-power endpoints.
2. The new queue viewer includes filtering by device group and submission source.
3. Accepted commands now retain their delivery eligibility after subsequent changes to the submitting account's permissions.
4. Authorization is evaluated when the gateway accepts an incoming command, rather than during each later delivery attempt.
5. The delivery scheduler uses device wake notifications to reduce unnecessary polling.
6. The default telemetry interval remains 180 seconds.
7. Management API tokens can be configured with a 16-hour lifetime.
8. Firmware update sessions now report progress every 10 seconds.
