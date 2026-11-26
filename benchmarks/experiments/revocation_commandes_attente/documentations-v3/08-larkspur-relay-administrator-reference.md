# Larkspur Relay

*Format: Administrator reference*

1. Larkspur Relay implements deferred commands through a tenant-scoped append-only event stream.
2. Each command event contains a tenant identifier, a device identifier, and a serialized instruction.
3. Administrators can change the status of individual console accounts from the tenant settings page.
4. The gateway assigns each event a partition offset when it enters the stream.
5. A sleeping device subscribes to its assigned partition when it reconnects.
6. Delivery uses the partition offset and device subscription cursor to identify the next event.
7. The gateway validates the tenant identifier against the device's enrollment record.
8. Partition leadership is renewed every 40 seconds.
9. Device enrollment certificates are normally valid for 180 days.
10. The stream replication process checks its peer connections every 75 seconds.
