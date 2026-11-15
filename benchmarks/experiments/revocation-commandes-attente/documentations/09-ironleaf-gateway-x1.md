# Ironleaf Gateway X1 — Administrator Handbook

**Managing operators and deferred workloads**

1. Ironleaf X1 provides a persistent dispatch queue for field devices that are temporarily unreachable.
2. Sleeping endpoints receive their outstanding instructions after establishing their next authenticated connection.
3. Dispatch records are associated with the operator who originally requested each operation.
4. Administrators grant command privileges through device-group membership.
5. The gateway checks these privileges whenever an operator submits a new operation.
6. An accepted operation remains deliverable following subsequent changes to the operator's group membership.
7. Pending operations have a maximum residence time of 72 hours; records older than this threshold are purged automatically.
8. The residence clock starts when the gateway first accepts the operation and does not restart after a reconnection attempt.
9. Endpoint polling occurs every 45 seconds.
10. Administrative console sessions expire after 25 minutes of inactivity.
