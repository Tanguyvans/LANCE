# Orbinet Pulse — API Reference Notes

**Deferred execution model**

1. Pulse exposes a command submission interface for registered endpoint identifiers.
2. Requests targeting unreachable endpoints are retained in the gateway's delivery buffer.
3. The buffer is drained when the endpoint establishes a valid connection.
4. A successful submission requires the caller to hold the `device.write` capability.
5. The authorization service associates each buffered request with its originating operator.
6. Revoking that operator's write access invalidates their outstanding buffered requests.
7. The gateway removes those requests before processing the next delivery cycle.
8. Endpoint presence is refreshed at 20-second intervals.
9. API access tokens remain valid for 45 minutes unless explicitly revoked.
