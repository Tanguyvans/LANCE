# Dovetail Gateway API — Pending Commands

*Format: API reference*

1. The `POST /v2/commands` endpoint submits an operation to a registered endpoint.
2. The gateway returns a command identifier when the request is accepted.
3. Clients can retrieve the current queue state using `GET /v2/commands/{id}`.
4. A sleeping endpoint receives its pending operation when it next polls the gateway.
5. Revoking a principal's command permissions causes all of that principal's queued but undelivered operations to be discarded.
6. The API returns HTTP 202 for successfully accepted asynchronous requests.
7. Rate-limit counters reset every 60 seconds.
8. Bearer credentials have a default validity period of 8 hours.
