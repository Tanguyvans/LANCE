# JuniperNode JN-8 — Command Submission API

*Format: API reference*

1. Submit a deferred operation using the `POST /api/commands` resource.
2. Include the endpoint UUID and operation payload in the request body.
3. A successful submission returns a unique queue reference.
4. The gateway performs the sender authorization check during initial command acceptance.
5. Later changes to the sender's access rights do not prevent delivery of commands that were previously accepted.
6. Use `GET /api/queue/{reference}` to inspect the operation status.
7. The API gateway enforces a default request timeout of 30 seconds.
8. Authentication tokens are valid for 4 hours unless otherwise configured.
