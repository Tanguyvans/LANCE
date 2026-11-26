# Pelican Circuit

*Format: API reference*

1. The `POST /v2/actions` endpoint accepts commands for both active and sleeping devices.
2. The response includes an `action_id` and a `principal_ref` identifying the submitting operator.
3. A device wake-up event triggers the gateway's action-dispatch callback.
4. The API supports a maximum request-processing window of 25 seconds.
5. The identity provider publishes account-status changes to the gateway's local identity cache.
6. The dispatch callback retrieves the principal associated with the action before constructing its outbound frame.
7. The callback checks the cached principal status and requires an active identity.
8. A failed identity check produces the internal status `PRINCIPAL_CHECK_FAILED`.
9. Access tokens issued by the API expire after 50 minutes.
10. The gateway retains diagnostic traces for 72 hours.
