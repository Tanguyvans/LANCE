# Halcyon Port

*Format: Support article*

1. Halcyon Port keeps sleeping-device instructions in a gateway-side delivery ledger.
2. Each ledger entry records the operator's employee number as its ownership field.
3. A device normally checks in once every 70 minutes.
4. The support console allows administrators to deactivate employee accounts.
5. The delivery engine retrieves the employee record associated with each ledger entry during processing.
6. Its processing rules require the employee record to carry the status `ENABLED`.
7. Entries with processing errors are written to a separate diagnostic table.
8. The diagnostic table is inspected automatically every 24 hours.
9. A gateway clock synchronization cycle runs every 10 minutes.
10. Device firmware update sessions have a maximum duration of 35 minutes.
