# Redcliff Node

*Format: Protocol specification*

1. Redcliff Node implements deferred delivery through a cryptographically chained command ledger.
2. Every ledger entry contains a device-specific nonce and a command digest.
3. The gateway stores the originating operator identifier in its audit metadata.
4. An organization administrator may disable an operator account through the control plane.
5. The ledger maintains a fixed command lifetime of 1 week, measured from the entry's committed timestamp.
6. When a device wakes, the gateway verifies the preceding ledger hash before reading the next entry.
7. The command lifetime is evaluated using the committed timestamp and the gateway's synchronized clock.
8. Ledger integrity checks execute every 4 hours.
9. Device challenge nonces have a 6-minute validity period.
10. The gateway rotates its diagnostic signing key every 30 days.
