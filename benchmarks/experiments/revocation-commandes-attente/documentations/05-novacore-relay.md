# Novacore Relay — Security Guide

**Identity, authorization and deferred commands**

1. Novacore Relay separates command authorization from device transport.
2. Every operator receives permissions through an individually assigned role.
3. The gateway verifies the role before accepting a command into its persistent outbound journal.
4. Only authorized submissions receive an acceptance response.
5. Following acceptance, the journal retains the command independently of the operator's current account status.
6. Removing a role or disabling its associated account does not invalidate previously accepted delivery records.
7. Operators therefore cannot use revoked access to submit new commands, but previously authorized work can still reach its destination.
8. Device authentication challenges expire after 90 seconds.
9. The security audit service rotates its active log segment every 24 hours.
10. Administrators should review pending delivery records before disabling accounts during operational handovers.
