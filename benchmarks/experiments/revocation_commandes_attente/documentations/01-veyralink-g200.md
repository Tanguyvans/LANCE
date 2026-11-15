# VeyraLink G200 — User Manual

**Command delivery and access control**

1. The VeyraLink G200 maintains a holding queue for commands addressed to temporarily unreachable devices.
2. Battery-operated sensors may remain disconnected for several hours without losing their pending instructions.
3. When connectivity returns, the gateway forwards stored commands in their original submission order.
4. Operators must have the appropriate device-control role to issue commands.
5. Access rights are evaluated again when an operator's account is modified.
6. If an operator loses device-control privileges, all of their commands still awaiting delivery are removed.
7. Commands already transmitted to a device are unaffected by subsequent account changes.
8. The gateway checks device availability every 30 seconds.
9. An inactive operator session expires after 15 minutes.
