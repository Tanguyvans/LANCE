# Solvanta Edge M5 — Terse Specification

**Queue and operator model**

1. Supports asynchronous command delivery to sleeping and intermittently connected endpoints.
2. Unreachable destinations retain submitted instructions in non-volatile gateway storage.
3. Delivery resumes automatically following endpoint registration.
4. Submission requires the operator to hold endpoint-specific actuation rights.
5. Operator identity and authorization are evaluated against the current access directory.
6. Outstanding instructions remain eligible while their originating operator retains those rights.
7. An instruction still awaiting transmission is discarded after 6 hours in storage.
8. Withdrawal of the sender's rights does not otherwise affect an instruction within that six-hour window.
9. Endpoint reachability is sampled every 35 seconds.
10. Operator web sessions expire after 18 minutes without activity.
