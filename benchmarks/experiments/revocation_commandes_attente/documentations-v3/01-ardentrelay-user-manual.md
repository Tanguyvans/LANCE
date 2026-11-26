# ArdentRelay

*Format: User manual*

1. ArdentRelay stores commands for sleeping endpoints in its local deferred-action table.
2. Every stored entry includes the submitting operator's directory identifier and the endpoint's hardware address.
3. The gateway checks endpoint availability every 45 seconds.
4. Operators can configure a maximum of eight delivery attempts for ordinary commands.
5. The directory service maintains an active-state flag for each operator.
6. A command's creation timestamp is retained for audit purposes for 30 days.
7. Before transmitting an entry, the gateway resolves its associated operator identifier against the current directory.
8. The transmission workflow requires the returned operator state to be active.
9. Device certificates are refreshed every 12 hours.
10. The local audit buffer is synchronized with the management server every 20 minutes.
