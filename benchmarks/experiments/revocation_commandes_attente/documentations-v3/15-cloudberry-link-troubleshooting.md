# Cloudberry Link

*Format: Troubleshooting article*

1. Cloudberry Link uses a staged instruction pipeline for devices that spend most of their time asleep.
2. Each staged instruction is assigned a server-generated delivery ticket.
3. The ticket contains a destination identifier, an encrypted payload, and a gateway-issued ticket number.
4. The operator's identity is written to a separate compliance log during submission.
5. Administrators can disable an operator's login from the organization control panel.
6. When a device wakes, the gateway retrieves the next staged ticket associated with its destination identifier.
7. The gateway validates the ticket number against its local ticket ledger before constructing the radio frame.
8. The gateway refreshes its ticket-ledger index every 22 minutes.
9. Device discovery windows last approximately 14 seconds.
10. The compliance log is exported to the central server every 8 hours.
