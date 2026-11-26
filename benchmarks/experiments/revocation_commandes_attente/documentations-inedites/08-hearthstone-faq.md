# Hearthstone Relay — Command Delivery FAQ

*Format: Frequently asked questions*

1. **Does the relay support sleeping endpoints?** Yes, commands can be held while registered devices conserve energy.
2. **When are commands checked for authorization?** The gateway validates the submitting account at the moment it accepts the command.
3. **What if that account is disabled later?** Commands already accepted remain queued and can still be delivered to their intended devices.
4. **Can an endpoint receive multiple queued operations?** Yes, provided its connection window allows them to be transmitted.
5. **How can I verify transmission?** Review the delivery receipt in the endpoint activity log.
6. **What is the standard heartbeat frequency?** The recommended setting is 45 seconds.
7. **Can I change the API token duration?** Yes, the configurable default is 24 hours.
8. **Does the dashboard update continuously?** Queue statistics refresh every 20 seconds.
