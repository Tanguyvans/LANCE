# Teralink Drift — Integration Guide

**Connecting intermittent LoRaWAN devices**

1. Drift provides a deferred instruction channel for LoRaWAN endpoints that spend extended periods in sleep mode.
2. Integrators submit instructions through the gateway's northbound interface.
3. If the endpoint is unavailable, Drift holds the instruction until its next uplink establishes a delivery opportunity.
4. Command submission requires an operator account with control rights over the endpoint's assigned application.
5. These rights are validated when the northbound request enters the gateway.
6. After acceptance, the instruction is handled by the transport scheduler rather than the operator's account.
7. Consequently, an account suspension between submission and the next uplink does not prevent that instruction from being transmitted.
8. The gateway expects an endpoint heartbeat at least once every 10 minutes.
9. Integration credentials expire after 60 days and must be renewed before their next use.
