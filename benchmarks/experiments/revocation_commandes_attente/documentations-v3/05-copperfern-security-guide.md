# CopperFern

*Format: Security guide*

1. CopperFern gateways use a policy-controlled command broker to coordinate sleeping endpoints.
2. The broker associates each queued instruction with the policy identifier that governed its submission.
3. Policy evaluation results are cached for 90 seconds.
4. An organization can disable an individual operator through the administrative identity console.
5. When a device wakes, the broker evaluates the associated policy identifier against the current policy registry.
6. The outbound frame is constructed only after the broker receives a positive policy evaluation.
7. Commands can be assigned a priority from zero to seven.
8. A broker health check runs every five minutes.
9. Device challenge-response exchanges have a 12-second response window.
10. Security event records are retained for 180 days.
