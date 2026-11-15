# KestrelNode S8 — FAQ

**What happens when devices go offline?**

1. KestrelNode S8 can retain instructions for devices that temporarily disappear from the network.
2. This is particularly useful for solar-powered meters and devices using scheduled radio transmissions.
3. The gateway resumes delivery automatically when a device checks in.
4. Who can send instructions? Only operators assigned to the relevant device group and granted control privileges.
5. Does removing an operator's access affect pending work? Yes.
6. Any instructions that the operator submitted but that have not yet reached their destination are erased when their control privileges are withdrawn.
7. Instructions already received by the device remain in effect.
8. The gateway sends a connectivity probe every 40 seconds.
9. Operator authentication sessions close after 12 minutes of inactivity.
