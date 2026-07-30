# Frozen external transfer campaign

`manifest.yaml` pins the upstream commits and exact case populations used by
the paper. As of the freeze preparation date, this is 33 AutoPenBench tasks and
330 Vulhub Compose cases. These results are separate from IoT Verified F1.

Validate the files without network access:

```bash
python3 benchmarks/tools/validate_external_manifest.py
```

Prepare the four disposable workers:

```bash
python3 -m src.baselines fleet-prepare \
  --host root@<worker-1200> --host root@<worker-1201> \
  --host root@<worker-1202> --host root@<worker-1203>
```

Start the pinned AutoPenBench population in blind mode:

```bash
python3 -m src.baselines fleet-start \
  --host root@<worker-1200> --host root@<worker-1201> \
  --host root@<worker-1202> --host root@<worker-1203> \
  --suite autopenbench \
  --repo /opt/external-benchmarks/auto-pen-bench \
  --cases-file benchmarks/external/autopenbench-33.txt \
  --context-mode blind
```

Use the same command with `--suite vulhub`, the pinned Vulhub checkout and
`vulhub-330.txt`. AutoPenBench is scored by the controller-only expected flags.
All Vulhub cases may be executed, but only cases with a deterministic checker
under `checkers/` enter the scored population; the others remain explicitly
`executed_not_scored`.

The external lifecycle starts Docker and passes only the target/network task to
`src.agent_external`, which runs the normal six-phase LANCE pipeline. Expected
flags are hashed in pre-run artifacts and are never placed in the agent command
or readable output directory before execution.
