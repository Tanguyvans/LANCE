# Vulhub success checkers

Vulhub runs are publishable as scored results only when the case has a
pre-committed deterministic checker in this directory. Starting a container,
receiving an HTTP response, or producing a plausible finding is not sufficient.

Each checker must:

- be specific to one pinned Vulhub case and CVE;
- derive its verdict from target-side effects or a case-specific success signal;
- accept the run directory and target endpoint as inputs;
- emit JSON containing `success`, `reason`, and `evidence_refs`;
- return a non-zero exit status when it cannot evaluate the run.

Unevaluable cases are failures, not missing observations. The checker set is
frozen in `benchmarks/external/manifest.yaml` before an official campaign.
