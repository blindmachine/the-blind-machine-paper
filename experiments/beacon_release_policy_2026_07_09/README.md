# Beacon Release-Policy Experiment

This optional experiment uses public IGSR/1000 Genomes genotypes to demonstrate
why encrypted aggregate computation still needs output governance. It compares
exact adjacent-cohort differencing against simple release policies such as
minimum-N floors, cohort freeze, query budgets, and rounded counts.

Run it from the repository root:

```bash
bash docs/paper/experiments/e7_beacon_release_policy.sh
```

Per-sample traces are written only to ignored `work/`. Committed outputs are
aggregate policy metrics.

The public paper evidence page is:

```text
https://blindmachine.org/verify/paper/public-genomics-e7-beacon-policy
```
