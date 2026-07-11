# Security Notes

`genotype_pair_ld` uses multiplication-supporting BFV because the server computes
an encrypted genotype-by-genotype product. It releases aggregate LD moments only.

Boundaries:

- The server receives public context and ciphertexts only.
- The secret key remains local to the project owner.
- Adjacent-pair LD matrices can still leak through outputs if released over small
  or overlapping cohorts. Use cohort freeze, min-N, run caps, and pair-count caps.
- The current bundle is draft experiment code and is not yet signed as a
  production curated application.
