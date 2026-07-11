# Public 1000 Genomes LD Window

- Source: IGSR/1000 Genomes Phase 3 `20130502`
- Region: `22:16050000-16900000`
- Samples: 25 public samples
- Variants: 12 complete-call biallelic SNPs
- Adjacent pairs: 11
- Application: draft `genotype_pair_ld`
- blindmachine.org verification: `not_published`

## Strongest Adjacent-Pair LD Signals

| Pair | Coordinate A | Coordinate B | covariance | r2 |
|---:|---|---|---:|---:|
| 4 | `22:16052986:C:A` | `22:16053444:A:T` | 0.1056 | 1.0000 |
| 10 | `22:16054454:C:T` | `22:16054740:A:G` | -0.1824 | 0.2702 |
| 6 | `22:16053659:A:C` | `22:16053791:C:A` | 0.1360 | 0.1896 |
| 11 | `22:16054740:A:G` | `22:16055070:G:A` | 0.1120 | 0.1467 |
| 1 | `22:16051249:T:C` | `22:16052080:G:A` | -0.0720 | 0.1406 |
| 8 | `22:16053862:C:T` | `22:16053863:G:A` | -0.0720 | 0.1406 |
| 9 | `22:16053863:G:A` | `22:16054454:C:T` | -0.0720 | 0.1406 |
| 2 | `22:16052080:G:A` | `22:16052962:C:T` | -0.0560 | 0.0972 |

## Validation

- `genotype_pair_ld` encrypted product moments matched the cleartext oracle exactly.
- LD-style covariance and r2 were derived post-decrypt from aggregate moments.
- Individual-level genotype vectors were written only under ignored `work/`.

## Interpretation Boundary

This is a small public-data workflow demonstration of an encrypted-product application. It is not a population-scale LD reference panel.
