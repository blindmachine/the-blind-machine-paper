# `gwas_chi_square` — encrypted case/control GWAS (allelic chi-square)

A curated Blind Machine application that runs a **genome-wide association study**
over encrypted genotypes: the one-degree-of-freedom **allelic chi-square test**
for difference in minor-allele frequency between cases and controls, per SNP —
with odds ratios and p-values.

It reproduces the **Chi-Square GWAS protocol** of

> Marcelo Blatt, Alexander Gusev, Yuriy Polyakov, Shafi Goldwasser.
> *Secure large-scale genome-wide association studies using homomorphic
> encryption.* PNAS 117(21):11608–11613, 2020.
> [doi:10.1073/pnas.1918257117](https://doi.org/10.1073/pnas.1918257117) ·
> reference prototype
> [`palisade-gwas-demos`](https://gitlab.com/duality-technologies-public/palisade-gwas-demos)
> (`demo-chi2.cpp`)

on the same public demo dataset they ship, and gives **bit-identical** results.
See [`BENCHMARK.md`](BENCHMARK.md) for the head-to-head comparison and timings.

## The idea: push the multiply to the data owner, keep the server additive

Their prototype encrypts everyone's genotypes and phenotypes to one key and forms
the case/control cross term `g·y` with a **ciphertext × ciphertext** multiply on
the server. In The Blind Machine's model **each data owner holds their own
genotype `g` and phenotype `y`**, so that product is computed **locally, in the
clear**, before anything is encrypted. What reaches the blind server is then only:

| per SNP j (chunked at 8192 slots) | meaning |
|---|---|
| `Σᵢ gᵢⱼ`         | minor-allele count (contingency-table column total `c1`) |
| `Σᵢ gᵢⱼ · yᵢ`    | minor-allele count in cases (`n11`) |
| `meta = [Σᵢ yᵢ, N]` | number of cases, contributor count |

and the server does **one thing: add**. This is the weakest homomorphic operation
there is — the additive-only BFV circuit of the flagship `allele_frequency_count`
(ring 2¹³, multiplicative depth 0, no relinearization or Galois keys). Everything
non-linear — the chi-square ratio, the odds ratio, the p-value — is computed on the
project owner's machine, after decryption, from **exact integer** sufficient
statistics.

The result: the association test that costs a deep CKKS circuit in the single-key
setting becomes a coordinate-wise sum in the multiparty setting, because the
parties who own the plaintext do the multiplication for free.

## Roles and flow (RFC 0002 `aggregate` scenario)

- **Data owner** (`local_data_owner.py`) — `encode` a `{"genotype": [...],
  "phenotype": 0|1}` record; `encrypt` it into ONE packed BMCT1 blob carrying the
  chunked `g` and `g·y` series plus the tiny `meta` ciphertext. Public context
  only; the secret key is never here.
- **Server** (`server.py`) — `compute`: stream-fold every contributor's blob into
  one aggregate by additive homomorphic sum. Runs in the network-isolated sandbox
  with the public context and ciphertexts only.
- **Project owner** (`local_project_owner.py`) — `keygen` (additive BFV context);
  `decrypt` the aggregate (the only use of the secret key, on their own machine);
  `decode` into per-SNP chi-square, p-value and odds ratio.

## Input / output

Input per contributor: `{"genotype": [dosages in {0,1,2}], "phenotype": 0|1}`
(missing genotype calls → 0; `phenotype` 0 = control, 1 = case). The published
coordinate length `L` (number of SNPs) is fixed by the manifest — set to **16,384**
to match the Duality demo. Longer SNP sets are analysed in blocks (the paper
likewise "batches 4,096 SNPs at a time").

Output (released to the project owner):

```json
{
  "protocol": "gwas_chi_square",
  "n_contributors": 200, "cases": 101, "controls": 99,
  "minor_allele_count":          [ ... per-SNP Σg ... ],
  "minor_allele_count_in_cases": [ ... per-SNP Σg·y ... ],
  "chi_square":  [ ... ], "p_value": [ ... ],
  "neg_log10_p": [ ... ], "odds_ratio": [ ... ]
}
```

## Security levels

`keygen(security=128|192|256)` selects the coeff-modulus chain (the only knob);
`N` and the plaintext modulus are fixed. The chains are byte-identical to the four
additive protocols. Exactness holds for cohorts up to N ≈ 500,000 (`t = 1032193 >
2N`). See [`SECURITY.md`](SECURITY.md).

## Test / run

```bash
cd applications/gwas_chi_square
uv --project signed/env sync --group dev                       # build the sealed env
uv --project signed/env run --group dev python -m pytest tests/  # bit-exact equivalence loop
```
