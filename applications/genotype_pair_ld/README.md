# `genotype_pair_ld` - Blind Machine draft protocol

This draft application computes adjacent-pair genotype LD moments over a fixed
ordered variant coordinate list. It is the public-real-data experiment's
justification for a new multiplication-supporting application: the server derives
`g_a * g_b` under encryption for each adjacent variant pair.

The first experiment uses adjacent pairs only, so for a genotype vector
`g[0..L-1]` the pair list is:

```text
(0,1), (1,2), ..., (L-2,L-1)
```

Released aggregate moments per pair:

- `sum_a`
- `sum_b`
- `sum_a2`
- `sum_b2`
- `sum_ab`
- post-decrypt covariance and `r2`

This bundle is a draft paper experiment application, not yet a hosted curated
application with a production signature.
