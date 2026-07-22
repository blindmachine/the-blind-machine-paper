# Security Policy

## Supported releases

Only the latest published `blindmachine` release receives security fixes. The CLI
handles private data and cryptographic keys, so users should not remain on an older
release after a security update is published.

## Reporting a vulnerability

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/blindmachine/blind/security/advisories/new).
Do not open a public issue for an unpatched vulnerability and do not include real
credentials, private keys, genomic data, or other sensitive records in a report.

Useful reports include the affected version, operating system, container runtime,
reproduction steps using synthetic data, impact, and any proposed mitigation. We
will acknowledge a report through the private advisory and coordinate disclosure
after a fix is available.

## Security boundaries

- Application bundles must pass digest and pinned Ed25519 verification before use.
- Dependency installation occurs in a data-free container build phase.
- Every data-bearing application stage runs in a digest-pinned container with no
  network, a read-only root, a non-root UID, dropped capabilities,
  `no-new-privileges`, bounded memory/CPU/PIDs/files, a read-only output directory,
  and only the predeclared, size-bounded output files mounted writable.
- Private keys use the operating-system keychain by default. Plaintext file storage
  requires the explicit `BLIND_SECRET_BACKEND=file` escape hatch and is reported as
  insecure by `blind doctor`.
- API keys and passwords are accepted only by a hidden prompt or standard input;
  arbitrary credential-file and state-root paths are not part of the CLI surface.
- A stored FHE secret context is delivered to the decrypt container through an
  anonymous stdin pipe (`/dev/stdin`), never reconstructed as a host file.
- Every pull request runs the multi-version tests, static and dependency audits,
  full-history secret scan, distribution inspection, CodeQL, and a live kernel
  sandbox probe before it can merge.
- The protected `main` branch accepts only verified signatures and approved
  noreply or `@blindmachine.org` author addresses. CI independently scans every
  reachable commit's author and committer metadata, so a privacy regression also
  blocks builds and releases.
- PyPI releases originate only from protected `main`. A single designated
  maintainer can create a `v*` tag, only at the clean remote `main` commit after
  its identity and GitHub signature are verified; tag updates and deletions have
  no bypass. The protected release workflow re-verifies that exact revision and
  publishes through GitHub OIDC Trusted Publishing with attestations. No
  long-lived PyPI token is used.

These controls reduce risk but do not make arbitrary third-party application code
trustworthy. Install only applications signed by a publisher you intend to trust.

## Maintainer merge procedure

GitHub can use the account's selected web author email for pull-request-generated
commits. Before opening any human-authored pull request, maintainers must enable
both **Keep my email addresses private** and **Block command line pushes that
expose my email** in GitHub email settings. This prevents synthetic merge objects
from exposing a personal address. Maintainers merge only clean pull requests with:

```sh
uv run --locked python scripts/secure_merge.py <pull-request-number> --yes
```

The command derives the authenticated maintainer's GitHub ID-based noreply address,
pins the expected pull-request head, requests a squash merge through GitHub's
GraphQL API, and then fails unless the resulting commit has that noreply author,
GitHub's noreply committer, and a valid GitHub signature.

## Maintainer release procedure

After updating the package version through the normal protected pull-request flow,
create the one-time version tag from a clean checkout of remote `main`:

```sh
uv run --locked python -m scripts.create_release_tag --yes
gh workflow run release.yml --repo blindmachine/blind --ref main
```

The first command refuses a feature branch, dirty checkout, local/remote mismatch,
unapproved commit email, invalid GitHub signature, or conflicting existing tag.
The release workflow is read-only for repository contents, runs every verification
gate again, checks that the immutable package-version tag points to its exact
`main` revision, and then obtains a short-lived PyPI OIDC credential.
