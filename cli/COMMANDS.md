# `blind` — Command Reference

Stripe-CLI-style **resource + CRUD-verb** surface for The Blind Machine trust
CLI. This file is the buildable command spec: every command lists a one-line
description, its key flags, whether it is **LOCAL** (runs only on your machine),
**REMOTE** (calls the Rails HTTP API), or **BOTH**, and which artifact hashes it
**prints** or **verifies**.

Single source of truth for *what the commands mean* (not their syntax):
[`../docs/requirements.md`](../docs/requirements.md) and
[`../docs/simulation_mode.md`](../docs/simulation_mode.md). This file does not
restate them.

---

## Porcelain vs plumbing

Like Git, `blind` has two layers. **Porcelain** commands are the human-first,
guided path a person types to run the loop; **plumbing** commands are the
resource + CRUD surface (documented in the rest of this file) that the porcelain
orchestrates and that scripts, audits, and power users call directly. The
porcelain does not hide the trust story — each command prints a Rails-style
state transcript (aligned verb + object + hash + trust class), ends with the
single next action, and **never freezes a cohort silently**. Every porcelain
command supports `--json` for the desktop GUI / scripting, just like the plumbing.

Origin: [`../docs/audits/simplification/2026-07-08-project-owner-data-owner-loop.md`](../docs/audits/simplification/2026-07-08-project-owner-data-owner-loop.md).

**The five porcelain commands** (one human verb per step of the loop):

| Porcelain command | What it does | Plumbing it wraps |
|---|---|---|
| `blind projects start <application> --name "…" --min 20` | Start a study in one guided command: install + verify the signed application, create the project, generate LOCAL keys, publish ONLY the public context, and mint a contributor link. Prints the `blind contribute …` command to hand out + the `status` monitor command. The secret key never leaves the machine. | `applications install` + `projects create` + `keys create` + `projects invite` |
| `blind contribute <invite-link> <file>` | The data owner's ONE command. Resolves the project, the pinned application, and the public-context digest from the invite **link alone** (via `GET /api/v1/invitations/:token`), installs/verifies the signed application, encrypts LOCALLY, uploads **only** ciphertext, and auto-pins the packet's public-context digest (so a malicious server can't substitute its own key). No account is created; the raw file never leaves the machine. | `applications install` + `contributions create` |
| `blind projects status <project>` | Progress-first study status: state, contributors X/Y, run count, and the SINGLE next command — the next action sits **above** the commitment hashes. | `projects retrieve` (reordered) |
| `blind projects run <project>` | Run a study end to end: readiness gate → **explicit freeze confirmation** ("Freeze is permanent…") → dispatch → watch the sandbox stages → decrypt ONLY the aggregate locally. Refuses cleanly (and says why) when below min-N. | `projects freeze` + `jobs estimate`/`create`/watch + `results decrypt` |
| `blind projects proof <project>` | The reviewer's `blind verify <cert-hash>` command + the certificate's public URL — the one command a skeptic runs to verify the result offline. | `certificates list` / `certificates verify` |

Porcelain flags: `projects start` takes `--name`, `--min`/`--min-contributors`
(default 20), `--scenario`; `contribute` takes `--pin-context <digest>` (override
the invite packet's public-context digest); `projects run` takes `--yes`/`-y`
(skip the freeze/cost confirm), `--timeout`, `--interval`. All accept the global
flags (`--json`, `--quiet`, `--api`, `--api-key`, `--project`, …).

The mapping, at a glance:

| User job | Porcelain (type this) | Plumbing (still available) |
|---|---|---|
| Start a study | `blind projects start <application> --name … --min 20` | `applications install` · `projects create` · `keys create` · `projects invite` |
| Check progress | `blind projects status <project>` | `projects retrieve` · `contributions list` |
| Contribute data | `blind contribute <link> <file>` | `contributions create --link <url> --data <file>` |
| Run compute | `blind projects run <project>` | `projects freeze` · `jobs estimate/create/watch` · `results decrypt` |
| Share proof | `blind projects proof <project>` | `certificates list/retrieve/verify` |

The rest of this file is the **plumbing reference** — the full resource + CRUD
surface. The porcelain is the guided layer on top; the object model underneath is
never removed.

---

## Stripe-CLI conventions

`blind` follows the [Stripe CLI](https://stripe.com/docs/cli) shape:

- **Resource + verb.** Every API resource is a plural noun; you act on it with a
  verb: `blind <resource> <verb>`. Verbs are the CRUD set —
  **`create` · `retrieve` · `update` · `list` · `delete`** — plus
  resource-specific actions (e.g. `freeze`, `invite`, `install`, `decrypt`).
  `retrieve` fetches a single object, `list` fetches the collection. (This is a
  rename of the old `show` → **`retrieve`**.)
- **IDs are positional.** `blind projects retrieve <id>`,
  `blind results decrypt <job>`, `blind certificates retrieve <hash>`.
- **API params are `--field value` flags.** `blind projects create
  --application allele_frequency_count@<digest> --name "…" --min-contributors 20`.
- **Project scope is a global flag.** `--project <id>` sets the active project;
  resource commands that operate under a project (`keys`, `contributions`,
  `jobs create/estimate/list`) read it from there or take it explicitly.
- **`--json` on every command.** Machine-readable output is guaranteed for the
  whole surface — the future desktop GUI shells out to this CLI and parses its
  JSON (see [`../desktop/README.md`](../desktop/README.md)); the CLI stays the
  single trust surface, the GUI is a face over it.
- **Raw-API power commands.** `blind get <path>` / `blind post <path>` hit any
  `/api/v1` path directly (like `stripe get` / `stripe post`) for scripting and
  debugging.
- **Trust shortcuts.** `blind verify <target>` and `blind explain <target>` are the
  two top-level trust commands. They dispatch to the resource-specific application,
  project-event, result, or certificate commands, but keep the mental model simple:
  verify checks; explain interprets.
- **Discoverability.** `blind resources` lists the resource types; each resource
  responds to `--help`.

---

## Conventions

**Global flags** (accepted by every command):

| Flag | Meaning |
|---|---|
| `--json` | machine-readable output (guaranteed for **every** command; the GUI depends on it) |
| `--project <id>` | set the active project for project-scoped commands |
| `--api-key <key>` | API key for this invocation (overrides the stored profile token) |
| `--profile <name>` | select an `~/.blind` auth/config profile (default `default`) |
| `--color auto\|on\|off` | control ANSI color (default `auto`) |
| `--api <url>` | override platform base URL (default from `config.yml`, else `https://blindmachine.org`) |
| `--quiet` / `-q` | suppress the trust banners (hashes still print with `--json`) |
| `--yes` / `-y` | assume yes at confirmation prompts (e.g. a paid run) |
| `--version` | print CLI version and exit (same as `blind version`) |

**Environment overrides** (for CI / wrappers that can't pass a flag per call; an
explicit flag always wins):

| Env var | Effect |
|---|---|
| `BLIND_JSON=1` | default to `--json` output |
| `BLIND_QUIET=1` | default to `--quiet` output |
| `NO_COLOR=1` | disable ANSI color |
| `BLIND_HOME=<dir>` | relocate `~/.blind` state |

The base URL (`--api` / `config.yml`) is guarded: a non-loopback `http://` URL is
refused so a bearer token never travels in cleartext, and a single dim notice is
printed the first time a command runs against a non-default server.

**Trust-class legend** used in the trust banners (see README):
`Raw` and `Encoded` and `Private` = LOCAL ONLY, never uploaded ·
`Encrypted` and `Public` = the only uploadable classes.

**Hash vocabulary** (SHA-256 throughout; never MD5):
`application digest` = `name@sha256(bundle incl. manifest coordinate definition)` ·
`public-context hash` · `cohort commitment` = `sha256(sorted(contribution_hashes)+project_id+application_digest)` ·
`result digest` = `sha256(result ciphertext)` · `certificate hash`.

Auth: REMOTE calls use `Authorization: Bearer <token>` from `~/.blind/auth/`.
The **accountless bearer-link** data-owner path
(`contributions create --link`) uses the 7-day project invite token instead of
an account token — a contributor never needs a The Blind Machine account.

---

## Top-level commands

| Command | Description | LOCAL/REMOTE | Key flags | Hashes |
|---|---|---|---|---|
| `blind login` | Obtain and store an API token (device/browser code flow) | REMOTE | `--api-key <key>` (non-interactive), `--profile` | — |
| `blind logout` | Delete the stored token for the profile | LOCAL | `--profile` | — |
| `blind config` | View or edit `~/.blind/config.yml` (api URL, active profile, output prefs, account) | LOCAL | `--list`, `--set k=v`, `--json` | — |
| `blind doctor` | Verify Python, the **sandbox/container runtime** (`podman`/`docker`, `--network none` ok), the **`uv` env-sealer**, OS keychain, `cryptography` (Ed25519), `~/.blind` perms, a **sealed-env self-test** (newest installed application imports its own crypto), and API reachability | BOTH | `--json`, `--offline` (skip API ping) | — |
| `blind version` | Print CLI version (and the sandbox-runtime + `uv` sealer versions) | LOCAL | `--json` | — |
| `blind resources` | List the resource types (`applications`, `projects`, `keys`, …) | LOCAL | `--json` | — |
| `blind credits` | Show the account's credit balance (one credit = one US dollar) and the `/billing` top-up URL | REMOTE | `--json` | — |
| `blind contribute <invite-link> <file>` | **Porcelain** — the data owner's ONE command. Resolve project + pinned application + public-context digest from the invite link, install/verify the signed application, encode + encrypt LOCALLY, upload **only** ciphertext (auto-pinning the packet's public-context digest). No account created; raw file never leaves the machine. Wraps `applications install` + `contributions create` | BOTH | `--pin-context <digest>` (override the packet's public-context digest), `--json` | prints uploaded ciphertext `sha`, `public-context hash` match, **min-N satisfied** |
| `blind verify <target>` | Core trust command: verify a application bundle, project event chain, result digest, or certificate depending on target shape | LOCAL/BOTH | `--json`, `--offline`, `--local` | verifies application/result/certificate/event hashes as applicable |
| `blind explain <target>` | Core trust command: explain a application, certificate, result, or project in human terms, including what computes, what leaks, and what can be checked | LOCAL/BOTH | `--json` | prints bound hashes + explanation |
| `blind get <path>` | Raw authenticated `GET /api/v1/<path>` (power/dev) | REMOTE | `--json` (default) | — |
| `blind post <path>` | Raw authenticated `POST /api/v1/<path>` (power/dev) | REMOTE | `--field k=v`, `--data <json>`, `--json` | — |
| `blind bench <name@digest>` | Run the benchmark matrix (application × crypto × N × L × security) and emit CSV/Markdown/LaTeX + feasibility plots. Thin alias for `simulations create --sweep …` (docs/simulation_mode.md §2, paper G1) | LOCAL | `--n`, `--length`, `--sweep`, `--crypto`, `--security`, `--emit`, `--json` | prints `sim-run-hash`, `application digest`, `coordinate_hash` |

`login` writes `~/.blind/auth/<profile>.token` (chmod 600). `config --list`
shows the active profile, account, and base URL; `doctor` is where API
reachability is checked. Data owners contributing via a link do **not** log in.

`verify` and `explain` are aliases over the resource-specific trust surface:
`blind verify allele_frequency_count@sha256:…` runs `applications verify`;
`blind verify <certificate_hash>` runs `certificates verify`;
`blind verify <job_id>` runs `results verify`; `blind verify --project <id>`
runs `projects events --verify`. `blind explain <name@digest>` runs
`applications explain`; certificate/result/project targets print the bound hashes,
release policy, and verification steps.

---

## `blind applications` — the public registry  *(BOTH)*

| Command | Description | LOCAL/REMOTE | Key flags | Hashes |
|---|---|---|---|---|
| `blind applications list` | List curated registry applications (name, crypto hint, min-N, latest digest) | REMOTE | `--crypto <hint>` (e.g. `tenseal-bfv`), `--json` | prints each `application digest` |
| `blind applications retrieve <name[@digest]>` | Show a application's manifest, crypto hint, params, coordinate definition, versions | REMOTE | `--version <digest>`, `--json` | prints `application digest`, `coordinate_hash` |
| `blind applications install <name[@digest]>` | Download + **verify The Blind Machine signature** + digest, unpack into `~/.blind/applications/<name>@<digest>/`, then run `uv --project env sync --frozen --no-dev` in a **network-enabled BUILD phase** to seal a pinned env and record `env_lock` | BOTH | `--version <digest>`, `--force`, `--no-seal` (skip env build), `--json` | **verifies** `application digest` (recompute == server), checks Ed25519 signature; **records** `env_lock` |
| `blind applications verify <name@digest>` | Re-verify an installed bundle's digest + signature **and its sealed-env `env_lock`** offline | LOCAL | `--all`, `--json` | **verifies** `application digest`, signature, `env_lock` |
| `blind applications explain <name@digest>` | Plain-language: what it computes, crypto approach, why, what the coordinate definition is, what leaks | LOCAL | `--json` | prints `application digest`, `coordinate_hash` |
| `blind applications test <name@digest>` | Run the bundle's `test_vectors/` locally in the sealed env (bit-exact for BFV integer, tolerance for CKKS) | LOCAL | `--vector <id>`, `--compute-only`, `--json` | prints per-vector expected/actual, tolerance |

`install`/`verify` are the supply-chain gate on the client side: an installed
application is content-addressed and its digest must equal the name suffix and the
server's, and its The Blind Machine signature must validate, or it will not load.
`install` also runs `uv --project env sync --frozen --no-dev` in a **two-phase**
model — a network-enabled **build phase** (fetch uv-locked deps → seal a
container image / venv, record `env_lock`; this phase never sees data) followed
by data-only, network-forbidden **run phases**. Every later stage — local
(`00_keygen.py`/`10_encode.py`/`20_encrypt.py`/`40_decrypt.py`/`50_decode.py`) and
server (`30_compute_encrypted.py`) — runs inside that sealed, `--network none`
sandbox. See
[`../docs/application_structure.md`](../docs/application_structure.md).

**Deferred to v2 (third-party public registry applications).** v1 ships **curated,
signed applications only**, so the write verbs — `applications create`,
`applications update`, `applications delete` — are **not** in the v1 surface. They
arrive with the third-party public-application review story in v2, along with
author-signing and review endpoints. Do not implement them for v1.

---

## `blind projects` — studies + governance  *(mostly REMOTE)*

> These are the **plumbing** resource commands. For the guided human path, use
> the porcelain — `blind projects start`, `status`, `run`, `proof` (see
> "Porcelain vs plumbing" above) — which orchestrate these.

| Command | Description | LOCAL/REMOTE | Key flags | Hashes |
|---|---|---|---|---|
| `blind projects create` | Create a project pinned to one application version | REMOTE | `--application <name@digest>` (required), `--name`, `--min-contributors`, `--scenario`, `--json` | prints `project id`, pinned `application digest` |
| `blind projects list` | List your projects (state, cohort size, run count) | REMOTE | `--state active\|frozen\|archived`, `--json` | — |
| `blind projects retrieve <id>` | Show project state, cohort size, **min-N satisfied?**, run count, all hashes | REMOTE | `--json`, `--watch` | prints `application digest`, `public-context hash`, `cohort commitment` (if frozen), **minimum contributors satisfied** |
| `blind projects update <id>` | Edit mutable project metadata (name, description, min-contributors) **while unfrozen** | REMOTE | `--name`, `--min-contributors`, `--description`, `--json` | — |
| `blind projects delete <id>` | Archive/tombstone the project (append-only event; ciphertext may be tombstoned, but **immutable audit evidence is retained**) | REMOTE | `--reason`, `--yes`, `--json` | — |
| `blind projects freeze <id>` | Commit the cohort so no one can add/remove/re-run contributors | REMOTE | `--yes`, `--json` | **prints + records** `cohort commitment`; prints **minimum contributors satisfied** |
| `blind projects invite <id>` | Mint an **accountless**, short-lived bearer contributor link (+ QR) to hand out out-of-band | REMOTE | `--expires 7d` (default, max 7d), `--qr`, `--count <n>`, `--json` | prints link + `project id`; embeds pinned `application digest` |
| `blind projects events <id>` | Print the project's append-only event log (ProjectCreated → ApplicationPinned → CryptoContextPublished → ContributionAdded → CohortFrozen → JobCreated/Completed → ResultPublished), each with its event hash | REMOTE | `--json`, `--since`, `--verify` | prints each event hash; `--verify` re-checks the hash chain locally |

`freeze` is the anti-differencing gate: it is required before any job and returns
the cohort commitment that every later certificate binds. `delete` never erases
audit evidence — derived state comes from the immutable `events` log, and the
tombstone is itself an appended event.

---

## `blind keys` — the crypto context (100% local keygen)  *(LOCAL)*

All **key material handling is LOCAL** — the secret key is generated on your
machine and stored in the OS keychain; there is no endpoint and no column that
could receive a Private Crypto Context. The only bytes that ever touch the
network in this group are the **public** half: `create` publishes the Public
Crypto Context once, and `retrieve` compares your local public hash against the
server's. Neither moves a secret.†

| Command | Description | LOCAL/REMOTE | Key flags | Hashes |
|---|---|---|---|---|
| `blind keys create --project <id>` | **Locally** run the application's `00_keygen.py` (in the sealed env) to generate the project keypair; store the secret in the OS keychain; publish only the Public Crypto Context | LOCAL † | `--force`, `--json` | prints + publishes `public-context hash`; secret never leaves the machine |
| `blind keys retrieve --project <id>` | Status: where the secret lives (keychain vs fallback file), and whether the local public context matches the server's | LOCAL † | `--json` | **verifies** local `public-context hash` == server's |
| `blind keys list` | List local keypairs across projects (project, crypto hint, keychain vs fallback) | LOCAL | `--json` | prints each `public-context hash` |
| `blind keys export-public --project <id>` | Write the Public Crypto Context to a file to share with contributors (safe to publish) | LOCAL | `--out <path>`, `--json` | prints `public-context hash` |
| `blind keys delete --project <id>` | Delete the **local** key material (keychain entry + `~/.blind` refs). Local only — does not touch the server | LOCAL | `--yes`, `--json` | — |

† `create` performs a single upload of the *public* crypto context
(`PUT …/public_context`) and `retrieve` does a hash comparison against the
server. Keygen runs the platform-owned lifecycle (params come from the manifest,
not the user). No secret/private material is ever uploaded — there is no endpoint
that could accept it.

---

## `blind contributions` — encrypted data in  *(BOTH; encode+encrypt are LOCAL)*

Replaces the old `data submit`. `create` runs the LOCAL encode+encrypt pipeline
and then uploads **only** the resulting ciphertext.

| Command | Description | LOCAL/REMOTE | Key flags | Hashes |
|---|---|---|---|---|
| `blind contributions create --project <id> --data <file>` | LOCAL encode → encrypt (under the project **public** context), then upload **only** the Encrypted ciphertext | BOTH | `--data <file>` (required), `--link <url>` (accountless bearer-link owner path), `--append-sentinel` (default on), `--json` | prints uploaded ciphertext `sha`, `public-context hash` match, **minimum contributors satisfied** (from response); banner: Raw/Encoded LOCAL ONLY, Encrypted uploaded |
| `blind contributions list --project <id>` | List the cohort's contribution hashes + count (owner); `--mine` shows only this caller's/link's submission(s) | REMOTE | `--mine`, `--json` | prints `cohort commitment` (if frozen), each contribution `sha`, **min-N satisfied** |
| `blind contributions retrieve <id>` | Show one contribution's **metadata only** — accepted?, hash, cohort size. **Never** returns plaintext | REMOTE | `--json` | prints contribution `sha`; **min-N satisfied** |

`contributions create --link <url>` is the whole data-owner flow: no account,
encode + encrypt happen locally, and only ciphertext is uploaded. The append-1
sentinel is added at encrypt time and yields the exact contributor count N on
decrypt (integrity check, **not** a MAC).

> **Porcelain:** `blind contribute <invite-link> <file>` is the human door over
> this command — it resolves the project + application + public-context digest
> from the invite link alone (no `--project`/`--application` to copy), then reuses
> `contributions create` underneath. See "Porcelain vs plumbing" above.

---

## `blind data` — LOCAL primitives (power / dev)  *(LOCAL)*

The encode/encrypt steps that `contributions create` runs under the hood, exposed
for power users and application development. Both are LOCAL; nothing is uploaded.

| Command | Description | LOCAL/REMOTE | Key flags | Hashes |
|---|---|---|---|---|
| `blind data encode --project <id>` | Run the application's `10_encode.py` on Raw input → **Encoded** (still plaintext, local only) | LOCAL | `--input <path>` (required), `--out`, `--json` | prints `application digest`, `coordinate_hash`; banner: Raw/Encoded LOCAL ONLY |
| `blind data encrypt --project <id>` | Encrypt Encoded data under the project **public** context → **Encrypted** ciphertext (local) | LOCAL | `--input <path>` (auto-encodes if Raw), `--append-sentinel` (default on), `--json` | prints `public-context hash`, ciphertext `sha`; banner: Encrypted UPLOADABLE |

`data encrypt` fetches the project's public context (`GET …/public_context`) if
it is not already cached locally, but produces only a local artifact — run
`blind contributions create` to upload.

---

## `blind jobs` — compute on ciphertext  *(REMOTE)*

| Command | Description | LOCAL/REMOTE | Key flags | Hashes |
|---|---|---|---|---|
| `blind jobs estimate --project <id>` | Return the **marked-up CPU-second cost estimate** before running (no dispatch) | REMOTE | `--json` | prints `cohort commitment` (if frozen), estimated cost |
| `blind jobs create --project <id>` | Request a compute run; **shows the cost estimate and confirms** before dispatch | REMOTE | `--yes` (skip confirm), `--json` | prints `job id`, pinned `application digest`, `cohort commitment`; requires frozen cohort + min-N |
| `blind jobs list --project <id>` | List the project's jobs (state, cost, result digest) | REMOTE | `--state`, `--json` | prints each `result digest` (when done) |
| `blind jobs retrieve <job>` | Job status (stage, cost, result digest when done) | REMOTE | `--json`, `--watch` | prints `result digest` when done |
| `blind jobs logs <job>` | Fetch the compute worker's logs for a job | REMOTE | `--follow`, `--json` | — |
| `blind jobs watch <job>` | Stream job stages (`verify_contexts` → `seal_env` → `compute` → `store_result`) live by polling `/events` until a terminal line | REMOTE | `--json`, `--timeout`, `--interval` | prints `result digest` when done; prints `failure_reason` and exits nonzero on a failed run |

`jobs create` is blocked server-side unless the cohort is frozen, min-N is met,
the per-project run cap is not exceeded, and the owner's credit balance covers
the estimate. An `insufficient_credits` refusal (HTTP 409) prints the balance,
the estimated cost, and the `/billing` top-up URL (derived from the configured
API base). `jobs estimate` shows the cost before any paid CPU-second is spent
(infinite free projects; compute is the metered axis).

### The job stage stream (`GET /jobs/:id/events`, NDJSON)

One JSON object per line. Lifecycle lines (always present, derived from
persisted state) keep their exact historical shape:

```
{"stage":"queued","at":"<iso8601>"}
{"stage":"running","at":"<iso8601>"}
{"stage":"completed","at":"<iso8601>","result_digest":"sha256:…"}   # or
{"stage":"failed","at":"<iso8601>","failure_reason":"<code>"}
```

Runs executed by the compute worker interleave one line per persisted worker
stage between `running` and the terminal line:

```
{"stage":"verify_contexts","at":"…","status":"ok","elapsed_ms":40,"bundle_digest":"sha256:…","ciphertext_count":21}
{"stage":"seal_env","at":"…","status":"ok","elapsed_ms":3010,"env_lock":"sha256:…","cache":"hit"}
{"stage":"compute","at":"…","status":"ok","elapsed_ms":31000,"ciphertext_count":21,"exit_status":0}
{"stage":"store_result","at":"…","status":"ok","elapsed_ms":90,"result_digest":"sha256:…"}
```

`status` is `running|ok|failed` (a failed stage carries `error: <code>` in its
detail). Every line has `stage` + `at`; detail keys are additive per stage —
consumers MUST tolerate unknown keys. `jobs watch` polls this endpoint
(default every 2 s, `--interval`), renders each `(stage, at, status)`
transition exactly once, and stops on `completed`/`failed` or `--timeout`.
Under `--json` it emits the final `{"object":"job_watch","job":…,"stages":[…],
"result_digest":…}` view (plus `failure_reason` when the run failed); legacy
runs with no persisted worker stages render the exact historical 4-line shape.

---

## `blind results` — download / decrypt / verify  *(BOTH; decrypt is LOCAL)*

| Command | Description | LOCAL/REMOTE | Key flags | Hashes |
|---|---|---|---|---|
| `blind results retrieve <job>` | Download the **Encrypted** result ciphertext + result digest | REMOTE | `--out`, `--json` | **verifies** downloaded `result digest` == server's |
| `blind results decrypt <job>` | Download if needed, then **locally** decrypt with the keychain secret → the aggregate; recover sentinel N | BOTH | `--out`, `--show` (frequencies), `--display maf`, `--json` | **verifies** `application digest`, `cohort commitment`, `result digest`; prints sentinel N, **min-N satisfied** |
| `blind results verify <job>` | **Verify-by-re-execution**: deterministically re-run the pinned `30_compute_encrypted.py` (in the sealed, `--network none` sandbox) on the same ciphertexts → bit-identical result digest | BOTH | `--local` (recompute here), `--inputs <dir>` (with `--local`), `--context <path>`, `--bundle <dir>`, `--timeout <s>` / `--interval <s>` (server-mode polling), `--json` | **verifies** same ciphertexts in → same `result digest` out (determinism, **not** ZK) |

Decryption happens on your machine with the secret key from the OS keychain; the
plaintext aggregate is a local artifact until you choose to publish it.

`results verify` has two modes (the JSON view carries `mode: "server"|"local"`):

* **server** (default) — `POST /jobs/:id/reexecute` spawns a QUEUED,
  non-billable re-execution run (its `result_digest`/`matches` are null at
  creation — the 201 is not a verdict). The CLI polls that run (`--interval`,
  default 2s) until it reaches a terminal state (`--timeout`, default 300s),
  then compares the recomputed digest against the original job's
  `result_digest` (a server `matches` verdict, when present, is respected).
  If the re-execution failed, the CLI surfaces its `failure_reason`; if it is
  still pending at the timeout, the CLI exits with a precondition error —
  never a fabricated verdict.
* **`--local`** — honest local re-execution: the CLI resolves the pinned,
  installed bundle (or `--bundle <dir>`), then runs `30_compute_encrypted.py`
  HERE exactly as the server does (argparse `--context/--inputs/--out`, inputs
  sorted ascending by their sha256 digest — the server's canonical order) over
  the ciphertext files in `--inputs <dir>`, and compares the recomputed digest
  to the server's `result_digest`. Individual cohort ciphertexts are NEVER
  served, so `--local` is for synthetic or self-owned cohorts where you already
  hold the input files.

In both modes digest comparison is encoding-normalized: the platform serves
result digests as bare 64-hex while the CLI's canonical printed form is
`sha256:<hex>` — the same value, compared on the hex.

---

## `blind certificates` — the verifiable record  *(BOTH; verify is LOCAL/offline)*

| Command | Description | LOCAL/REMOTE | Key flags | Hashes |
|---|---|---|---|---|
| `blind certificates retrieve <hash>` | Fetch/print the Computation Certificate by its hash (binds application/project/cohort/data/result hashes + min-N-satisfied + run-count + release policy) | REMOTE | `--out`, `--json` | prints all bound hashes |
| `blind certificates list --project <id>` | List a project's certificates (one per completed job) with their hashes | REMOTE | `--json` | prints each `certificate hash`, `result digest` |
| `blind certificates verify <hash>` | **Offline** re-verify a certificate: recompute every hash and check consistency without trusting The Blind Machine | LOCAL | `--application <name@digest>`, `--file <cert.json>`, `--json` | **verifies** `application digest`, `public-context hash`, `cohort commitment`, `result digest`, `certificate hash`, **min-N satisfied** |

`certificates verify` is the "don't trust, verify" command a skeptical reviewer
runs against a public result page's certificate, fully offline (fetching only the
public certificate + result-digest lookups if it does not already hold them).

---

## `blind simulations` — simulation mode (paper-creation engine)  *(LOCAL)*

Entry point for `docs/simulation_mode.md`. Runs the exact application pipeline in
**cleartext** as the correctness oracle, sweeps synthetic cohorts at scale for
feasibility curves, and emits paper-grade artifacts — all with **no real data and
no server**.

> **Alias:** `blind simulate <name@digest> [flags]` is a documented alias for
> `blind simulations create <name@digest> [flags]`. `blind bench <name@digest>
> [flags]` is a second alias that runs the same engine in matrix mode
> (`--sweep`, default `--emit methods,table,plots,threat_model`) — the benchmark
> matrix the paper's §6 evaluation cites (G1).

| Command | Description | LOCAL/REMOTE | Key flags | Hashes |
|---|---|---|---|---|
| `blind simulations create <name@digest>` | Run the hash-pinned application in **cleartext** on synthetic (or local) data and assert it agrees with the encrypted run — bit-exact for BFV integer results, within published tolerance for CKKS reals | LOCAL | see flag table below | prints `application digest`, `coordinate_hash`; asserts equivalence + max observed error |
| `blind simulations list` | List local simulation runs under `~/.blind/simulations/` (hash, application, cohort sizes, date) | LOCAL | `--json` | prints each `sim-run-hash`, `application digest` |
| `blind simulations retrieve <sim-run-hash>` | Show one simulation run's config + artifacts (equivalence, benchmark, methods, threat model, provenance) | LOCAL | `--json`, `--emit …` | prints `sim-run-hash`, `application digest`, `coordinate_hash` |

Full flag shape for `create` / `simulate` (SSoT: `../docs/simulation_mode.md` §6):

| Flag | Meaning |
|---|---|
| `--synthetic --n 20,100,1000` | generate seeded synthetic cohort(s) at these sizes (HWE sampler) |
| `--coordinates <manifest-key>` | manifest coordinate/variant/bucket definition to generate over (byte-shaped exactly like real contributions) |
| `--maf-dist <beta\|file>` · `--missingness <p>` · `--seed <n>` | reproducible cohort recipe — a reviewer regenerates the *exact* cohort from `(seed, params)` |
| `--from <dir>` | run the oracle on the researcher's own **LOCAL** raw vectors instead of synthetic (never uploaded) |
| `--against-result <result-hash>` | assert the cleartext oracle agrees with an already-produced encrypted result |
| `--crypto <id>` | override the application's crypto config (for the additive-vs-multiplicative-depth comparison row) |
| `--security <128,192,256>` | security-level axis; single value sets the base level, a comma list sweeps it |
| `--sweep n=…,length=…,crypto=…,security=…` | feasibility grid: measure runtime / ciphertext size / memory / cost / exactness per cell |
| `--emit methods,table,plots,threat_model` | write paper-grade artifacts (Methods paragraph, LaTeX/MD/CSV table, plots, threat-model prose) |
| `--attack differencing` | demonstrate the K-vs-K+1 attack on an *unfrozen* cohort, then show freeze + min-N + run-cap refuse it |
| `--replay <sim-run-hash>` | reproduce a cited simulation byte-for-byte |

Every run is written under `~/.blind/simulations/<sim-run-hash>/` (`config.yml`,
`equivalence.json`, `benchmark.{csv,md,tex}`, `plots/`, `methods.md`,
`threat_model.md`, `provenance.json`) as a **NON-authoritative `SimulationRun`** —
never a `ComputationCertificate`, no cohort commitment, no min-N gate. Nothing is
uploaded unless you explicitly push a shareable sim result page.

---

## `blind dev` — plaintext-vs-encrypted harness  *(LOCAL)*

Developer tools for building and trusting a application before wiring it to the
platform. All local.

| Command | Description | LOCAL/REMOTE | Key flags | Hashes |
|---|---|---|---|---|
| `blind dev run-local <name@digest>` | Run the full pipeline in **cleartext** on given input (the oracle) | LOCAL | `--input`, `--n`, `--seed`, `--out`, `--json` | prints `application digest` |
| `blind dev run-encrypted <name@digest>` | Run the full pipeline **encrypted** end-to-end locally (keygen→encode→encrypt→compute→decrypt), no server | LOCAL | `--input`, `--n`, `--seed`, `--out`, `--json` | prints `application digest`, `public-context hash`, `result digest` |
| `blind dev compare <name@digest>` | Run both and assert agreement: **bit-exact** (BFV integer) or **within published tolerance** (CKKS reals) | LOCAL | `--input`, `--n`, `--tolerance`, `--json` | prints both `result digest`s + pass/fail |

`dev compare` is the daily-system-test primitive: cleartext result must equal the
encrypted-then-decrypted result (bit-exact for BFV integer results;
tolerance-bounded for CKKS reals), which is also the paper's
simulation-vs-encrypted equivalence claim.

---

## Full command list (flat)

```
# porcelain — the guided human loop (see "Porcelain vs plumbing")
blind projects      start <application> --name … --min 20   # owner: set up a study
blind contribute    <invite-link> <file>                    # data owner: contribute once
blind projects      status <id>                             # owner: progress + next action
blind projects      run <id>                                # owner: freeze + compute + decrypt
blind projects      proof <id>                              # owner: the reviewer's verify command

# plumbing — the resource + CRUD surface
blind login
blind logout
blind config [--list | --set k=v]
blind doctor
blind version
blind resources
blind credits
blind verify <target>
blind explain <target>
blind get <path> | post <path>

blind applications     list | retrieve <name@digest> | install <name@digest> | verify <name@digest> | explain <name@digest> | test <name@digest>
                    # create | update | delete  → v2 third-party public applications, not in v1
blind projects      create | list | retrieve <id> | update <id> | delete <id> | freeze <id> | invite <id> | events <id>
                    # porcelain: start <application> | status <id> | run <id> | proof <id>
blind keys          create --project <id> | retrieve --project <id> | list | export-public --project <id> | delete --project <id>
blind contributions create --project <id> --data <file> | list --project <id> | retrieve <id>
blind data          encode --project <id> | encrypt --project <id>
blind jobs          estimate --project <id> | create --project <id> | list --project <id> | retrieve <job> | logs <job> | watch <job>
blind results       retrieve <job> | decrypt <job> | verify <job>
blind certificates  retrieve <hash> | list --project <id> | verify <hash>
blind simulations   create <name@digest> | list | retrieve <sim-run-hash>      (alias: blind simulate <name@digest>)
blind bench         <name@digest> [--sweep n=…,length=…,crypto=…,security=…]   (alias: simulations create --sweep …)
blind dev           run-local <name@digest> | run-encrypted <name@digest> | compare <name@digest>
```

---

## HTTP API contract

Endpoints the Rails platform must expose for the CLI (Step-7 builds these). All
JSON over HTTPS, versioned under `/api/v1`. Account calls use
`Authorization: Bearer <token>`; the **accountless bearer-link** contributor path
uses `Authorization: Bearer <invite-token>` (a 7-day project token, not an
account). Byte-exact artifact contracts (application bundle layout, public-context
serialization, ciphertext framing, certificate JSON) are shared fixtures the CLI
and platform both test against.

CRUD verbs map to REST the usual way: **create → POST**, **list → GET
collection**, **retrieve → GET item**, **update → PATCH item**, **delete →
DELETE item**, and **resource-specific actions → POST a sub-resource**. Item-level
reads on globally-addressable objects (a job, a contribution, a certificate) are
flat top-level paths, Stripe-style; project-scoped creates/lists are nested under
the project.

**Hard invariant:** there is **no** endpoint that accepts a Private Crypto
Context or a secret key. `keys create` uploads the public context only.

### Auth  (`login`, `config`, `doctor`)
| Method + path | Purpose | Used by |
|---|---|---|
| `POST /api/v1/auth/device` | Start device/browser code login | `login` |
| `POST /api/v1/auth/token` | Exchange code (or API key) for a bearer token | `login` |
| `GET  /api/v1/me` | Current account + reachability | `login` (verify), `config --list`, `doctor` |

### `credits`  (billing)
| Method + path | Purpose | Used by |
|---|---|---|
| `GET  /api/v1/credits` | Credit balance for the authenticated bearer — `balance_cents` (canonical) + `balance_usd` ("12.34"-style string) | `credits`; `jobs create` (the insufficient_credits hint) |

### `applications`  (registry)
| Method + path | CRUD/verb | Purpose | Used by |
|---|---|---|---|
| `GET  /api/v1/applications` | list | List curated applications (name, crypto hint, min-N, latest digest) | `applications list` |
| `GET  /api/v1/applications/:name` | retrieve | Application metadata + version digests | `applications retrieve` |
| `GET  /api/v1/applications/:name/versions/:digest` | retrieve | Manifest + coordinate definition + params for a pinned version | `applications retrieve` / `explain` |
| `GET  /api/v1/applications/:name/versions/:digest/bundle` | action | Download the signed, content-addressed bundle (tarball) | `applications install` |
| `GET  /api/v1/applications/:name/versions/:digest/signature` | action | The Blind Machine Ed25519 signature over the bundle | `applications install` / `verify` |

> v2 only (third-party public applications, **not** in v1): `POST /api/v1/applications`, `PATCH
> /api/v1/applications/:name/versions/:digest`, `DELETE
> /api/v1/applications/:name` — the create/update/delete verbs. Curated-only in v1.

### `projects`  (studies + governance)
| Method + path | CRUD/verb | Purpose | Used by |
|---|---|---|---|
| `POST   /api/v1/projects` | create | Create project pinned to `name@digest` | `projects create` |
| `GET    /api/v1/projects` | list | List caller's projects | `projects list` |
| `GET    /api/v1/projects/:id` | retrieve | State, cohort size, min-N satisfied, run count, hashes | `projects retrieve` |
| `PATCH  /api/v1/projects/:id` | update | Edit mutable metadata (name, min-contributors) while unfrozen | `projects update` |
| `DELETE /api/v1/projects/:id` | delete | Archive/tombstone (append-only event; audit evidence retained) | `projects delete` |
| `POST   /api/v1/projects/:id/freeze` | action | Freeze cohort → returns `cohort_commitment` | `projects freeze` |
| `POST   /api/v1/projects/:id/invitations` | action | Mint a ≤7-day accountless bearer contributor link/token | `projects invite` |
| `GET    /api/v1/invitations/:token` | retrieve | Resolve an invite token to a **contribution packet** (project id + name, pinned `application`, `public_context_digest`, min-N, expiry) so the CLI needs only the link | `contribute` |
| `GET    /api/v1/projects/:id/events` | action | Append-only, hash-chained event log | `projects events` |

### `keys`  (public crypto context only)
| Method + path | CRUD/verb | Purpose | Used by |
|---|---|---|---|
| `PUT  /api/v1/projects/:id/public_context` | action | Publish the Public Crypto Context (server stores the **public half only**) | `keys create` |
| `GET  /api/v1/projects/:id/public_context` | retrieve | Fetch the project public context (compare / contributors need it) | `keys retrieve`, `data encrypt`, `contributions create` |

> `keys list`, `keys export-public`, and `keys delete` are **LOCAL only** — no
> endpoint. There is deliberately no path that could receive a secret key.

### `contributions`  (encrypted data in)
| Method + path | CRUD/verb | Purpose | Used by |
|---|---|---|---|
| `POST /api/v1/projects/:id/contributions` | create | Upload one Encrypted ciphertext (+ its hash); account **or** invite-token auth | `contributions create` |
| `GET  /api/v1/projects/:id/contributions` | list | Cohort size + contribution hashes (owner) | `contributions list` |
| `GET  /api/v1/projects/:id/contributions/mine` | list | Status of this caller's/link's submission(s) | `contributions list --mine` |
| `GET  /api/v1/contributions/:id` | retrieve | One contribution's metadata (**never** plaintext) | `contributions retrieve` |

### `jobs`  (compute on ciphertext)
| Method + path | CRUD/verb | Purpose | Used by |
|---|---|---|---|
| `POST /api/v1/projects/:id/jobs/estimate` | action | Return marked-up CPU-second cost estimate (no dispatch) | `jobs estimate` |
| `POST /api/v1/projects/:id/jobs` | create | Create + dispatch a compute job (requires frozen cohort + min-N + run cap) | `jobs create` |
| `GET  /api/v1/projects/:id/jobs` | list | List the project's jobs | `jobs list` |
| `GET  /api/v1/jobs/:id` | retrieve | Job status + result digest when done | `jobs retrieve` |
| `GET  /api/v1/jobs/:id/events` | action | Job stage stream | `jobs watch` |
| `GET  /api/v1/jobs/:id/logs` | action | Compute worker logs | `jobs logs` |

### `results` + `certificates`
| Method + path | CRUD/verb | Purpose | Used by |
|---|---|---|---|
| `GET  /api/v1/jobs/:id/result` | retrieve | Download Encrypted result ciphertext + `result_digest` | `results retrieve` / `decrypt` |
| `POST /api/v1/jobs/:id/reexecute` | action | Verify-by-re-execution → returns recomputed `result_digest` | `results verify` |
| `GET  /api/v1/projects/:id/certificates` | list | List a project's certificates (one per completed job) | `certificates list` |

### Public verification (no auth)
| Method + path | CRUD/verb | Purpose | Used by |
|---|---|---|---|
| `GET  /api/v1/certificates/:certificate_hash` | retrieve | Public certificate fetch for a Blind Result Page | `certificates retrieve` / `verify` |
| `GET  /api/v1/results/:result_digest` | retrieve | Public result-digest lookup for offline verification | `certificates verify`, `results verify` |

### Raw power commands
`blind get <path>` and `blind post <path>` issue an authenticated request to any
`/api/v1/<path>` (Stripe-style). `post` takes `--field k=v` (repeatable) or
`--data <json>`.

---

## Command → trust-boundary summary

| Group | LOCAL-only ops | REMOTE ops | Both |
|---|---|---|---|
| porcelain | — | projects status | projects start, contribute, projects run, projects proof |
| top-level | logout, config, version, resources, bench | login, credits, get, post | doctor |
| applications | verify, explain, test | list, retrieve | install |
| projects | — | create, list, retrieve, update, delete, freeze, invite, events | — |
| keys | create †, retrieve †, list, export-public, delete | — | — |
| contributions | — | list, retrieve | create |
| data | encode, encrypt | — | — |
| jobs | — | estimate, create, list, retrieve, logs, watch | — |
| results | — | retrieve | decrypt, verify |
| certificates | verify | retrieve, list | — |
| simulations | create, list, retrieve | — | — |
| dev | run-local, run-encrypted, compare | — | — |

† Key material handling is LOCAL. `keys create` additionally publishes the
*public* context once and `keys retrieve` compares a public hash against the
server — the sole, public-only network touches in the group. **No secret ever
leaves the machine, and no endpoint could receive one.**

The pattern the whole surface enforces: **keygen, encode, encrypt, decode,
decrypt, simulate, and all verification are LOCAL**; the server only ever
receives Public contexts and Encrypted ciphertext, and only ever returns
Encrypted results plus public metadata + certificates.
