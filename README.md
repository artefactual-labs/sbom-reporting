# sbom-reporting

A small Python CLI for combining software inventories and reporting them to
Dependency-Track. Repositories build their software and select collectors. This
tool checks the declared inputs, preserves their origins, creates one complete
CycloneDX snapshot, and verifies its import.

This is a CLI, not a deployed service. Enduro legacy has a verified development
pilot; main, release, and other-repository adoption remain separate rollout
tasks.

## GitHub Actions

Use this repository directly as a setup action, pinned to a full commit SHA:

```yaml
- uses: actions/checkout@v7.0.1
- uses: artefactual-labs/sbom-reporting@FULL_COMMIT_SHA
  id: reporting
- run: sbom-reporting merge manifest.json --output sbom-snapshot
- run: sbom-reporting verify sbom-snapshot
```

The action installs Python 3.14 and uv, then installs its own downloaded
revision using `uv.lock`. It adds that environment's executables, including
`sbom-reporting` and Python, to PATH. It does not upload anything. The `python`
output identifies the exact Python executable for repository collectors that
need the reporting package; `revision` records the installed package commit for
retained evidence. The action currently targets Linux runners.

During development, callers may use `@main`. For mutable refs the action fetches
a separate checkout into the runner's temporary directory, resolves its commit,
and installs that exact checkout. This preserves an accurate `revision` output
even if the branch changes after the runner downloads the action. SHA-pinned
calls install directly from the downloaded action directory.

Callers still own build orchestration, collection configuration, secrets,
collection prerequisites, serialized uploads, branch freshness, and evidence
retention. See [the contract] for the upload requirements.

For retries, authenticate the retained build evidence first, then pass its saved
full commit SHA as the `revision` input. The setup action fetches that commit
from its own repository and installs it with its own lockfile. A branch or tag
is rejected for this input. Keep the setup action itself SHA-pinned and record
its revision separately from the installed CLI revision when they differ.

Version `v0.1.0` is the first tagged release. Tags are not moved after
publication. During the `0.x` series, incompatible CLI or reporting-contract
changes increment the minor version; compatible fixes increment the patch
version. Retained snapshots are retried with their original CLI commit rather
than assuming that new versions can reconstruct them.

## Shared collection

Version 0.2.0 includes a GoReleaser archive collector and a packaged Vite
evidence plugin. They are distributed with the Python package and setup action,
so a product repository needs configuration and plugin registration, not copies
of the collector code. The current explicit profile supports one Linux amd64,
CGO-disabled Go binary in one tar.gz archive with an embedded Vite frontend.
Other platforms and delivery formats fail until a supported profile is added.

Create a repository configuration such as `sbom.toml`:

```toml
product = "Example App"
repository = "example/app"
property_namespace = "example-app"
binary = "app"
platform = "linux/amd64"
dist = "dist"
frontend = "frontend/.output/public"
evidence = "sbom-evidence"
rolling_versions = ["main"]
```

Paths resolve relative to the configuration file. Before building, retain
`go list -m -json all` as `go-modules.json` and the npm `package-lock.json` in
the evidence directory. Install the setup action before the frontend build, and
pass its `frontend-plugin` output as `SBOM_FRONTEND_PLUGIN` together with an
absolute `SBOM_FRONTEND_EVIDENCE` destination for `frontend-build.json`. Without
Actions, `sbom-reporting frontend-plugin` prints the same packaged plugin path.

Nuxt/Vite configuration imports the supplied module only for reporting builds:

```javascript
import { pathToFileURL } from 'node:url'

const pluginPath = process.env.SBOM_FRONTEND_PLUGIN
const plugins = pluginPath
  ? [(await import(pathToFileURL(pluginPath).href)).sbomEvidence({ nuxtIcons: true })]
  : []
// Add plugins to the application's Vite configuration.
```

The `nuxtIcons` integration is opt-in. It verifies generated icon bodies against
their installed collection packages and rejects unknown generated formats. The
plugin records rendered package modules separately from build-only inputs and
hashes emitted JavaScript chunks without changing them. It does not establish
complete CSS/font/virtual-asset package attribution.

After GoReleaser finishes:

```sh
sbom-reporting collect-goreleaser sbom.toml \
  --version "$VERSION" --commit "$COMMIT" --run "$CI_RUN"
sbom-reporting merge sbom-evidence/manifest.json --output sbom-evidence/snapshot
```

Set `DEPENDENCY_TRACK_PARENT_UUID` as usual. The collector validates archive
checksums, platform, clean source identity, compiled Go dependencies, frontend
package versions, chunk hashes, and embedded file bytes. It emits six required
inventories and the manifest: Go source, npm source, binary, frontend bundle,
frontend build inputs, and artifact files. Collection never uploads. Retry
commands continue to use the original installed tool revision and snapshot.

## Development

Requires Python 3.14 and [uv]. The project uses `pyproject.toml`, a `src`
layout, type hints, [Ruff], [ty], and [pytest]. Dependencies were resolved from
current releases on 30 October 2026; `uv.lock` records the exact versions.
Normal checks use the lock rather than silently changing dependencies on every
run.

```sh
uv sync --locked
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked ty check
uv run --locked pytest --cov=sbom_reporting --cov-report=term-missing
uv build
node --test tests/frontend.test.mjs
```

To update to the latest compatible releases, run `uv lock --upgrade`, then
`uv sync --locked` and the checks above. Update direct dependency minimums and
Python/build-backend/CI pins deliberately when adopting new versions. There is
no automatic publication or repository migration workflow.

## Workflow dependencies

CI runs [jactionlint] with the pedantic profile and fails on warnings. The
[Actions lockfile] pins direct and transitive workflow dependencies; CI verifies
both coverage and upstream provenance with `gh actions-lock --verify`. The
published setup action also pins its internal setup-uv dependency to a full SHA
for callers that do not maintain their own Actions lockfile.

After changing an action reference, regenerate and verify the lockfile:

```sh
gh extension install github/gh-actions-lock --pin v0.4.0
gh actions-lock --no-narrow
gh actions-lock --verify
jactionlint --strict-exit
```

Use jactionlint 2.4.0, matching CI. Do not edit `actions.lock` by hand.
Dependabot checks GitHub Actions and uv dependencies weekly, groups version
updates by ecosystem, and allows a seven-day cooldown. Repository Dependabot
alerts and security updates are enabled; proposed updates still require review
and passing CI.

Python 3.14 is used to stay within Dependabot's supported updater runtimes. The
initial Python 3.15 configuration prevented uv update jobs from running.

## Try it locally

The checked-in example uses invented packages and a placeholder collection UUID.
It is suitable for merge/verification only.

```sh
uv run sbom-reporting manifest-schema
uv run sbom-reporting merge examples/manifest.json --output snapshots/example
uv run sbom-reporting verify snapshots/example
```

`merge` creates a new directory and refuses to overwrite an existing snapshot.
The directory includes original input bytes, a normalized manifest, the combined
BOM, input and output hashes, tool version, and the distinction between asserted
artifact identities and hashes verified from an available local file. Stable
inputs produce the same snapshot identity and output. `verify` revalidates the
schemas and reconstructs the merge from the saved inputs.

After configuring a real manifest and authorizing an upload:

```sh
export DEPENDENCY_TRACK_URL=https://your-api-server.example
# Set DEPENDENCY_TRACK_API_KEY using your secret manager or CI secret store.
uv run sbom-reporting upload snapshots/example
```

A missing child is an error unless `--allow-create` is explicitly supplied. That
option creates the version child only. The versionless collection must already
exist. The tool never creates or reparents collections, changes reporting tags,
or makes vulnerability-policy decisions.

A rolling upload also requires `--expected-head COMMIT`. The CI wrapper must
serialize uploads and obtain that commit from the current remote branch under
the lock, immediately before invoking the tool. This argument checks
consistency; it does not acquire a lock or discover the current head itself. The
wrapper must check freshness again afterward and make newer build failures
visible.

For retries, keep the complete snapshot directory and use the same tool version.
The tool does not rebuild artifacts or rerun scanners. The wrapper remains
responsible for authenticating the retained evidence and matching it to its
original trusted CI run/attempt. Hashes detect changes; they are not signatures.

## Contracts and boundaries

See [the contract] for the manifest, origins, supported CycloneDX structures,
merge rules, and upload verification. See [rollout] for the remaining pilot and
operational work.

The implementation draws on the existing a3m, AIPscan, depbot, and Enduro legacy
approaches. Shared collectors handle supported archive inspection and frontend
evidence. Build orchestration, unsupported artifact formats, container scanning,
CI-specific trust/freshness checks, and release retention remain repository
responsibilities.

[actions lockfile]: https://github.com/github/gh-actions-lock
[jactionlint]: https://jactionlint.jdx.dev/
[pytest]: https://docs.pytest.org/en/stable/
[rollout]: docs/rollout.md
[ruff]: https://docs.astral.sh/ruff/
[the contract]: docs/contract.md
[ty]: https://docs.astral.sh/ty/
[uv]: https://docs.astral.sh/uv/
