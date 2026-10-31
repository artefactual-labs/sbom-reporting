# Initial implementation and rollout

Implemented in the initial CLI:

- Python 3.14 package/CLI, uv lockfile, Ruff, ty, pytest, and CI checks.
- Versioned manifest and origin contracts; explicit required inputs.
- CycloneDX 1.6/1.7 validation, flat/nested component handling, dependency graph
  remapping, conservative identity merging, and multi-valued scanner properties.
- Original input retention, deterministic snapshots, hash checks, and retry
  verification without rebuilding.
- Dependency-Track hierarchy checks, explicit child creation, processing states,
  and normalized import verification with loopback HTTP integration tests.

The implementation was informed by depbot's identity/graph merger, a3m's
explicit input and provenance checks, AIPscan's hierarchical/platform coverage,
and Enduro's import/retry review. Their behavior was compared rather than
copying Enduro's flat merger into a generic interface.

Local compatibility checks also accepted retained a3m source/container and
depbot scanner inventories. The retained a3m pair was merged and locally
verified, including Trivy's repeated layer properties and equivalent PyPI name
spellings. Those checks used synthetic run/parent values and performed no
uploads; they are not a replacement for the two pilots.

## Enduro development pilot

The historical Enduro legacy pilot used tool commit
`3c6b667d7c0cd833a7ef878530d1e9c6770f1000`. Its [reporting run] and [test run]
passed on `dev/sbom-reporting` at `b060f01273ab1444d2a8d24d14ea3bb3f7627566`.
The [imported inventory] is named `Legacy Enduro`, version `dev/sbom-reporting`;
main and release adoption remain unverified.

The pilot combined Go source, npm source, the archived Go executable, confirmed
frontend bundle packages, frontend build inputs, and delivered files into one
validated 1,869-component snapshot. The actual Linux amd64 archive, embedded
frontend, component origins, source commit, CI run, hashes, and dependency graph
were retained and verified against the server export. Post-import freshness was
true for the final branch commit. The pilot originally used an Enduro-local
collector. Collection now lives in the shared package; Enduro owns configuration
and CI coordination; common merging, snapshot validation, hierarchy checks, and
import verification are provided here.

Live use exposed sparse lookup responses and the Java PURL library's legacy Go
casing. The shared client now fetches full project records and recognizes that
specific export normalization, with HTTP regression tests. It retains server
exports for diagnosis. Original component identities and all provenance remain
strictly checked.

The server also omitted properties on a processed update. Re-uploading the same
snapshot restored them. Enduro's wrapper now retries an import once only after
it has completed processing but failed verification, checks branch freshness
before each upload under the same lock, and retains both receipts/exports. The
final run exercised recovery successfully. Persistent differences still fail;
the server-side cause remains unresolved. Other callers should investigate the
behavior on their server and must not weaken verification to hide missing
evidence.

## Remaining adoption work

- Agree the manifest/origin/containment contract with report consumers.
  Demonstrate that a component found in source and an artifact retains both
  observations, tooling-only findings stay distinguishable, and absent origin
  appears as unknown. Do not infer runtime reachability from source presence.
- Review licensing and release ownership for the new repository.
- Add representative scanner fixtures from the pilot workflows and test any
  unsupported structures before claiming those formats are covered.
- Pilot depbot and AIPscan locally and then, with explicit authorization,
  against Dependency-Track. Verify real import/export normalization, hierarchy,
  package identities, file hashes, multi-valued properties, graphs, and origins.
  Include container/Python scanner outputs and a GitLab caller before extending
  the GoReleaser collector's deliberately narrow platform/build profile.
- Enduro provides a GitHub caller wrapper. Implement and verify equivalent
  trusted-run lookup, serialization, freshness, failure visibility, and release
  retention for the other callers, including GitLab.
- Exercise retained-release recovery with an expired CI artifact and an
  available original run record. Enduro authenticates release assets against
  that record, so preserve the run for the entire supported release lifetime. A
  saved copy of run JSON inside the same asset is not independent
  authentication. A missing run must remain a visible failure until a durable,
  independently verifiable provenance mechanism is implemented.
- Pin callers to a reviewed commit. An invocation can use
  `uvx --from 'git+https://github.com/artefactual-labs/sbom-reporting@COMMIT' sbom-reporting ...`;
  use a full commit SHA and retain the corresponding lockfile.
- Review and merge Enduro’s development integration, then verify real main and
  exact-release inventories. Follow with depbot/AIPscan and a3m pilots. Preserve
  artifact-specific scans when replacing common merge/upload code.

The tool is published at `artefactual-labs/sbom-reporting`. The verified Enduro
development pilot establishes one live integration; it does not establish main,
release, other-repository, or report-consumer adoption.

[imported inventory]: https://dependency-track.pet.artefactual.dev/projects/74d97590-3c25-40ea-b872-b41a38cbdc2d
[reporting run]: https://github.com/artefactual-labs/enduro/actions/runs/41179860877
[test run]: https://github.com/artefactual-labs/enduro/actions/runs/41179860825
