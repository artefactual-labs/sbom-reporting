# Version 1 reporting contract

The manifest schema is available from `sbom-reporting manifest-schema`. The
[example manifest] is executable documentation.

## Manifest

All fields are required unless described otherwise. Unknown fields are rejected.

| Field            | Meaning                                                         |
| ---------------- | --------------------------------------------------------------- |
| `schema_version` | `1`                                                             |
| `product`        | Canonical Dependency-Track application/collection name          |
| `version`        | Exact branch label or release tag; never strip a leading `v`    |
| `kind`           | `rolling` or `release`                                          |
| `repository`     | Repository HTTP(S) URL without embedded credentials             |
| `source_commit`  | Full 40- or 64-character lowercase commit hash                  |
| `ci_run`         | Exact build/run URL, including attempt where the CI supports it |
| `parent_uuid`    | UUID of the pre-existing versionless collection                 |
| `inputs`         | Nonempty list of required input inventories                     |

Optional `parent_collection_logic` and `parent_collection_tag` fields constrain
the collection configuration before upload. A tag requires
`AGGREGATE_DIRECT_CHILDREN_WITH_TAG`. Enduro uses these to enforce its
`report-current` collection prerequisite.

Every input declares a unique lowercase `id`, `role` (`source`, `artifact`, or
`tooling`), and `sbom` path relative to the manifest. An artifact input also
requires an `artifact` object. Source/tooling inputs may supply one if
applicable.

Artifact identity contains `name`, `platform` (for example `linux/amd64`), and
exactly one of `sha256` or `image`. An image reference must include an immutable
`@sha256:` digest. A file identity may also specify a local `path`: its bytes
are checked against `sha256` at merge time. Without those bytes, the identity is
recorded as **asserted**, not independently verified. Image digests are always
caller assertions in this implementation; the tool does not pull images.

The caller declares every required platform/artifact. The tool cannot discover
that an omitted platform should have been scanned. It never uploads a partial
fallback when a declared input fails.

## CycloneDX and merging

CycloneDX JSON 1.6 and 1.7 are schema-validated with bundled schemas. Mixed
inputs produce 1.7 if any input is 1.7. Each input requires a metadata component
and unique component references. Flat and nested components and `dependencies`
edges are supported. Dangling edges fail validation.

Vulnerability records, services, compositions, formulations, annotations,
`provides` edges, and unhandled reference-bearing structures are rejected. An
empty `vulnerabilities` array is accepted because Trivy includes it in inventory
output. Pedigree, evidence, model cards, crypto/data structures, and nested
references outside component containment are unsupported rather than silently
dropped. Pilot scanner fixtures must establish any extension to this boundary.

The combined root is an application. Original input roots retain their own
identities and types. Their scanner metadata is retained as serialized JSON on
the original root, and all original documents are retained unchanged.

Package identity includes canonical PURL with all qualifiers/subpaths, explicit
version, component type, and CPE. Different package versions/platform qualifiers
stay separate. Original input roots and components without a reliable PURL
retain per-input occurrence identities; matching names alone never merges them.

Equivalent PyPI spellings (case, underscores, hyphens, and dots) are normalized
using the [Python packaging rule]. Original spellings are retained in
`sbom-reporting:scanner-names:v1`. Other scalar metadata conflicts fail the
merge. Compatible dictionaries are combined and list evidence is unioned.
Dependency references are rewritten to deterministic component identifiers and
edges are unioned. Input-root dependencies are attached to the combined
application root. This does not imply that all source/tooling components are
shipped or reachable at runtime.

Nested components are flattened into the output component table. Original
containment is preserved separately in `sbom-reporting:contains:v1`, a JSON
array of child component identities. Containment is not converted into invented
runtime dependency edges. Original documents remain available for consumers that
need the scanner's original tree.

Known `*:source:commit`, reporting-version, and image-reference assertions are
checked against the manifest when supplied. A manifest is still a
caller-supplied provenance assertion, not proof that a scanner read the declared
artifact. Repository adapters must independently establish that connection, such
as Enduro's comparison of embedded frontend bytes.

## Origins and scanner properties

Every output component has these properties:

- `sbom-reporting:identity`: deterministic component identity, independent of
  server-generated `bom-ref` values.
- `sbom-reporting:snapshot`: binds it to the exact manifest and input hashes.
- `sbom-reporting:source-commit`: keeps the inventoried commit visible after
  import.
- `sbom-reporting:origins:v1`: JSON array of observations, each with an input
  ID, role, and declared artifact identity/platform when applicable.

A component shared between inputs retains all observations. A consumer must show
missing or unknown origins as **unknown**; source presence never implies runtime
inclusion or exclusion. This format needs agreement with the report consumers
before rollout.

Scanner component properties can be multi-valued: Trivy, for example, repeats
layer properties. They are preserved in `sbom-reporting:scanner-properties:v1`
as a JSON object mapping each original property name to its distinct values.
They are not silently reduced to a single scalar. This also avoids duplicate
property names being collapsed by Dependency-Track. Scanner inputs may not use
reserved `sbom-reporting:` component properties.

## Snapshots and retries

`merge` saves:

- `manifest.json`: normalized manifest; saved inputs use relative snapshot
  paths.
- `inputs/*.cdx.json`: original scanner bytes.
- `combined.cdx.json`: one complete combined application inventory.
- `snapshot.json`: versioned record of tool version, manifest/input fingerprint,
  input checksums, artifact-check status, and canonical combined checksum.

The serial number derives from the snapshot identity. No fresh timestamp is
added on merge/retry, so identical input bytes and normalized manifest reproduce
the same result. Scanner timestamps already present in the raw inputs remain
part of their identity. Moving the original input files does not change the
normalized snapshot. Changing their bytes does.

`verify` and `upload` check input checksums, the manifest fingerprint, schema
and reference integrity, and equality with a reconstructed merge. Retry with the
recorded tool version. A successful local check is not authentication: an
attacker who can replace the whole directory can recompute hashes. CI must
authenticate artifact origin, workflow, repository, commit/tag, and exact run
attempt.

Retain snapshots for at least 90 days, and release evidence for its supported
lifetime if longer. Those storage/retention guarantees belong to each caller.

## Upload behavior

Supply `DEPENDENCY_TRACK_URL` (API base URL, without `/api/v1`) and
`DEPENDENCY_TRACK_API_KEY` through the environment. HTTPS is required except for
loopback test servers; redirects are refused. Keys are never written to
snapshots or receipts. HTTP errors report status without echoing the server
response body.

The parent must match the manifest product, have an empty version, classifier
`APPLICATION`, and a recognized non-`NONE` collection aggregation mode. Existing
children must match product/version/parent and use `APPLICATION`/`NONE`.
`--allow-create` permits a missing child; `parentUUID` does not reparent an
existing child. Administrative collection/tag management remains outside the
CLI.

Reads need `VIEW_PORTFOLIO` and access to the projects; uploads need
`BOM_UPLOAD`. Creating missing children additionally needs
`PROJECT_CREATION_UPLOAD` or `PORTFOLIO_MANAGEMENT`. The reporting key need not
administer collections.

The uploader records distinct stages in `upload-result.json`: validation,
acceptance, processed-but-unverified, and verified import. Failures replace a
previous receipt with a failing state and retain the last completed stage. The
original snapshot remains available for retry. The latest server-exported BOM is
retained as `imported.cdx.json` for mismatch diagnosis. It never reports a
failed upload as zero vulnerabilities or as a vulnerability-policy pass.

After processing completes, the tool exports the server's inventory and compares
application identity, source/CI references, component identities, origins,
properties, types, versions, platforms, hashes, and dependency edges. It
tolerates server-rewritten references and canonicalized PURLs. Export comparison
also accepts the Java PURL library’s older lowercase rule for Go namespaces and
names. This does not change merge identity or source PURLs; component names,
stable identities, versions, qualifiers, subpaths, and every provenance property
still must match. Collapsed components fail the identity/count checks. Project
metadata properties need not round-trip; the snapshot fingerprint is carried on
every component. Loss or ambiguity fails verification. A server that cannot
supply this evidence produces an unverified failure, never success based on
token completion alone.

The CLI does not implement a cross-system lock or fetch branch heads. The caller
must serialize all writers (including retries), supply a fresh matching
`--expected-head` for rolling inventories, recheck the head after import, and
expose failed newer builds. GitHub/GitLab-specific wrappers belong in those
repos.

[example manifest]: ../examples/manifest.json
[python packaging rule]: https://packaging.python.org/en/latest/specifications/name-normalization/
