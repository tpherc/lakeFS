# Mixed-backend logical views: implementation record

Implementation against development `b7fdfa20f15eec07645773a384db6a4fd4b3120d`, following the [accepted design](../accepted/mixed-backend-logical-views.md). This record separates local test evidence from production release gates. No deployment or live-provider validation is claimed.

## Implemented behavior

- `storage_id` is optional on `StagingLocation`, `ObjectStageCreation`, `ImportLocation` and `ObjectStats`. The OpenAPI server and Python/Java/Rust SDKs are regenerated. Catalog Entry tag 8 and the Spark schema mirror carry the saved binding.
- New home-managed RELATIVE entries save an empty ID; their API response reports effective home. FULL references save the selected effective ID. Metadata updates preserve representation. Nonempty IDs contribute a typed, named identity component; empty IDs preserve legacy hashes.
- REST, gateway, Actions, copy sources and native properties/presign use the saved source. Unknown explicit IDs never fall back, including restored bindings in legacy single-store mode; all physical access passes through the configured-ID dispatcher. Foreign RELATIVE records fail explicitly. FULL pointers carry no inherited repository namespace, so opaque locators cannot borrow its account/container context. FULL unpresigned metadata needs no adapter lookup; relative addresses retain adapter namespace formatting, including the configured local root.
- Link remains metadata-only. Stage retains native syntax/capability checks. Known home aliases preserve managed-link signatures while retaining FULL addresses and alias IDs. Imports use each source's capability and walker, persist bindings through normal/skipped entries and temporary serialization, and check overlap using physical ownership.
- Allocations, uploads, multipart destinations, metadata and GC files stay home-bound. Physical cross-ID copy remains unsupported. Supported physical copies clear source bindings on the new managed destination.
- UI listings fetch metadata without presigning; object views, diff sides, CLI and Python readers choose capabilities per object. Markdown image and complex bulk paths can use server proxying. Explicit presign choices are preserved; writers remain home-bound. CLI staging/import expose `--storage-id`; Python import exposes `storage_id`.
- Export captures records into a temporary spool, rejects unrepresentable bindings before publishing anything, and publishes the same records. Manifest grouping handles parent entries interleaved with subdirectories. Temporary files and readers are cleaned up on failures/cancellation. Storage failures during publication do not have an atomic multi-manifest guarantee.

## Credential-selection authorization contract

The implemented contract preserves existing authorization:

| Operation | Authorization boundary |
| --- | --- |
| Link and Stage | `WriteObject` on the destination object |
| Import | Branch write/commit, destination writes, and `ImportFromStorage` on each source URI |
| Read, properties and presign | Existing read permissions on the logical object |

There is no additional caller-to-storage-ID or repository-to-storage-ID allowlist. Therefore an authorized writer can select any configured backend and reference data accessible through that backend's credentials. Subsequent logical read permission grants access to the referenced data. Import permissions cannot distinguish identical native URIs on two different backend IDs. Configured-ID validation and managed signatures do not impose a credential-selection policy.

`controller_binding_authorization_test.go` records the permission trees for multiple IDs, checks URI collisions, and proves denials happen before catalog/configuration/storage access. Successful dispatch is covered separately by authenticated API fixtures. These tests expose the implemented authority; they do not establish that a deployment has accepted it.

**Production gate:** the operator must explicitly accept this shared authority for every selectable backend, or supply and enforce a narrower caller/repository selection policy before deployment. The implementation approval did not answer that deployment-policy choice. No inferred acceptance or new authorization configuration is claimed.

## Physical ownership and GC

Ownership uses a snapshot of nonsecret configuration, independently of live credential success. It distinguishes known home ownership, known external ownership and unknown ownership. GCS compares its native service/bucket/key; Azure uses the configured cloud/domain or test endpoint plus URI account/container/key. S3 compares normalized explicit endpoints or recognized AWS partitions. Explicit S3 `endpoint`/`pre_signed_endpoint` pairs declare equivalent access paths and are joined transitively across configured IDs. Unrelated configured endpoints remain separate; arbitrary DNS aliases and credential-selected namespaces cannot be inferred. Default IPv6 ports preserve address brackets, and Azure account hostnames are compared without case sensitivity.

For S3 without an explicit endpoint, SDK endpoint environment variables, profile/file settings or the presence of default shared configuration/credential files make cross-ID comparison unknown. The snapshot checks presence only and does not read credentials. Explicit endpoints or `AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true` allow the supported comparison; unknown regions/partitions remain conservative. Same-ID operations retain their existing context. Use explicit endpoints for deployments whose SDK profile can select a custom service. Credential expiry alone does not change classification.

This affects ordinary AWS configurations too: even a default shared profile file containing only region/credential settings makes cross-ID ownership unknown when no explicit endpoint is supplied. Affected alias imports and GC preparation then fail, while same-ID operations keep their existing context. Configure an explicit, correct endpoint for each compared source, or use the existing SDK ignore-endpoint setting with a known configured region when appropriate for the deployment. Removing credential files is not required or recommended. The comparator does not inspect profile contents or resolve credentials to guess an endpoint.

Ownership follows the selected adapter's interpretation. S3 reads accept recognized alternate URI schemes and extract the same bucket/key; those addresses therefore remain S3 ownership references and still require managed signatures. GS and Azure preserve their native scheme checks. Link remains metadata-only, and opaque locators may be saved but must fail physical access if they cannot be interpreted independently. Declared presigning endpoints must actually address the same physical objects as their paired data endpoints.

Uncommitted preparation emits only owned addresses and fails on unknown ownership, including foreign RELATIVE records. A regression test obtains a successful first page and then encounters unknown ownership on continuation. The failed page does not publish a usable continuation result.

**Production gate:** the deployed collector must invalidate the entire affected repository run after any later-page failure, preventing all sweeps dependent on its incomplete preparation. Earlier successful pages are not permission to sweep. Verify committed retention, dry-run and actual deletion, including home aliases, foreign references and independent valid repository runs. The private collector is unavailable in this checkout; local preparation tests cannot certify its completion or sweep logic. No new collector coordinator was invented.

References in other repositories do not provide global retention protection for bytes owned by a source repository. Keep the source lifecycle contract, stable backend IDs and their configuration mapping in backups. An ID referenced only by entries/history is still in use even when no repository uses it as home.

## Local acceptance evidence

| Area | Evidence and limits |
| --- | --- |
| REST source dispatch | Same URI on separate memory stores and two independent HTTP S3 endpoints; GET/range, native properties, S3 signing credential/endpoint selection, home-bound allocation; metadata-only Link/stat has no object-store calls |
| Native providers | S3-home/GCS-source and GCS-home/S3-source GET/range/properties; GCS alias managed-signature rejection and successful signed-address link; Azure SharedKey GET/range/properties and SAS endpoint/permissions |
| GCS fixture limit | Uses the existing emulator endpoint and disables presign. It does not verify independent real GCS credential authorization or successful GCS signing |
| Persistence/history | ID-only relink commits; actual Catalog divergent merge and revert retain bindings and historical references; legacy hash compatibility and optional-field separation; metadata representation preserved |
| Import | Normal and skipped WriteRange entries, temporary serialization, and an actual two-source import with object/prefix inputs, committed reads and paginated listing; source import capabilities work even when home does not support import |
| Restore | Actual API dump/restore after copying managed data and committed metadata to a different home ID/namespace; empty RELATIVE entries relocate and explicit FULL addresses/IDs remain unchanged |
| Logical views | Source bytes survive logical deletion; Actions uses source bindings; physical copy clears supported managed destinations and rejects cross-ID copying |
| Ownership | GCS/Azure/S3 alias/endpoint/partition comparisons, local absolute-URI compatibility, immutable configuration snapshot, conservative SDK endpoint ambiguity, foreign relative rejection and later GC-page failure |
| Export | Unsupported later entry gives zero writes; publication uses captured records despite changes to the live selection; malformed capture and cancellation give zero writes; interleaved parent directories retain all addresses |
| Metadata compatibility | Removed saved source configuration still permits unpresigned FULL stat/list; common prefixes omit IDs; local RELATIVE stat/list/export retain configured base directories |
| Clients | Gateway native/legacy/foreign-relative coverage; CLI per-source and explicit signing; UI diffs, Markdown and import selection; Python automatic/explicit read signing and home-bound writers |

Provider fixtures use native adapters and SDKs against local HTTP services. They do not replace authorized small live-provider checks for real signature verification, credentials, IAM behavior or provider-specific import pagination. Cross-provider import plus server restart against persistent infrastructure remains a deployment acceptance exercise; local serialization/history/restore checks are complementary evidence.

## Validation commands and results

- Focused Go block, API, catalog, gateway, CLI, helpers and local suites pass. Catalog binding/ownership/history tests and the new API acceptance tests also pass with the race detector. The final full API suite passed after the local-address formatting correction (40.169s); focused API race tests passed (10.254s).
- UI: 90 unit tests, lint and production build pass after the mixed-listing regression fix. Repository format check reports the pre-existing `src/pages/repositories/index.test.jsx` formatting issue.
- Python wrapper: 63 unit tests pass against the regenerated SDK. Changed wrapper modules pass pylint and focused mypy with SDK imports skipped; full mypy traverses existing generated-SDK typing errors.
- Pinned client generation succeeds. Regenerating Go protobuf/API/wrappers and all three SDKs produces byte-identical artifacts.
- `make lint` / `make -k checks-validator` report 19 existing Go lint errors (18 `err113` in auth/authentication/httputil and one `gocyclo` in `auth_middleware.go`), the existing UI format issue, and expected comparisons of modified generated files against Git HEAD. Mockgen, permissions and wrapper validators pass. Generated SDK whitespace follows pinned generator templates; source-owned diffs pass whitespace checks.
- Plain `make fast-test` reaches the existing `TestInstrumentation` assumption that the process is outside Docker. A broader run uses the existing `auth.DockeEnvExists` test hook and clears `KUBERNETES_SERVICE_HOST` for deterministic environment detection. That full short suite passed across 68 tested packages; the final API suite was rerun after the local-address formatting correction.

The broad command using the repository's existing instrumentation test hook was:

```sh
env -u KUBERNETES_SERVICE_HOST GOMAXPROCS=4 go test -p 2 -count=1 -short -cover \
  -ldflags='-X github.com/treeverse/lakefs/pkg/auth.DockeEnvExists=/tmp/lakefs-msb-no-docker-marker' ./...
```

The marker path must not exist; this only supplies the outside-Docker initial condition assumed by `TestInstrumentation`, which then exercises its own Docker/Kubernetes transitions. No tests were removed or skipped to obtain this result (the normal `-short` suite exclusions still apply).

## Independent review corrections

The seven reported implementation findings were confirmed and corrected. These changes do not constitute independent merge approval or production release acceptance.

| Finding | Correction and regression evidence |
| --- | --- |
| P1: configured endpoint aliases | Ownership joins explicitly declared data/presign endpoints, including reverse/shared/transitive aliases. Import overlap and GC Parquet tests retain managed bytes. API tests reject unsigned alias links and accept correctly signed links without storage calls. |
| P1: S3 locator/ownership mismatch | Ownership uses the selected S3 adapter's bucket/key semantics. Signature and retention tests cover `gs://`/`https://` locators; API tests also cover the same-ID form of the bypass. |
| P1: legacy single-store fallback | Legacy mode retains the existing routing layer with the empty ID as its sole configured key. Unknown IDs fail before native credentials are used. Tests cover object operations, both multipart-copy variants, native S3 GET/range/properties/presign/copy, readable FULL metadata, and continued legacy-empty-ID access. Native type/runtime-stat reporting is preserved. |
| P2: UI list presigning | Main listings never presign the whole result set. A component test rejects such requests and verifies mixed rows still render, signed home downloads still sign, and unsigned source downloads use proxy URLs. |
| P2: gateway Range error overwrite | Pointer errors and range errors are separate. Multi-range/malformed/unsupported-unit requests retain full-body 200 fallback; valid ranges return 206; unsatisfiable ranges return 416 without accessing storage. |
| P2: foreign Azure namespace inheritance | FULL pointers omit repository namespace context. Native Azure tests save opaque metadata but reject its GET/presign without storage calls, then verify a valid FULL reference still reads. This also prevents same-ID opaque FULL references from borrowing home context. |
| P2: IPv6/Azure canonicalization | Default ports retain IPv6 brackets and Azure account hostnames are lowercased. Ownership and GC retention regression cases cover both. |

Review-round focused tests passed for native API boundaries, block/configuration, gateway and catalog. Race tests passed for ownership/GC and the legacy/native/gateway boundary regressions. UI tests, lint and production build passed. The full short Go suite passed again across 68 tested packages using the documented instrumentation environment hook. Final `make lint` still reports exactly the same 19 baseline Go issues; source formatting and whitespace checks pass. No OpenAPI/protobuf/client generation sources changed in this correction round, so previous generation reproducibility evidence remains applicable.

## Release and rollback

Ship compatible servers, clients and collectors together before creating overrides. Older readers may ignore the field and select the wrong credentials; old writers may drop it. The Spark schema mirror alone does not certify Spark/Hadoop/MSB consumers. URI-only exports reject nonhome bindings because the existing format cannot describe them.

Rollback requires removing or migrating incompatible references before reverting binaries. Restoring refs preserves raw saved IDs; `--ignore-storage-id` changes repository creation, not explicit entry bindings. Stable backend IDs and physical meaning are operational requirements. Production remains gated on the credential-selection decision, deployed collector verification and outstanding live-provider/persistent-infrastructure acceptance.
