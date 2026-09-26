**Mixed-backend logical views: feasibility review — 26 September 2026**

Historical review, before implementation. The subsequent [accepted design](../accepted/mixed-backend-logical-views.md) and [implementation record](msb-per-object-storage-validation.md) track the agreed rules and current evidence.

Recommendation: proceed with the existing native MSB adapters after tightening the contracts below. The supplied plan is feasible for versioned, mixed-backend references and reads. It deliberately keeps new uploads on the repository home backend and does not implement physical transfer between backends. This is a cross-cutting catalog and client feature, despite the small API addition.

Reviewed the supplied revised plan against local lakeFS `development` at `b7fdfa20f15eec07645773a384db6a4fd4b3120d`, s3-proxy at `91139410df6fc1c90c0ebe0255ead7bb954ccab8`, and OpenDAL at `53610f898eb07e38803614ea6aa7cb20bcd0ddd3`. The lakeFS baseline exactly matches the plan. This document records source inspection; no application changes, provider experiments, or automated tests were performed.

Updated after reviewing the supplied comments. The attached `backend.rs`, `lib.rs`, and `manager.go` match the corresponding local reference files. The preferred persistence contract below revises the original plan's recommendation to materialize IDs on home-managed relative entries. It is a design recommendation; the four proposed API schema additions remain unchanged.

**The foundation is already present.**

[MSB dispatch](../../pkg/block/multi/adapter.go) selects a configured adapter from `ObjectPointer.StorageID` and selects walkers by ID. FULL addresses resolve without using the repository namespace in [the common resolver](../../pkg/block/namespace.go). Therefore native S3 sources in a GCS-home repository, and native GCS sources in an S3-home repository, fit the existing abstraction. No OpenDAL dependency, proxy service, address inference, or new credential database is needed.

The plan correctly identifies the persistence requirements: protobuf tag 8 is free in [catalog.proto](../../pkg/catalog/catalog.proto), and [EntryToValue](../../pkg/catalog/entry.go) serializes the entry into `graveler.Value.Data`. Including nonempty storage IDs in identity is essential: [commit.go](../../pkg/graveler/committed/commit.go), line 155, retains the base value when identities match. The proposed named map contribution uses distinct typed framing in [ident.go](../../pkg/ident/ident.go), preserving legacy hashes when omitted. Updating both walker conversion and the separate skipped-entry conversion is also necessary.

Keep backend selection, address interpretation, and physical ownership separate. A selected credential set does not establish which repository owns the bytes. Preserve the plan's FULL-address requirement for foreign bindings, home-bound allocation, metadata-only Link behavior, and catalog-only REST HEAD.

The public [MSB documentation](https://docs.lakefs.io/admin/multiple-storage-backends/) describes repository-level backend binding and importing through the repository backend's credentials. It also excludes Spark GC, Spark client, and Hadoop FileSystem support. This proposal extends that public contract; these sources do not establish parity with a private Enterprise implementation.

**Changes recommended before implementation, in priority order.**

1. **Make credential-selection authority an explicit deployment contract.**

   [LinkPhysicalAddress](../../pkg/api/controller.go), line 946, and StageObject, line 3727, authorize `WriteObject` on the destination. They do not authorize access to a source credential set. ImportStart, line 3266, authorizes the source URI, but [StorageNamespace](../../pkg/permissions/permission.go), line 34, does not encode the storage ID. Two services with the same bucket/key therefore have the same source permission resource.

   Under the proposed unchanged authorization policy, a user with write/read access to one repository could stage a known address through another configured backend and subsequently read it using that backend's credentials. Existing destination checks and configured-ID validation do not prevent this. This is a concrete expansion of the authority available to repository writers, even though the permission names stay unchanged.

   A shared trust boundary must explicitly mean that authorized writers may reference data accessible through every selectable backend; sharing one lakeFS installation is insufficient. Document and test that contract, or add a server-enforced restriction on which source IDs a caller or destination repository may select. Reusing URI-only import authorization would not distinguish colliding S3 endpoints. Source-selection authorization is independent of staging validation and does not require remote HEAD, existence, or checksum checks. This remains a deployment-policy decision, not an implementation change made by this review.

2. **Specify three ownership outcomes and the entire GC run's failure behavior.**

   Use `home-owned`, `known external`, and `unknown`, rather than a boolean that can quietly classify missing configuration as external. A removed ID might have been an alternate credential binding for home-owned bytes. Ignoring that reference could remove retention protection.

   Current [uncommitted GC](../../pkg/catalog/gc_write_uncommitted.go), line 110, uses address type and a textual namespace prefix. The [Catalog struct](../../pkg/catalog/catalog.go), line 240, does not retain the storage registry. Supply immutable physical-service comparison context to catalog admission and GC; do not make ownership depend on live adapter calls. Define normalization cases explicitly: credential-independent GCS service/bucket, Azure account plus effective cloud/domain/container, and S3 service/endpoint namespace plus bucket. Preserve AWS partition distinctions while ignoring ordinary within-partition credential and region differences. Use the endpoint the selected adapter actually targets; Azure's client builds it from configured domain in [client_cache.go](../../pkg/block/azure/client_cache.go), line 123.

   Existing configuration has no general service-alias identifier. Without expanding configuration, only supported provider identities and known equivalent endpoint forms can be recognized. Undeclared aliases and credential-selected namespaces remain deployment limitations, as the plan already notes.

   Unknown ownership must invalidate the affected repository's collection run while stat/list can still return stored metadata. Independent collection runs for other repositories need not stop. Expired credentials or unavailable storage do not themselves make physical ownership unknown: comparison uses local configuration, not successful network access.

   PrepareGCUncommitted already returns before publishing the current page on an error ([catalog.go](../../pkg/catalog/catalog.go), line 3030). The deployed collector must also abandon that repository's entire run if any later page fails; earlier pages cannot authorize a partial sweep. Verify its existing completion/error handling before introducing any new run-management machinery. The unavailable committed collector remains a release dependency: require its binding-aware retention and deletion verification before enabling collection over the new entries.

3. **Let home-managed relative entries inherit their repository home.**

   The plan's dump/restore acceptance criterion needs a destination-binding condition. Bare-repository creation explicitly supports copying `_lakefs/` and restoring refs ([controller.go](../../pkg/api/controller.go), line 2349). [RestoreRepositorySubmit](../../pkg/catalog/catalog.go), line 2192, checks for a bare repository and loads refs; it does not rewrite object bindings. The [restore script](../../scripts/refs/lakefs-refs.py), line 273, can omit the repository storage ID but does not alter entries inside ranges.

   Example: a new entry stores `storage_id=A` and relative address `data/x`. Restoring its ranges into a repository whose home is B leaves A on the entry, while relative-address expansion uses B's namespace. That violates the proposed rule that a foreign binding must use a FULL address.

   Prefer the comments' simplification: persist an empty ID on newly created home-managed RELATIVE entries and return the effective home ID in API responses. Apply this only after resolving and validating the requested ID and deciding the address type. The selected backend must equal the resolved repository home ID, and existing managed-prefix normalization must produce RELATIVE. An explicit home ID returned by staging GET and sent back must still normalize to empty stored ID. Apply the same binding rule to Link and Stage while preserving their different signature requirements.

   | Entry case | Persisted binding | API response |
   | --- | --- | --- |
   | New home-managed RELATIVE entry | Empty ID; inherit repository home | Effective home ID |
   | New FULL reference in MSB, including one selected through the home ID | Explicit effective source ID | That saved ID |
   | Known home-owned bytes selected through a different credential ID | FULL address plus selected ID; retain ownership/signature rules | That saved ID |
   | Existing entry changed only through metadata update | Preserve the stored ID and address type | Effective ID |

   Single-store empty-ID behavior and legacy FULL entries with absent IDs remain supported without backfill. Never clear an alias ID merely because its physical ownership is home-owned: the selected credentials still matter. Imports remain FULL with an explicit effective ID in MSB. Uploads, multipart completions, and physical copies to new managed home-relative addresses persist empty IDs; a physical copy must clear any copied source ID. Shallow copies retain the existing binding.

   This preserves ordinary managed-data relocation semantics, provided the existing data and metadata relocation requirements are met. It does not migrate explicit FULL references or their configuration mappings. Legacy FULL entries with absent IDs retain their existing fallback semantics. When transferring a legacy or inherited reference into another repository through link/import, first expand the address using the source repository namespace and materialize its effective source ID; otherwise the destination would reinterpret it.

   Empty home-relative IDs preserve the existing hash contribution and avoid a one-time change caused solely by materializing the home ID. Explicit FULL binding changes must still affect identity; newly materialized legacy FULL references can still produce the documented one-time change. Keep stored IDs separate from effective IDs in response construction so a metadata-only update does not inadvertently persist the response's effective ID.

   If materialized home-relative IDs are retained instead, the earlier same-home-ID restore restriction remains necessary. A different-home restore must reject incompatible materialized relative entries or use a separate migration; rewriting IDs can require rebuilding ranges and commit history. `--ignore-storage-id` alone cannot perform that migration. Under the preferred contract, test managed relative relocation and preservation of explicit FULL bindings separately.

4. **Extend the audit beyond REST and S3 gateway readers.**

   [ActionsSource.load](../../pkg/catalog/actions_source.go), line 98, reads a catalog entry using the repository ID and hardcoded `IdentifierTypeRelative`. It must use the effective entry ID and stored address type for linked/imported action files. Add an action-file regression case to the server read matrix.

   [CreateSymlinkFile](../../pkg/api/controller.go), line 4671, emits native URI strings alone. Its manifest cannot distinguish two configured S3 services containing `s3://bucket/key`. Updating dispatch cannot recover that missing information for a downstream client. The endpoint publishes incrementally at line 4683, so validating each entry immediately before writing is insufficient: a later unsupported binding can leave earlier manifests published.

   Validate the complete export selection before the first manifest write. Validation and publication must use the same selected records; do not validate a mutable branch and then independently reread it. A bounded temporary spool is one option if no suitable immutable view is available. This prevents partial publication caused by unsupported bindings; it does not promise atomic multi-object publication under arbitrary storage failures. A richer manifest format and compatible consumers can remain separate work.

5. **Select client read capabilities per object and version.**

   The plan's UI/CLI/Python work is necessary, with several concrete implementation traps:

   - [ObjectsDiff](../../webui/src/lib/components/repository/objectsDiff.jsx), lines 35 and 154, uses one repository signing configuration for both versions. An ID-only relink can put the two versions on different backends. Reuse the stats already fetched at lines 47 and 48 to select each side's `(repository, ref, path)` read context.
   - [Markdown image resolution](../../webui/src/lib/remark-plugins/imageUriReplacer.ts), lines 42 and 54, shares the document's signing choice with its images, including links into another repository. Existing proxied image URLs are the simplest initial choice; per-image signing can use each image's own source context when needed.
   - [Python LakeFSIOBase](../../clients/python-wrapper/lakefs/object.py), line 62, eagerly chooses `_pre_sign` from the repository. Updating only the reader's lazy getter at line 210 is insufficient. Move automatic read selection to the reader boundary while keeping writer behavior home-bound.

   Existing server-proxied reads are a practical initial fallback for complex read surfaces. Explicit presigning must still honor the selected adapter and its native errors. A capability flag is not proof that credentials can sign successfully. Legacy clients remain useful for home-bound writes and server-routed reads, but workflows that round-trip only a physical URI cannot preserve a foreign binding.

6. **State copy and rollout limits in user-visible terms.**

   [normalizeCopyTargets](../../pkg/block/multi/adapter.go), line 80, rejects different IDs for physical copy and both multipart-copy variants. After source dispatch is corrected, copying a foreign entry to the home backend can therefore be unsupported even within one logical repository. Existing [shallow clone](../../pkg/catalog/catalog.go), line 3068, is limited to the same repository and branch. Cross-repository logical views in this feature come from linking/importing the same source, not an expanded shallow-copy API. Ordinary overwrite can create a new home-owned object.

   Preserve these restrictions explicitly, including native `UploadPartCopy`; streaming cross-provider transfer needs separate lifecycle, retry, and checksum design. An additive protobuf field is not semantic compatibility with older readers or collectors. Use a coordinated cutover, or a deliberate enablement gate, so all participating readers/writers/collectors understand bindings before overrides are persisted. Reverting a binary is not a safe rollback once incompatible references exist.

**What the local reference implementations establish.**

| Local implementation | Relevant evidence | Implication for lakeFS |
| --- | --- | --- |
| s3-proxy `pkg/s3-proxy/s3client/manager.go`, lines 24 and 69 | Client lookup uses a target name; construction binds target credentials, endpoint, region, and path style. | Reuse configured clients by stable ID. Identical URI text need not identify the same service. This implementation does not establish native GCS/Azure or catalog/GC behavior. |
| OpenDAL `core/services/s3/src/backend.rs`, lines 943, 955, and 1044 | Endpoint, credential providers, and operation capabilities belong to a configured service instance. | Preserve native adapters and select capabilities with the source binding. Provider name alone is insufficient. |
| OpenDAL `core/layers/route/src/lib.rs`, lines 32 and 250 | Glob routing is first-match, has a default, and keeps wrapped-operator capabilities. Copy selects the source route and does not transfer between route targets. | Do not introduce path routing for committed bindings or infer cross-backend copy support from routing. |
| OpenDAL `SECURITY-THREAT-MODEL.md`, lines 74 and 270 | End-user authorization belongs to the host application; operator calls share that operator's authority. | Adapter selection is not a substitute for lakeFS source-selection authorization. |

Neither reference implementation supplies a universal physical-ownership comparator or repository retention semantics. Their useful contribution is the configured-client boundary that lakeFS MSB already has.

**Recommended execution and evidence.**

Add a step before the plan's four implementation steps to settle the credential-selection trust scope, supported ownership normalization, inherited-home persistence contract, and deployed collector integration. Update the plan's entry creation, physical-copy reset, identity, and restore acceptance rules consistently with the preferred persistence contract above. Keep the four code steps as reviewable changes, but enable the complete feature together.

Retain the proposed acceptance matrix and add: foreign action-file reads; both diff versions and Markdown images with different signing capabilities; Python automatic reader initialization; a late unsupported export entry causing zero manifest writes; and GC failure after an earlier successful page preventing sweep for that repository while independent runs can continue. For inherited-home entries, test staging GET/Link ID round-trip, unchanged home-relative hashes, reset after physical copy, managed relative relocation to another home, and unchanged explicit FULL bindings after restore. Exercise credential-selection permissions according to the chosen trust contract. Verify unknown request IDs fail immediately while missing saved source configuration leaves unpresigned metadata readable.

Use recording adapters for deterministic dispatch assertions and two independent S3 services for identical bucket/key tests. Native GCS/Azure credential and signing claims still require authorized real-provider checks; emulator success is insufficient. Validate the deployed collector's complete prepare/retain/delete flow. No such checks have been run in this review.

The likely engineering cost lies in complete propagation, ownership, compatibility, and client behavior. Adapter selection itself remains a local lookup. Server-proxied cross-cloud reads also retain their network latency and egress implications. The architecture is suitable once these contracts and release gates are made concrete.
