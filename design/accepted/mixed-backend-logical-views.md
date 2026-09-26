# Mixed-backend logical views

Accepted 26 September 2026. The original plan recorded design review only; implementation and validation are tracked in [the implementation record](../open/msb-per-object-storage-validation.md).

**Decision**

Keep MSB and its existing native adapters. Add an optional per-object `storage_id` to API inputs/responses and catalog entries. The saved ID selects an existing configured adapter directly; an absent ID uses the repository’s backend. This is an explicit fork API and catalog-format extension.

A repository retains its home backend and namespace for uploads, metadata and GC. Entries can reference objects on other configured backends under arbitrary logical paths. Native S3 ↔ GCS is required in both directions; Azure uses its native adapter and address format. Repository listing remains a versioned catalog view, not a live union of bucket listings.

Keep `blockstores.stores[]`, startup configuration, credential providers and repository creation unchanged. Backend credentials remain inside their existing adapter. No database of credentials, backend CRUD, proxy service or OpenDAL replacement is needed.

| Logical path | Stored FULL address | Stored source ID |
| --- | --- | --- |
| `research/main/video.m2ts` | `s3://raw/capture-123` | `ecs-b` |
| `research/main/metadata.json` | `gs://source-metadata/123.json` | `gcs-research` |
| `review/main/renamed-video.m2ts` | `s3://raw/capture-123` | `ecs-b` |

The video entries reference the same bytes. Endpoint and credentials come from the `ecs-b` configuration. ObjectScale namespaces can therefore remain in configured endpoints such as `https://namespaceUuid.objectscale.example.com`; they need not be encoded into every S3 URI. Two different GCS credential configurations can likewise be selected without changing `gs://bucket/key`.

The [official MSB documentation](https://docs.lakefs.io/admin/multiple-storage-backends/) describes repository backend bindings and an import prerequisite using that backend’s credentials. Explicit per-source/per-object selection extends that public contract. Do not claim private Enterprise implementation parity.

**1. Minimal API extension**

Add optional string fields to four existing schemas in [api/swagger.yml](../../api/swagger.yml), then regenerate server models and generated clients.

| Schema/surface | Change and meaning |
| --- | --- |
| `StagingLocation.storage_id` | GET staging/backing returns the allocation’s effective home ID. PUT link consumes `staging.storage_id`. |
| `ObjectStageCreation.storage_id` | Optional source ID for the separate StageObject operation. |
| `ImportLocation.storage_id` | Optional ID on each source in `paths[]`; one import can combine providers. |
| `ObjectStats.storage_id` | Effective entry backend in object responses, including stat/list, link/stage, upload, multipart completion and copy. Omit for common-prefix rows. |

Omitted or empty input means repository backend. An explicit ID must name a configured backend; unknown IDs return the existing invalid-storage/configuration error mapping and never fall back. Preserve legacy single-store and backward-compatible repository-ID resolution.

Example link request:

```json
{
  "staging": {
    "physical_address": "s3://raw/capture-123",
    "storage_id": "ecs-b"
  },
  "checksum": "13ded84af8a579fe1af6cc12f7d8475c",
  "size_bytes": 25,
  "content_type": "text/plain",
  "force": false
}
```

Example import sources inside the existing request:

```json
{
  "paths": [
    {
      "type": "common_prefix",
      "path": "s3://raw/video/",
      "destination": "video/",
      "storage_id": "ecs-b"
    },
    {
      "type": "object",
      "path": "gs://source-metadata/123.json",
      "destination": "metadata.json",
      "storage_id": "gcs-research"
    }
  ],
  "commit": { "message": "Import mixed sources" }
}
```

**Staging GET stays home-bound.** It allocates a new managed address on the repository backend and returns that ID. Do not add a foreign `storage_id` query selector in this feature: allocation elsewhere also needs a target bucket/prefix and lifecycle contract. `default_namespace_prefix` remains a UI hint, not an allocation root. Existing objects elsewhere are linked through PUT or imported.

No data GET/stat/presign selector is needed: those operations use the saved entry ID. Do not add new headers or endpoints.

Keep existing presign meanings:

- Staging GET with presigning supplies a native physical address plus a separate URL for uploading with HTTP PUT.
- Staging PUT links metadata. Its existing `presigned_url` and expiry fields remain unused by the link handler; do not repurpose them.
- Object stat with `presign=true` returns a signed GET URL in `physical_address`, using the saved source ID. Without presigning it returns the native address. Both return the effective `storage_id`.

No new remote HEAD, existence or checksum verification is added to staging. Local configured-ID selection is required to interpret the extension. Existing checksum requirements and managed-link signature checks remain.

Credential-selection authority is a separate deployment contract. Keeping current staging authorization requires explicit acceptance that authorized writers may reference data accessible through every selectable backend. Sharing an installation alone does not establish that permission. Otherwise enforce caller/repository source-ID restrictions before exposing arbitrary overrides. Existing URI-only ImportFromStorage permissions do not distinguish identical bucket/key addresses on different services. Document and test the chosen access boundary; this does not require remote object validation.

**2. Catalog persistence and identity**

This is an additive serialized-entry change, not a new SQL column or side table. [catalog.proto](../../pkg/catalog/catalog.proto) entries are serialized into `graveler.Value.Data` for staging and committed ranges.

Add `string storage_id = 8` to Entry; fields 1–7 are occupied. Regenerate Go protobufs and update the [Spark schema mirror](../../clients/spark/src/main/resources/catalog.proto) with the same tag. Synchronizing its schema does not establish Spark/MSB support.

Carry the field through [model.go](../../pkg/catalog/model.go), DBEntry builders, `newEntryFromCatalogEntry`, `newCatalogEntryFromEntry`, entry creation and import conversion.

Persistence rules:

| Entry case | Stored binding |
| --- | --- |
| New home-managed RELATIVE object | Empty ID; inherit repository home |
| New FULL reference in MSB, including one selected through home | Explicit effective selected source ID |
| Home-owned bytes accessed through another credential ID | Explicit alias ID; retain FULL address |
| Metadata-only update | Preserve existing stored ID and address representation |
| Upload, multipart completion or supported physical copy creating a home-relative object | Empty ID; explicitly clear any copied source ID |
| Existing supported shallow copy | Preserve source representation and binding |

Resolve and locally validate a supplied ID before normalization. Clear it only when the selected backend equals the resolved repository home and existing managed-prefix normalization produces RELATIVE. Returning the effective home ID from staging GET/stat and sending it back through Link/Stage must still produce an empty stored ID for a home-relative entry. Preserve the APIs' different signature requirements. Never clear an alias ID merely because its bytes are physically home-owned.

Existing entries with no ID, including legacy FULL entries, keep repository-backend semantics without backfill. Legacy single-store empty-ID behavior remains valid. Keep stored and effective IDs distinct in model/response construction so formatting a response cannot materialize an ID during a metadata-only update. The field is system entry data, separate from customer metadata.

When referencing an inherited or legacy entry from another repository through link/import, expand its relative address in the source namespace and materialize its effective source ID before the destination can reinterpret it. Preserve current shallow-copy API restrictions; cross-repository views use link/import.

**Include binding changes in entry identity.** [EntryToValue](../../pkg/catalog/entry.go) currently hashes size, ETag, customer metadata and optional content type. [commit.go](../../pkg/graveler/committed/commit.go) retains the base entry when identities match. Without a hash change, an ID-only relink can disappear at commit.

For nonempty IDs, append a typed, named contribution, for example `MarshalStringMap({"storage_id": id})`, after the existing fields. Do not append an untagged optional string: it can collide with the existing optional content-type encoding. Empty IDs preserve the exact legacy hash.

Home-relative entries retain empty IDs and existing hashes, including when callers round-trip the effective home ID. Newly recreated legacy FULL references now receive explicit IDs in MSB and can produce a one-time binding change; metadata-only updates preserve the old representation. Leave physical-address-only equality semantics unchanged; a general redesign of content identity is outside this feature.

**3. Reuse dispatch and address boundaries**

Use one small effective-ID helper: explicit entry/request ID, otherwise the already resolved repository ID. Reuse `ResolveStoredRepositoryStorageID` and `ValidateObjectStorageID` from [storage_resolver.go](../../pkg/config/storage_resolver.go).

[ObjectPointer](../../pkg/block/adapter.go) already has StorageID. [multi/adapter.go](../../pkg/block/multi/adapter.go) already dispatches exactly by ID through `adapterForObject` and selects walkers through `GetWalker`. Reuse those methods, adapter construction, credential refresh and metrics wrappers. No new mandatory adapter interface or optional ObjectResolver layer.

| Operation | Backend/address context |
| --- | --- |
| Object GET/range, underlying-storage properties/existence and read presign | Effective entry ID and entry AddressType |
| REST object HEAD | Existing catalog-only response; no new storage request |
| Source listing/import | Effective per-source ID and native URI |
| Copy or multipart-copy source | Effective source entry ID and AddressType |
| Upload, upload presign and all multipart destinations | Repository home |
| Metadata, ranges/metaranges and GC metadata I/O | Repository home |
| Supported physical copy destination | Destination home; existing cross-storage restriction remains |
| Catalog deletion | Existing logical operation, without eager source deletion |

Audit REST, S3 gateway and internal catalog-entry readers together; passing repo.StorageID everywhere would defeat the new field. In particular, ActionsSource.load must use the effective entry ID and stored AddressType instead of hardcoded home/RELATIVE for linked/imported action files. Actions are catalog-referenced objects; range/metarange metadata stays home-bound. Do not globally replace repository context in metadata or write paths.

Home-managed entries remain RELATIVE with empty stored IDs where existing normalization produces that representation. Foreign-backend references must remain FULL, including when their bucket/key text happens to equal the home namespace. An ID supplies adapter selection, not a namespace for resolving relative keys. Reject a nonhome explicit ID paired with RELATIVE instead of combining that adapter with the destination home's namespace.

Keep native addresses: `s3://bucket/key`, `gs://bucket/key` and supported Azure URLs. Native SDK endpoint configuration and `force_path_style` determine outbound requests. This feature adds no S3 HTTP-address parser, namespace header injection or conversion to HTTPS on import. Dell endpoint layouts must work with the existing configured S3 adapter.

Unpresigned metadata formatting must not require a live adapter: retain FULL addresses as stored and expand RELATIVE addresses through the home namespace. Return the saved ID even if its configuration is missing; object access/presigning then fails explicitly. Removing one backend must not make an unrelated object’s catalog metadata unreadable.

**4. Imports and admission**

In [controller.go](../../pkg/api/controller.go), pass each `ImportLocation.storage_id` into `catalog.ImportPath.StorageID` and check that source backend’s existing import capability. Preserve existing ImportFromStorage and destination permissions.

In [catalog.go](../../pkg/catalog/catalog.go):

1. Add StorageID to ImportPath and internal WriteRangeRequest.
2. Select the native walker with the effective source ID.
3. Pass that ID as conversion context to [NewWalkEntryIterator/objectStoreEntryToEntryRecord](../../pkg/catalog/walk_entry_iterator.go).
4. Stamp the field in both ordinary entries and WriteRange’s separate skipped-entry conversion.

Keep Walker, ObjectStoreEntry, WalkerWrapper and native walker implementations unchanged. One selected walker supplies one source binding; no per-entry endpoint reconstruction or decorator is necessary.

Imports retain FULL addresses. Their existing temporary database/range serialization carries the new field. Preserve native keys, markers, ordering and continuation tokens. Range-ingestion callers repeat the same source ID and URI when continuing. There is no public WriteRange endpoint in these supplied API sources, and no new one is proposed. Current asynchronous import status is not a restartable source-job record; do not add such a subsystem.

Preserve API differences: Link remains metadata-only with its existing managed signature check; StageObject retains native syntax/type validation using the selected backend; Import retains overlap protection; WriteRange does not acquire Import’s overlap prohibition.

**5. Ownership and GC: retain the necessary check**

Backend selection and physical ownership are different. Two IDs may be separate credentials for the same GCS bucket or S3 service. Conversely, two S3 services can contain the same bucket/key text.

Use a small pure ownership comparison at existing admission/GC boundaries. It returns home-owned, known external or unknown from the already selected source/home configurations and native parsed locations; it never selects a backend. Inject immutable, non-secret physical-service comparison context into Catalog, which does not currently retain the storage registry. Use effective adapter configuration rather than live adapter calls. Compare physical service, bucket/container and existing namespace-prefix rules:

| Provider | Known physical context |
| --- | --- |
| GCS | Native GCS service and bucket, independent of credential identity |
| Azure | Native account, cloud/domain and container |
| S3 | Configured service/endpoint namespace and bucket; preserve AWS partitions, but do not split the same bucket merely by within-partition credential or region settings |

Use known configured aliases only; no DNS discovery, globs, credential probing or arbitrary URL routing. Different custom endpoints are distinct unless their equivalence is already represented by configuration. Implicit credential-selected ObjectScale namespaces and undeclared service aliases cannot be inferred; the proposed deployment uses explicit namespace endpoints. Document those limits rather than claiming universal physical identity detection.

Apply the comparison in three places:

- **Link normalization/signature:** only store RELATIVE when the selected backend is home. If another credential ID is known to address home-managed bytes, retain FULL plus that ID but still verify the existing link signature against the home-relative suffix. Stage does not gain a signature check.
- **Import overlap:** reject sources physically inside/containing the home namespace under the existing object/prefix rules. Identical bucket/prefix text on a distinct S3 service is not self-import. Keep WriteRange’s current admission.
- **GC classification:** determine whether the entry refers to home-owned bytes before applying existing retention/prefix logic. Keep known home aliases in retention accounting; exclude actual foreign objects even when URI strings match home. FULL entries inside the home namespace outside the managed data subtree retain their existing ownership treatment.

Update [gc_write_uncommitted.go](../../pkg/catalog/gc_write_uncommitted.go) at its existing classifier. Eligible records can still be emitted as home-relative physical addresses; GC inventory/manifests and deletion remain home-bound. Do not use a blanket “different ID means external” test or treat every FULL entry as external.

Unknown ownership invalidates the affected repository's entire collection run. No deletion set may be published or consumed from incomplete retention inputs, including previously successful prepare pages. Independent repository runs may continue. A missing configuration cannot silently become external if it might describe home-owned bytes. Unknown means insufficient information to establish physical ownership; credential expiry or storage unavailability alone does not make it unknown. No network probes belong in this comparison.

Committed collectors must interpret the new field and equivalent ownership rules too. The proprietary collector is absent from the supplied sources, and [official MSB documentation](https://docs.lakefs.io/admin/multiple-storage-backends/) excludes Spark GC. Verify its complete prepare/retain/delete flow and later-page error handling before enabling collection over new bindings. Reuse correct existing run-completion handling rather than automatically adding a new coordinator.

Keep repository-local retention. Referencing repo A’s managed object from repo B does not protect it from A’s GC. No global reference index, last-reference deletion or ownership transfer is added. Shared externally retained objects fit this model; their bytes can still change or disappear outside lakeFS.

**6. Bundled clients and capabilities**

Use the existing `storage_config_list` keyed by `ObjectStats.storage_id` for source capabilities. Upload capabilities remain home-bound.

- UI import adds an optional source backend selector and validates the URI with that selected backend’s existing native import regex. Object viewer/download uses the saved source ID for signing decisions. Diff views select signing independently for each version using their already fetched left/right stats. Markdown images use existing proxied URLs initially, or each image's own source context if signing is needed; include repo/ref/path context in image-processing dependencies so identical text at another ref does not retain stale URLs.
- lakectl exposes source selection on existing link/stage/import commands as applicable. Its stage command's existing raw namespace-prefix rejection must account for explicit source IDs or defer those cases to server ownership checks; it must not block an identical bucket/prefix on another service. Reads/stat/presign use per-object source capabilities. Bulk clone/sync must separate read choices from its shared upload Presign flag or use existing proxied reads.
- Python’s ObjectInfo carries the optional field. LakeFSIOBase must preserve the caller's None/explicit presign choice instead of eagerly selecting home capabilities; ObjectReader then chooses from the actual entry. Writer behavior, including Azure upload headers, continues using home context. Do not globally change shared StoredObject backend selection. Add optional `storage_id` arguments to ImportManager.prefix() and .object() and forward them to ImportLocation; generated models alone do not expose selection in the high-level wrapper.

Regenerate low-level SDKs from the schema. No global capability intersection, union import regex or extra config API fields are needed. Explicit presign uses the source’s native behavior/errors; automatic reads may use existing server-proxied access when signing is unavailable.

Release coverage includes REST, S3 gateway, UI, lakectl and Python. Direct filesystem/Spark/symlink consumers use their own clients and do not automatically inherit server dispatch. Keep existing support limits; a protobuf update alone does not certify them.

URI-only symlink exports cannot encode a backend binding. Reject selected bindings that the existing format/consumer cannot represent. Capture the selected records once, validate every record before the first manifest write, then generate manifests from those same captured records. Use a suitable immutable view or bounded temporary spool; do not independently reread a mutable branch after validation. This prevents partial publication caused by a later unsupported entry, without promising atomic multi-object writes under arbitrary storage failures. A richer manifest format and consumers remain separate work.

Physical copy and both multipart-copy variants retain concrete-ID restrictions, even when both logical paths are in the same repository. Same-repository/branch shallow-copy limits remain. Linking/importing creates cross-repository views; ordinary overwrite creates a new home-managed object.

**7. Implementation sequence and acceptance**

Source baseline: development `b7fdfa20f15eec07645773a384db6a4fd4b3120d`, compared with supplied upstream `24bfa90317e6e3ead13fb5cc8820f7c036baf088`.

| Step | Deliverable |
| --- | --- |
| 0 | Record credential-selection trust scope, supported physical identity cases and deployed collector integration; persistence rules above are settled |
| 1 | Optional schemas, catalog field/conversions, binding identity and legacy fallback |
| 2 | Entry-ID propagation through object reads/presign/copy sources; Link/Stage persistence and ownership checks |
| 3 | Both import paths, per-source capabilities, ownership/GC integration |
| 4 | Generated and bundled clients, documentation, complete integration gate |

Ship the complete feature together; persisting overrides before readers understand them is unsafe.

Acceptance must demonstrate:

1. S3 home ↔ native GCS source in both directions, plus Azure native references: link/import, commit/restart, GET/range, underlying properties and presign use the selected credentials. REST HEAD remains catalog-only.
2. Two S3 endpoints with identical bucket/key return their respective bytes. Two GCS credential configurations select deterministically without URI rewriting.
3. One source appears under different names in two repos; logical deletion leaves bytes intact. Owner-repo GC behavior remains as documented above.
4. Legacy absent IDs, single-store operation and compatible repository IDs retain default behavior. Unknown explicit IDs never fall back; adding unrelated backends never changes saved bindings.
5. Explicit FULL IDs survive normal/skipped import entries, pagination, commit/merge/revert, metadata updates and dump/restore. Logical references preserve effective source context; supported physical copies to managed home-relative addresses clear copied IDs. Metadata updates preserve stored representation.
6. ID-only relinking survives commit. Home-relative and legacy empty-ID hashes remain identical; staging GET/Link and Stage round-trips with explicit home IDs still store empty IDs. Optional-field encoding cannot collide; explicit materialization of legacy FULL bindings is covered.
7. Foreign equal-prefix S3 objects stay FULL and outside home GC, including through lakectl stage. Known same-store credential aliases retain managed signature/overlap/retention behavior; explicitly test two GCS credential IDs for the same home bucket/key. Include home FULL entries outside the data subtree.
8. Existing Link/Stage/Import/WriteRange admission differences remain; staging adds no remote validation. Test the explicitly selected credential-authority contract, including URI collisions across IDs; do not imply destination permission alone preserves backend isolation.
9. Uploads, multipart destinations, metadata and GC files remain home-bound. Cross-storage physical copy still reports unsupported; multipart-copy reads use the correct source AddressType.
10. Mixed signing capabilities work in bundled clients without changing upload behavior. Unpresigned metadata remains readable when a source configuration disappears.
11. The deployed collector’s dry-run/retention/deletion behavior accounts for the new binding and cannot sweep foreign objects or lose known home alias references. A later prepare page encountering unknown ownership prevents every sweep dependent on that repository's incomplete run; unrelated valid runs can continue. Credential expiry alone does not change ownership classification.
12. Linked/imported action files, each side of a diff, Markdown images and Python automatic reader initialization use the correct source context; explicit presign choices and home-bound writers retain their behavior.
13. A late unsupported export entry causes zero manifest writes. Concurrent branch changes between validation and publication cannot replace the captured records being exported.
14. Managed empty-ID RELATIVE entries relocate with repository home under existing data/metadata relocation requirements. Explicit FULL references retain their original IDs/addresses after restore. Nonhome-ID RELATIVE records fail explicitly rather than combining incompatible namespace/backend context.

Use existing adapter/API fixtures plus two independent S3 services and native GCS/Azure fixtures. Small authorized live-provider checks remain necessary for claimed real-provider signing/credential support. These are implementation gates, not tests already run.

**8. Compatibility, removed work and remaining limits**

Old clients can omit the new fields against an upgraded server. Old servers/readers/collectors are not safe for new overrides: ignoring or dropping the field can select the wrong backend. Upgrade participating components before creating these entries. Rollback requires removing/migrating incompatible references, not merely reverting a binary.

Raw restore preserves serialized entries. Empty home-relative bindings inherit the restored repository home, provided required data and metadata are relocated correctly. Explicit FULL bindings remain pinned to their original sources; legacy FULL entries with empty IDs retain existing home fallback. The restore script's --ignore-storage-id affects repository creation only and does not migrate explicit entry bindings. Rebinding existing explicit references is separate migration work and can change entry identities, ranges, metaranges and commit history. Reject incompatible materialized relative records at use/GC boundaries.

IDs and their physical meaning must remain stable. Credential rotation stays inside existing providers. Back up the configuration mapping with repository data. A backend may now be referenced only by entries/history, not by any repository’s home binding. Checking only repository home bindings is insufficient before removing a configured backend. Do not remove such configurations while those references are needed. No global dependency index or startup scan of every commit is proposed.

Removed from the original plan: hostname/path/glob matcher, provider-candidate inference, route cache/descriptors for selection, optional ObjectResolver interface, HTTPS canonicalization, walker decorator, union import hints and global signing intersection. Keep only the physical-ownership comparison required by signatures, import admission and GC.

Keep unrelated credential-flare redaction, backend-switch UI fixes and inherited multipart-origin issues in separate work. Per-user SAML/JWT attribute propagation, new AssumeRoleWithSAML machinery, foreign upload allocation and global GC reference counting remain outside this feature.

The useful lesson from [s3-proxy](../../../s3-proxy/pkg/s3-proxy/s3client/manager.go) and [OpenDAL](../../../opendal/core/services/s3/src/backend.rs) is to select a configured native client and retain its capabilities. Existing MSB already supplies that boundary; persisted IDs remove the need to infer selection from addresses.

This document preserves the accepted design. See the implementation record for tests actually run and remaining release gates. The private collector remains an explicit implementation dependency.
