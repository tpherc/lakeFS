package io.treeverse.gc

import java.io.InputStream
import java.security.MessageDigest
import java.time.Instant
import org.json4s._
import org.json4s.native.Serialization

case class GCTargetDescriptor(
    resolver_version: Int,
    provider: String,
    service: String,
    routes: Seq[String],
    namespace_prefix: String,
    bucket: String = "",
    account: String = "",
    container: String = ""
)

case class GCPart(location: String, size_bytes: Long, sha256: String, row_count: Long)

case class GCReferenceManifest(
    schema_version: Int,
    ownership_resolver_version: Int,
    scope: String,
    task_id: String,
    run_id: String,
    repository_id: String,
    repository_instance_uid: String,
    storage_id: String,
    storage_namespace: String,
    ownership_fingerprint: String,
    started_at: String,
    cutoff_time: String,
    minimum_age_seconds: Long,
    completed_at: String,
    expires_at: String,
    target: GCTargetDescriptor,
    parts: Seq[GCPart],
    total_rows: Long,
    source_count: Long,
    commit_count: Long,
    entry_count: Long
)

case class GCPreparedReferences(
    manifest_location: String,
    manifest_sha256: String,
    expires_at: String
)

case class GCCandidateManifest(
    schema_version: Int,
    mark_success: Boolean,
    run_id: String,
    references: GCReferenceManifest,
    reference_manifest: GCPreparedReferences,
    parts: Seq[GCPart],
    total_rows: Long,
    created_at: String
)

case class GCSweepReport(
    schema_version: Int,
    run_id: String,
    attempt_id: String,
    sweep_success: Boolean,
    attempted: Long,
    deleted: Long,
    already_absent: Long,
    failed: Long,
    started_at: String,
    completed_at: String,
    error: String,
    failures: Map[String, String] = Map.empty
)

object GCManifest {
  implicit private val formats: Formats = DefaultFormats
  val Version = 1
  val MaxParts = 20000
  val MaxManifestBytes = 16 * 1024 * 1024

  def encode[A <: AnyRef](value: A): Array[Byte] = {
    val bytes = Serialization.write(value).getBytes(java.nio.charset.StandardCharsets.UTF_8)
    require(bytes.length <= MaxManifestBytes, "GC manifest exceeds the size limit")
    bytes
  }

  def decode[A: Manifest](bytes: Array[Byte]): A = {
    require(bytes.length <= MaxManifestBytes, "GC manifest is too large")
    Serialization.read[A](new String(bytes, java.nio.charset.StandardCharsets.UTF_8))
  }

  def sha256(bytes: Array[Byte]): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))
  def hex(bytes: Array[Byte]): String = bytes.map(b => f"${b & 0xff}%02x").mkString

  def readBytes(in: InputStream, maxBytes: Int = MaxManifestBytes): Array[Byte] = {
    val out = new java.io.ByteArrayOutputStream()
    val buffer = new Array[Byte](65536)
    try {
      var n = in.read(buffer)
      while (n != -1) {
        require(out.size().toLong + n <= maxBytes, "GC manifest is too large")
        out.write(buffer, 0, n)
        n = in.read(buffer)
      }
      out.toByteArray
    } finally in.close()
  }

  def validateParts(parts: Seq[GCPart], totalRows: Long): Unit = {
    require(parts != null && parts.size <= MaxParts && totalRows >= 0,
            "Invalid or oversized GC part list"
           )
    require(parts.map(_.location).distinct.size == parts.size, "Duplicate GC part location")
    val rows = parts.foldLeft(0L) { (sum, part) =>
      require(part.location != null && part.location.nonEmpty, "Missing GC part location")
      require(part.size_bytes > 0 && part.row_count >= 0, "Invalid GC part size or count")
      require(part.sha256 != null && part.sha256.matches("[a-f0-9]{64}"), "Invalid GC part digest")
      Math.addExact(sum, part.row_count)
    }
    require(rows == totalRows, "GC manifest row count does not match its parts")
  }

  def validateReferences(m: GCReferenceManifest, repository: String, now: Instant): Unit = {
    require(m.schema_version == Version && m.ownership_resolver_version == Version,
            "Unsupported GC reference protocol"
           )
    require(m.scope == "installation", "GC references do not cover the installation")
    require(m.repository_id == repository && m.repository_instance_uid.nonEmpty,
            "GC reference repository does not match"
           )
    require(m.task_id.nonEmpty && m.task_id == m.run_id, "GC reference task does not match run")
    require(m.storage_namespace.nonEmpty && m.ownership_fingerprint.nonEmpty,
            "Missing GC target identity"
           )
    require(m.target != null && m.target.resolver_version == Version,
            "Unsupported GC target resolver"
           )
    require(m.minimum_age_seconds >= 0, "Invalid GC minimum age")
    val start = Instant.parse(m.started_at)
    require(Instant.parse(m.cutoff_time) == start.minusSeconds(m.minimum_age_seconds),
            "GC cutoff does not match the initial request time"
           )
    require(!Instant.parse(m.completed_at).isBefore(start), "Invalid GC completion time")
    require(now.isBefore(Instant.parse(m.expires_at)), "GC reference task has expired")
    require(m.source_count >= 1 && m.commit_count >= 0 && m.entry_count >= 0,
            "Invalid GC scan counts"
           )
    validateParts(m.parts, m.total_rows)
  }

  def validateRelativeKey(key: String): Unit = {
    require(key != null && key.nonEmpty, "GC key must not be null or empty")
    require(java.nio.charset.StandardCharsets.UTF_8.newEncoder().canEncode(key),
            "GC key must round-trip as UTF-8"
           )
    require(!key.startsWith("/") && !key.startsWith("\\") && !key.contains("\u0000"),
            "GC key must be relative"
           )
    require(!key.split("/", -1).exists(p => p == "." || p == ".."),
            "GC key contains a dot path component"
           )
    // Colon-containing legacy keys are valid. Keys are opaque strings, never resolved as URIs.
  }
  def isManagedDataKey(key: String): Boolean =
    key != null && key.nonEmpty && !key.endsWith("/") && key != "dummy" && key != "_lakefs" &&
      (!key.contains("/") || key.startsWith("data/"))

  def validateDataKey(key: String): Unit = {
    validateRelativeKey(key)
    require(isManagedDataKey(key), "GC candidate is outside managed repository data")
  }

}
