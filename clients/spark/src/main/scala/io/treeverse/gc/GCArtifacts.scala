package io.treeverse.gc

import java.io.{FileInputStream, FileOutputStream}
import java.nio.file.Files
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.fs.Path
import org.apache.parquet.example.data.Group
import org.apache.parquet.example.data.simple.SimpleGroupFactory
import org.apache.parquet.hadoop.{ParquetFileReader, ParquetReader}
import org.apache.parquet.hadoop.example.{ExampleParquetWriter, GroupReadSupport}
import org.apache.parquet.schema.{MessageType, OriginalType, PrimitiveType, Type}
import org.apache.spark.TaskContext
import org.apache.spark.sql.{DataFrame, SparkSession}
import org.apache.spark.storage.StorageLevel

object GCArtifacts {
  val MaxPartBytes: Long = 16L * 1024 * 1024
  private val CandidatePartBytes: Long = 8L * 1024 * 1024
  val MaxPartRows = 10000
  private val MaxParts = GCManifest.MaxParts

  private def localConfiguration: Configuration = {
    val conf = new Configuration(false)
    conf.set("fs.file.impl", "org.apache.hadoop.fs.LocalFileSystem")
    // The dedicated reader never uses Spark's skip-file options.
    conf.setBoolean("spark.sql.files.ignoreMissingFiles", false)
    conf.setBoolean("spark.sql.files.ignoreCorruptFiles", false)
    conf
  }

  private def schema(column: String): MessageType = new MessageType(
    "gc_addresses",
    new PrimitiveType(Type.Repetition.REQUIRED,
                      PrimitiveType.PrimitiveTypeName.BINARY,
                      column,
                      OriginalType.UTF8
                     )
  )

  private def checkSchema(actual: MessageType, column: String): Unit = {
    require(actual.getFieldCount == 1 && actual.getFieldName(0) == column,
            "GC Parquet schema must contain exactly the expected address column"
           )
    val field = actual.getType(0)
    require(field.isPrimitive && !field.isRepetition(Type.Repetition.REPEATED),
            "GC address column must be a scalar string"
           )
    require(
      field.asPrimitiveType().getPrimitiveTypeName == PrimitiveType.PrimitiveTypeName.BINARY &&
        field.getOriginalType == OriginalType.UTF8,
      "GC address column must be UTF-8 STRING"
    )
  }

  /** Decode only the exact bytes verified against the manifest, never reopen a mutable remote path. */
  private[gc] def readPart(target: GCTarget, part: GCPart, column: String): Iterator[String] = {
    require(part.size_bytes > 0 && part.size_bytes <= MaxPartBytes,
            "GC part exceeds the spool limit"
           )
    val local = Files.createTempFile("lakefs-gc-verified-", ".parquet")
    var reader: ParquetReader[Group] = null
    var closed = false
    def close(): Unit = if (!closed) {
      closed = true
      try { if (reader != null) reader.close() }
      finally Files.deleteIfExists(local)
    }
    try {
      target.withFileSystem(part.location) { (fs, path) =>
        require(fs.getFileStatus(path).getLen == part.size_bytes, "GC part size mismatch")
        val input = fs.open(path)
        val output = new FileOutputStream(local.toFile)
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = new Array[Byte](65536)
        var size = 0L
        try {
          var n = input.read(buffer)
          while (n != -1) {
            size = Math.addExact(size, n.toLong)
            require(size <= part.size_bytes, "GC part grew while reading")
            digest.update(buffer, 0, n)
            output.write(buffer, 0, n)
            n = input.read(buffer)
          }
        } finally {
          try input.close()
          finally output.close()
        }
        require(size == part.size_bytes && GCManifest.hex(digest.digest()) == part.sha256,
                "GC part checksum mismatch"
               )
      }
      val path = new Path(local.toUri)
      val conf = localConfiguration
      val footer = ParquetFileReader.readFooter(conf, path)
      checkSchema(footer.getFileMetaData.getSchema, column)
      reader = ParquetReader.builder[Group](new GroupReadSupport(), path).withConf(conf).build()
      Option(TaskContext.get()).foreach(_.addTaskCompletionListener[Unit](_ => close()))
      new Iterator[String] {
        private var rows = 0L
        private var nextGroup: Group = null
        private var loaded = false
        override def hasNext: Boolean = {
          if (!loaded && !closed) {
            try {
              nextGroup = reader.read()
              loaded = true
              if (nextGroup == null) {
                require(rows == part.row_count, "GC part row count mismatch")
                close()
              }
            } catch { case e: Exception => close(); throw e }
          }
          !closed
        }
        override def next(): String = {
          if (!hasNext) throw new NoSuchElementException("GC part exhausted")
          try {
            require(nextGroup.getFieldRepetitionCount(0) == 1, "GC key must not be null")
            val key = java.nio.charset.StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
              .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
              .decode(java.nio.ByteBuffer.wrap(nextGroup.getBinary(0, 0).getBytes))
              .toString
            column match {
              case "physical_address" => GCManifest.validateRelativeKey(key)
              case "address"          => GCManifest.validateDataKey(key)
              case _ => throw new IllegalArgumentException("Unsupported GC address column")
            }
            rows = Math.addExact(rows, 1L)
            require(rows <= part.row_count, "GC part contains extra rows")
            loaded = false
            key
          } catch { case e: Exception => close(); throw e }
        }
      }
    } catch { case e: Exception => close(); throw e }
  }

  def readParts(
      spark: SparkSession,
      target: GCTarget,
      parts: Seq[GCPart],
      totalRows: Long,
      column: String
  ): DataFrame = {
    GCManifest.validateParts(parts, totalRows)
    parts.foreach(p => target.validateLocation(p.location))
    import spark.implicits._
    val partitions = math.max(1, math.min(parts.size, spark.sparkContext.defaultParallelism))
    spark.sparkContext
      .parallelize(parts, partitions)
      .mapPartitions(_.flatMap(part => readPart(target, part, column)))
      .toDF("address")
  }

  def validatedReferences(spark: SparkSession, target: GCTarget): DataFrame = {
    val reference = target.manifest
    val df = readParts(spark, target, reference.parts, reference.total_rows, "physical_address")
      .persist(StorageLevel.MEMORY_AND_DISK)
    try {
      require(df.count() == reference.total_rows, "GC reference row count mismatch")
      df
    } catch { case error: Exception => df.unpersist(); throw error }
  }

  /** This full action validates every row and part before a caller may start deleting anything. */
  def validatedCandidates(
      spark: SparkSession,
      target: GCTarget,
      candidate: GCCandidateManifest
  ): DataFrame = {
    require(candidate.schema_version == GCManifest.Version && candidate.mark_success,
            "GC mark is incomplete or uses an unsupported protocol"
           )
    require(
      candidate.run_id == target.manifest.run_id && candidate.references == target.manifest &&
        candidate.reference_manifest == target.proof,
      "GC mark does not match the current certified reference task"
    )
    val df = readParts(spark, target, candidate.parts, candidate.total_rows, "address")
      .persist(StorageLevel.MEMORY_AND_DISK)
    try {
      require(df.count() == candidate.total_rows, "GC candidate row count mismatch")
      require(df.distinct().count() == candidate.total_rows, "Duplicate GC candidate key")
      df
    } catch { case e: Exception => df.unpersist(); throw e }
  }

  def validatedSweepCandidates(
      spark: SparkSession,
      target: GCTarget,
      candidate: GCCandidateManifest
  ): DataFrame = {
    val retained = validatedReferences(spark, target)
    try validatedCandidates(spark, target, candidate)
    finally retained.unpersist()
  }

  def candidateLocation(target: GCTarget, runID: String): String =
    s"${target.namespace}_lakefs/retention/gc/unified/$runID/candidates.json"

  private def writePart(
      target: GCTarget,
      prefix: String,
      keys: Iterator[String]
  ): Option[GCPart] = {
    if (!keys.hasNext) return None
    val local = Files.createTempDirectory("lakefs-gc-candidate-").resolve("part.parquet")
    val conf = localConfiguration
    val messageType = schema("address")
    val factory = new SimpleGroupFactory(messageType)
    val writer = ExampleParquetWriter
      .builder(new Path(local.toUri))
      .withConf(conf)
      .withType(messageType)
      .build()
    var rows = 0L
    try {
      try keys.foreach { key =>
        GCManifest.validateDataKey(key)
        writer.write(factory.newGroup().append("address", key))
        rows = Math.addExact(rows, 1L)
      } finally writer.close()
      val location = prefix + UUID.randomUUID().toString + ".parquet"
      val digest = MessageDigest.getInstance("SHA-256")
      val size = Files.size(local)
      require(size <= CandidatePartBytes, "Generated GC part exceeds the spool limit")
      target.withFileSystem(location) { (fs, path) =>
        val in = new FileInputStream(local.toFile)
        val out = fs.create(path, false)
        val buffer = new Array[Byte](65536)
        try {
          var n = in.read(buffer)
          while (n != -1) {
            digest.update(buffer, 0, n)
            out.write(buffer, 0, n)
            n = in.read(buffer)
          }
        } finally {
          try in.close()
          finally out.close()
        }
      }
      Some(GCPart(location, size, GCManifest.hex(digest.digest()), rows))
    } finally {
      Files.deleteIfExists(local)
      // Local Hadoop can also create a checksum file beside the spool.
      Files.deleteIfExists(local.resolveSibling(".part.parquet.crc"))
      Files.deleteIfExists(local.getParent)
    }
  }

  def writeAddressParts(
      target: GCTarget,
      prefix: String,
      addresses: Iterator[String]
  ): Iterator[GCPart] = {
    val keys = addresses.buffered
    new Iterator[GCPart] {
      private var parts = 0
      override def hasNext: Boolean = keys.hasNext
      override def next(): GCPart = {
        if (!hasNext) throw new NoSuchElementException("GC keys exhausted")
        parts += 1
        require(parts <= MaxParts, "GC inventory has too many parts")
        var partRows = 0
        var bytes = 0L
        val bounded = new Iterator[String] {
          override def hasNext: Boolean = {
            if (!keys.hasNext || partRows >= MaxPartRows) false
            else {
              GCManifest.validateDataKey(keys.head)
              val size = keys.head.getBytes(java.nio.charset.StandardCharsets.UTF_8).length
              require(size <= CandidatePartBytes / 2, "GC key exceeds the spool limit")
              partRows == 0 || bytes + size <= CandidatePartBytes / 2
            }
          }
          override def next(): String = {
            if (!hasNext) throw new NoSuchElementException("GC part complete")
            val key = keys.next()
            partRows += 1
            bytes += key.getBytes(java.nio.charset.StandardCharsets.UTF_8).length
            key
          }
        }
        writePart(target, prefix, bounded).get
      }
    }
  }

  def writeCandidates(
      spark: SparkSession,
      target: GCTarget,
      candidates: DataFrame
  ): GCCandidateManifest = {
    val prefix =
      s"${target.namespace}_lakefs/retention/gc/unified/${target.manifest.run_id}/candidates/"
    val parts = candidates
      .select("address")
      .rdd
      .mapPartitions { rows =>
        writeAddressParts(target, prefix, rows.map(_.getString(0)))
      }
      .take(MaxParts + 1)
      .toSeq
    require(parts.size <= MaxParts, "GC candidate manifest has too many parts")
    val total = parts.foldLeft(0L)((sum, p) => Math.addExact(sum, p.row_count))
    val manifest = GCCandidateManifest(GCManifest.Version,
                                       true,
                                       target.manifest.run_id,
                                       target.manifest,
                                       target.proof,
                                       parts,
                                       total,
                                       Instant.now().toString
                                      )
    val validated = validatedCandidates(spark, target, manifest)
    validated.unpersist()
    target.write(candidateLocation(target, manifest.run_id), GCManifest.encode(manifest))
    manifest
  }
}
