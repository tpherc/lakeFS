package io.treeverse.gc

import io.treeverse.clients.{BulkDeleteFailure, BulkRemover, DeleteOutcome, SparkSessionSetup}
import java.nio.file.{Files, Path => LocalPath}
import java.time.Instant
import java.util.UUID
import org.apache.commons.io.FileUtils
import org.apache.spark.sql.SparkSession
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers

class GCArtifactsSpec extends AnyFunSpec with Matchers with SparkSessionSetup {
  private def withTarget(test: (SparkSession, GCTarget, LocalPath) => Unit): Unit = {
    val directory = Files.createTempDirectory("gc-artifacts-test-")
    val namespace = directory.toUri.toString
    val start = Instant.parse("2026-09-27T00:00:00Z")
    val manifest = GCReferenceManifest(
      1,
      1,
      "installation",
      "task-one",
      "task-one",
      "repo",
      "uid",
      "home",
      namespace,
      "fingerprint",
      start.toString,
      start.minusSeconds(86400).toString,
      86400,
      start.plusSeconds(1).toString,
      "2099-01-01T00:00:00Z",
      GCTargetDescriptor(1,
                         "local",
                         "local",
                         Seq("local"),
                         directory.toString.stripPrefix("/") + "/"
                        ),
      Seq.empty,
      0,
      1,
      0,
      0
    )
    val bytes = GCManifest.encode(manifest)
    val proofLocation = namespace + "server-manifest.json"
    Files.write(directory.resolve("server-manifest.json"), bytes)
    val proof = GCPreparedReferences(proofLocation, GCManifest.sha256(bytes), manifest.expires_at)
    val target = new GCTarget(manifest, proof, Array.empty, true)
    try withSparkSession(spark => test(spark, target, directory))
    finally FileUtils.deleteDirectory(directory.toFile)
  }

  private class RecordingRemover(fail: Boolean = false) extends BulkRemover {
    var calls = Vector.empty[Seq[String]]
    override def getMaxBulkSize: Int = 2
    override def deleteObjects(keys: Seq[String], namespace: String): DeleteOutcome = {
      calls :+= keys
      if (fail)
        throw new BulkDeleteFailure(
          DeleteOutcome(keys.take(1), Seq.empty, keys.drop(1).map(_ -> "denied").toMap)
        )
      DeleteOutcome(keys, Seq.empty, Map.empty)
    }
  }

  describe("durable GC candidates") {
    it("reopens only persisted candidates after eviction without recomputing classification") {
      withTarget { (spark, target, _) =>
        import spark.implicits._
        val evaluated = spark.sparkContext.longAccumulator("classification-" + UUID.randomUUID())
        val source = spark.sparkContext
          .parallelize(Seq("data/a", "legacy:address"), 2)
          .map { key => evaluated.add(1); key }
          .toDF("address")
        val manifest = GCArtifacts.writeCandidates(spark, target, source)
        val count = evaluated.value
        count should be(2L)
        val stored = GCManifest.decode[GCCandidateManifest](
          target.read(GCArtifacts.candidateLocation(target, manifest.run_id))
        )
        val candidates = GCArtifacts.validatedCandidates(spark, target, stored)
        candidates.unpersist(true)
        spark.catalog.clearCache()
        candidates.collect().map(_.getString(0)).toSet should be(Set("data/a", "legacy:address"))
        evaluated.value should be(count)
        val remover = new RecordingRemover()
        GCSweeper.sweep(target, candidates, remover)
        remover.calls.flatten.toSet should be(Set("data/a", "legacy:address"))
      }
    }

    it("accepts an explicit empty mark and deletes nothing") {
      withTarget { (spark, target, _) =>
        import spark.implicits._
        val mark = GCArtifacts.writeCandidates(spark, target, Seq.empty[String].toDF("address"))
        mark.parts should be(empty)
        mark.total_rows should be(0)
        val rows = GCArtifacts.validatedCandidates(spark, target, mark)
        val remover = new RecordingRemover()
        try GCSweeper.sweep(target, rows, remover)
        finally rows.unpersist()
        remover.calls should be(empty)
      }
    }

    Seq("missing", "corrupt", "row-count", "digest", "size").foreach { fault =>
      it(s"fails closed on $fault despite permissive Spark skip-file flags") {
        withTarget { (spark, target, _) =>
          import spark.implicits._
          spark.conf.set("spark.sql.files.ignoreMissingFiles", "true")
          spark.conf.set("spark.sql.files.ignoreCorruptFiles", "true")
          try {
            val mark =
              GCArtifacts.writeCandidates(spark,
                                          target,
                                          Seq("data/a", "data/b").toDF("address").coalesce(1)
                                         )
            val part = mark.parts.head
            val location = java.nio.file.Paths.get(new java.net.URI(part.location))
            val modified = fault match {
              case "missing"   => Files.delete(location); mark
              case "corrupt"   => Files.write(location, Array[Byte](1, 2, 3)); mark
              case "row-count" => mark.copy(parts = Seq(part.copy(row_count = 3)), total_rows = 3)
              case "digest"    => mark.copy(parts = Seq(part.copy(sha256 = "0" * 64)))
              case "size" => mark.copy(parts = Seq(part.copy(size_bytes = part.size_bytes + 1)))
            }
            val remover = new RecordingRemover()
            intercept[Exception] {
              val rows = GCArtifacts.validatedCandidates(spark, target, modified)
              try GCSweeper.sweep(target, rows, remover)
              finally rows.unpersist()
            }
            remover.calls should be(empty)
          } finally {
            spark.conf.set("spark.sql.files.ignoreMissingFiles", "false")
            spark.conf.set("spark.sql.files.ignoreCorruptFiles", "false")
          }
        }
      }
    }

    Seq("integer", "extra-column", "null-key").foreach { invalid =>
      it(s"validates the physical Parquet schema and every row: $invalid") {
        withTarget { (spark, target, directory) =>
          import spark.implicits._
          val path = directory.resolve("invalid-" + invalid)
          val frame = invalid match {
            case "integer"      => Seq(1).toDF("address")
            case "extra-column" => Seq(("data/a", "extra")).toDF("address", "extra")
            case "null-key"     => Seq[String](null).toDF("address")
          }
          frame.coalesce(1).write.parquet(path.toString)
          val file = path.toFile.listFiles().find(_.getName.endsWith(".parquet")).get.toPath
          val bytes = Files.readAllBytes(file)
          val part = GCPart(file.toUri.toString, bytes.length, GCManifest.sha256(bytes), 1)
          intercept[Exception] {
            GCArtifacts.readParts(spark, target, Seq(part), 1, "address").collect()
          }
        }
      }
    }

    Seq("invalid-utf8", "dot-component").foreach { invalid =>
      it(s"rejects $invalid inside an otherwise valid checksummed Parquet part") {
        withTarget { (spark, target, directory) =>
          val file = directory.resolve("key-" + invalid + ".parquet")
          val schema = org.apache.parquet.schema.MessageTypeParser
            .parseMessageType("message gc { required binary address (UTF8); }")
          val writer = org.apache.parquet.hadoop.example.ExampleParquetWriter
            .builder(new org.apache.hadoop.fs.Path(file.toUri))
            .withType(schema)
            .build()
          val value =
            if (invalid == "invalid-utf8") Array(0xc3.toByte, 0x28.toByte)
            else "../outside".getBytes(java.nio.charset.StandardCharsets.UTF_8)
          try writer.write(
            new org.apache.parquet.example.data.simple.SimpleGroupFactory(schema)
              .newGroup()
              .append("address", org.apache.parquet.io.api.Binary.fromConstantByteArray(value))
          )
          finally writer.close()
          val bytes = Files.readAllBytes(file)
          val part = GCPart(file.toUri.toString, bytes.length, GCManifest.sha256(bytes), 1)
          val mark = GCCandidateManifest(1,
                                         true,
                                         target.manifest.run_id,
                                         target.manifest,
                                         target.proof,
                                         Seq(part),
                                         1,
                                         Instant.now().toString
                                        )
          val remover = new RecordingRemover()
          intercept[Exception] {
            val candidates = GCArtifacts.validatedCandidates(spark, target, mark)
            try GCSweeper.sweep(target, candidates, remover)
            finally candidates.unpersist()
          }
          remover.calls should be(empty)
        }
      }
    }

    it("accepts owned metadata and nonmanaged keys as protection but rejects them as candidates") {
      withTarget { (spark, target, directory) =>
        val keys = Seq("_lakefs/committed/range", "dummy", "other/path", "data/folder/")
        Seq("physical_address", "address").foreach { column =>
          val file = directory.resolve(column + ".parquet")
          val schema = org.apache.parquet.schema.MessageTypeParser
            .parseMessageType(s"message gc { required binary $column (UTF8); }")
          val writer = org.apache.parquet.hadoop.example.ExampleParquetWriter
            .builder(new org.apache.hadoop.fs.Path(file.toUri))
            .withType(schema)
            .build()
          val factory = new org.apache.parquet.example.data.simple.SimpleGroupFactory(schema)
          try keys.foreach(key => writer.write(factory.newGroup().append(column, key)))
          finally writer.close()
          val bytes = Files.readAllBytes(file)
          val part = GCPart(file.toUri.toString, bytes.length, GCManifest.sha256(bytes), keys.size)
          val rows = GCArtifacts.readParts(spark, target, Seq(part), keys.size, column)
          if (column == "physical_address") rows.collect().map(_.getString(0)).toSeq should be(keys)
          else intercept[Exception] { rows.collect() }
        }
        keys.foreach { key =>
          GCManifest.validateRelativeKey(key)
          intercept[IllegalArgumentException] { GCManifest.validateDataKey(key) }
          GCInventory.managedKey("repo/" + key, "repo/") should be(None)
        }
      }
    }

    it("rejects unpaired UTF-16 surrogates before native keys can be encoded lossily") {
      intercept[IllegalArgumentException] {
        GCManifest.validateRelativeKey("data/" + new String(Array(0xd800.toChar)))
      }
    }

    it("splits a large input partition into bounded independently validated parts") {
      withTarget { (spark, target, _) =>
        import spark.implicits._
        val mark = GCArtifacts.writeCandidates(
          spark,
          target,
          (1 to (GCArtifacts.MaxPartRows + 1)).map(i => s"data/$i").toDF("address").coalesce(1)
        )
        mark.parts should have size 2
        mark.parts.map(_.row_count).sum should be(GCArtifacts.MaxPartRows + 1L)
        all(mark.parts.map(_.row_count)) should be <= GCArtifacts.MaxPartRows.toLong
      }
    }

    it("refuses sweep-only when protection data is missing even for an empty candidate set") {
      withTarget { (spark, target, directory) =>
        import spark.implicits._
        val references =
          target.manifest.copy(parts =
                                 Seq(GCPart(target.namespace + "missing.parquet", 1, "0" * 64, 1)),
                               total_rows = 1
                              )
        val bytes = GCManifest.encode(references)
        Files.write(directory.resolve("server-manifest.json"), bytes)
        val proof = target.proof.copy(manifest_sha256 = GCManifest.sha256(bytes))
        val selected = new GCTarget(references, proof, Array.empty, true)
        val mark = GCArtifacts.writeCandidates(spark, selected, Seq.empty[String].toDF("address"))
        val remover = new RecordingRemover()
        intercept[Exception] {
          val candidates = GCArtifacts.validatedSweepCandidates(spark, selected, mark)
          try GCSweeper.sweep(selected, candidates, remover)
          finally candidates.unpersist()
        }
        remover.calls should be(empty)
      }
    }

    it("rejects duplicate manifest parts and incomplete mark manifests") {
      withTarget { (spark, target, _) =>
        import spark.implicits._
        val mark = GCArtifacts.writeCandidates(spark, target, Seq("data/a").toDF("address"))
        intercept[IllegalArgumentException] {
          GCArtifacts.validatedCandidates(spark,
                                          target,
                                          mark.copy(parts = mark.parts ++ mark.parts,
                                                    total_rows = 2
                                                   )
                                         )
        }
        intercept[IllegalArgumentException] {
          GCArtifacts.validatedCandidates(spark, target, mark.copy(mark_success = false))
        }
      }
    }

    it("rejects invalid keys before any deletion") {
      withTarget { (spark, target, _) =>
        import spark.implicits._
        val remover = new RecordingRemover()
        intercept[Exception] {
          GCSweeper.sweep(target, Seq("data/valid", "../outside").toDF("address"), remover)
        }
        remover.calls should be(empty)
      }
    }

    it("preserves mark success and reports a partial sweep failure independently") {
      withTarget { (spark, target, directory) =>
        import spark.implicits._
        val mark =
          GCArtifacts.writeCandidates(spark, target, Seq("data/a", "data/b").toDF("address"))
        val rows = GCArtifacts.validatedCandidates(spark, target, mark)
        try intercept[BulkDeleteFailure] {
          GCSweeper.sweep(target, rows, new RecordingRemover(true))
        } finally rows.unpersist()
        val stored = GCManifest.decode[GCCandidateManifest](
          target.read(GCArtifacts.candidateLocation(target, mark.run_id))
        )
        stored.mark_success should be(true)
        val reports = directory
          .resolve("_lakefs/retention/gc/unified/task-one/sweeps")
          .toFile
          .listFiles()
          .filter(_.getName.endsWith(".json"))
        reports should have size 1
        val report = GCManifest.decode[GCSweepReport](Files.readAllBytes(reports.head.toPath))
        report.sweep_success should be(false)
        report.deleted should be(1)
        report.failed should be(1)
        report.failures.values.toSet should be(Set("denied"))
      }
    }

    it("fails when the actual artifact filesystem reads a different server manifest") {
      withTarget { (spark, target, directory) =>
        import spark.implicits._
        Files.write(directory.resolve("server-manifest.json"),
                    "wrong endpoint content".getBytes("UTF-8")
                   )
        intercept[Exception] {
          GCArtifacts.writeCandidates(spark, target, Seq("data/a").toDF("address"))
        }
      }
    }
  }

  describe("reference manifest") {
    it("requires the original fixed cutoff and refuses expired or unversioned references") {
      withTarget { (_, target, _) =>
        val manifest = target.manifest
        val now = Instant.parse("2026-09-28T00:00:00Z")
        GCManifest.validateReferences(manifest, "repo", now)
        intercept[IllegalArgumentException] {
          GCManifest.validateReferences(manifest.copy(cutoff_time = manifest.started_at),
                                        "repo",
                                        now
                                       )
        }
        intercept[IllegalArgumentException] {
          GCManifest.validateReferences(manifest.copy(schema_version = 0), "repo", now)
        }
        intercept[IllegalArgumentException] {
          GCManifest.validateReferences(manifest.copy(expires_at = now.toString), "repo", now)
        }
      }
    }
  }
}
