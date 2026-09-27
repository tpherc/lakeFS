package io.treeverse.gc

import io.treeverse.clients.{BulkRemoverFactory, SparkSessionSetup, StorageClients}
import java.time.Instant
import java.util.concurrent.ConcurrentLinkedQueue
import okhttp3.mockwebserver.{Dispatcher, MockResponse, MockWebServer, RecordedRequest}
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import scala.jdk.CollectionConverters._

class GCTargetSpec extends AnyFunSpec with Matchers with SparkSessionSetup {
  private def xml(value: String): String =
    value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

  private class S3Fixture(keys: Seq[String]) {
    val server = new MockWebServer()
    val deleted = new ConcurrentLinkedQueue[String]()
    val credentials = new ConcurrentLinkedQueue[(String, String)]()
    var manifestBytes: Array[Byte] = Array.empty
    val manifestKey = "repo/_lakefs/retention/server-manifest.json"
    var modified = Map.empty[String, String]
    server.setDispatcher(new Dispatcher {
      override def dispatch(request: RecordedRequest): MockResponse = {
        credentials.add(
          (Option(request.getHeader("Authorization")).getOrElse(""),
           Option(request.getHeader("X-Amz-Security-Token")).getOrElse("")
          )
        )
        val url = request.getRequestUrl
        val path = url.encodedPath()
        if (url.queryParameterNames().contains("location")) {
          new MockResponse().setBody(
            "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-east-1</LocationConstraint>"
          )
        } else if (request.getMethod == "POST" && url.queryParameterNames().contains("delete")) {
          val document = javax.xml.parsers.DocumentBuilderFactory
            .newInstance()
            .newDocumentBuilder()
            .parse(new java.io.ByteArrayInputStream(request.getBody.readByteArray()))
          val nodes = document.getElementsByTagName("Key")
          val batch = (0 until nodes.getLength).map(i => nodes.item(i).getTextContent)
          batch.foreach(deleted.add)
          new MockResponse().setBody(
            "<DeleteResult>" + batch
              .map(k => "<Deleted><Key>" + xml(k) + "</Key></Deleted>")
              .mkString + "</DeleteResult>"
          )
        } else if (url.queryParameterNames().contains("list-type")) {
          val prefix = Option(url.queryParameter("prefix")).getOrElse("")
          val content = keys
            .filter(_.startsWith(prefix))
            .map { key =>
              "<Contents><Key>" + xml(key) + "</Key><LastModified>" + modified.getOrElse(
                key,
                "2020-01-01T00:00:00.000Z"
              ) + "</LastModified><ETag>\"etag\"</ETag><Size>1</Size><StorageClass>STANDARD</StorageClass></Contents>"
            }
            .mkString
          new MockResponse().setBody(
            "<ListBucketResult><Name>bucket</Name><Prefix>" + xml(
              prefix
            ) + "</Prefix><IsTruncated>false</IsTruncated>" + content + "</ListBucketResult>"
          )
        } else if (path == "/bucket/" + manifestKey || path == "/bucket/" || path == "/bucket") {
          val response = new MockResponse()
            .addHeader("Last-Modified", "Sun, 27 Sep 2026 00:00:00 GMT")
            .addHeader("ETag",
                       "\"" + GCManifest.hex(
                         java.security.MessageDigest.getInstance("MD5").digest(manifestBytes)
                       ) + "\""
                      )
            .addHeader("Accept-Ranges", "bytes")
          if (request.getMethod == "HEAD")
            response.addHeader("Content-Length", manifestBytes.length)
          else {
            val range = Option(request.getHeader("Range"))
            val (from, until) = range
              .map { value =>
                val fields = value.stripPrefix("bytes=").split("-", -1)
                (fields(0).toInt,
                 if (fields(1).isEmpty) manifestBytes.length
                 else math.min(fields(1).toInt + 1, manifestBytes.length)
                )
              }
              .getOrElse((0, manifestBytes.length))
            if (range.nonEmpty)
              response
                .setResponseCode(206)
                .addHeader("Content-Range", s"bytes $from-${until - 1}/${manifestBytes.length}")
            response.setBody(new okio.Buffer().write(manifestBytes.slice(from, until)))
          }
        } else
          new MockResponse().setResponseCode(404).setBody("<Error><Code>NoSuchKey</Code></Error>")
      }
    })
    server.start()
    def endpoint: String = server.url("/").toString.stripSuffix("/")
    def close(): Unit = server.shutdown()
  }

  private def target(fixture: S3Fixture, extra: Seq[(String, String)] = Seq.empty): GCTarget = {
    val start = Instant.parse("2026-09-27T00:00:00Z")
    val manifest = GCReferenceManifest(
      1,
      1,
      "installation",
      "task",
      "task",
      "repo",
      "uid",
      "home",
      "s3://bucket/repo/",
      "fingerprint",
      start.toString,
      start.minusSeconds(86400).toString,
      86400,
      start.plusSeconds(1).toString,
      "2099-01-01T00:00:00Z",
      GCTargetDescriptor(1, "s3", fixture.endpoint, Seq(fixture.endpoint), "repo/", "bucket"),
      Seq.empty,
      0,
      1,
      0,
      0
    )
    fixture.manifestBytes = GCManifest.encode(manifest)
    val proof = GCPreparedReferences("s3://bucket/" + fixture.manifestKey,
                                     GCManifest.sha256(fixture.manifestBytes),
                                     manifest.expires_at
                                    )
    val settings = Seq(
      "fs.s3a.endpoint" -> fixture.endpoint,
      "fs.s3a.path.style.access" -> "true",
      "fs.s3a.connection.ssl.enabled" -> "false",
      "fs.s3a.access.key" -> "test-access",
      "fs.s3a.secret.key" -> "test-secret",
      "fs.s3a.aws.credentials.provider" -> "org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider",
      "fs.s3a.bucket.probe" -> "0",
      "fs.s3a.connection.maximum" -> "4"
    ) ++ extra
    new GCTarget(manifest, proof, settings.toArray)
  }

  it(
    "uses effective per-bucket routing for actual Hadoop artifact and native inventory/delete clients"
  ) {
    val right = new S3Fixture(Seq("repo/data/a"))
    val wrong = new S3Fixture(Seq("repo/data/wrong"))
    try withSparkSession { spark =>
      val selected = target(right,
                            Seq("fs.s3a.endpoint" -> wrong.endpoint,
                                "fs.s3a.bucket.bucket.endpoint" -> right.endpoint
                               )
                           )
      selected.read(selected.proof.manifest_location).toSeq should be(right.manifestBytes.toSeq)
      val native = selected.nativeClient(spark.sparkContext, "us-east-1")
      try {
        GCInventory.addresses(native, selected).toSeq should be(Seq("data/a"))
        BulkRemoverFactory(native, selected.namespace).deleteObjects(Seq("data/a"),
                                                                     selected.namespace
                                                                    )
        right.deleted.asScala.toSeq should be(Seq("repo/data/a"))
        wrong.server.getRequestCount should be(0)
      } finally native.asInstanceOf[StorageClients.S3].s3Client.shutdown()
    } finally { right.close(); wrong.close() }
  }

  it("rejects a colliding bucket and manifest path on a different endpoint before any delete") {
    val right = new S3Fixture(Seq("repo/data/a"))
    val wrong = new S3Fixture(Seq("repo/data/a"))
    try withSparkSession { spark =>
      Seq("org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider",
          "com.amazonaws.auth.EnvironmentVariableCredentialsProvider"
         ).foreach { provider =>
        val selected = target(right,
                              Seq("fs.s3a.endpoint" -> wrong.endpoint,
                                  "fs.s3a.aws.credentials.provider" -> provider
                                 )
                             )
        wrong.manifestBytes = right.manifestBytes.clone()
        intercept[IllegalArgumentException] { selected.read(selected.proof.manifest_location) }
        intercept[IllegalArgumentException] {
          selected.nativeClient(spark.sparkContext, "us-east-1")
        }
      }
      wrong.deleted should be(empty)
      right.deleted should be(empty)
      wrong.server.getRequestCount should be(0)
      right.server.getRequestCount should be(0)
    } finally { right.close(); wrong.close() }
  }

  it(
    "preserves raw percent, repeated separators, spaces, Unicode, punctuation and backslashes through inventory and deletion"
  ) {
    val relative = Seq("data/%2F",
                       "data/%2e",
                       "data/a//b",
                       "data/a b",
                       "data/a?b#c",
                       "data/雪",
                       "data/a\\b",
                       "legacy:address"
                      )
    val fixture = new S3Fixture(
      relative.map("repo/" + _) ++ Seq("repo/_lakefs/secret", "repo/dummy", "repo/other/folder")
    )
    try withSparkSession { spark =>
      val selected = target(fixture)
      val native = selected.nativeClient(spark.sparkContext, "us-east-1")
      try {
        val listed = GCInventory.addresses(native, selected).toSeq
        listed should be(relative)
        val remover = BulkRemoverFactory(native, selected.namespace)
        remover.deleteObjects(listed, selected.namespace)
        fixture.deleted.asScala.toSeq should be(relative.map("repo/" + _))
      } finally native.asInstanceOf[StorageClients.S3].s3Client.shutdown()
    } finally fixture.close()
  }

  it("does not allow AWS hostname spelling to authorize a custom port or endpoint path") {
    val fixture = new S3Fixture(Seq.empty)
    try {
      val base = target(fixture)
      Seq("https://s3.us-east-1.amazonaws.com:8443",
          "https://s3.us-east-1.amazonaws.com/custom",
          "https://s3.us-iso-east-1.amazonaws.com"
         ).foreach { endpoint =>
        val changed = new GCTarget(
          base.manifest.copy(target = base.descriptor.copy(service = "aws", routes = Seq("aws"))),
          base.proof,
          Array("fs.s3a.endpoint" -> endpoint)
        )
        intercept[IllegalArgumentException] { changed.read(changed.proof.manifest_location) }
      }
    } finally fixture.close()
  }
  it("rejects custom S3A factories and access points before reading any manifest") {
    val fixture = new S3Fixture(Seq.empty)
    try {
      Seq(
        "fs.s3a.s3.client.factory.impl" -> "example.RedirectedClientFactory",
        "fs.s3a.bucket.bucket.s3.client.factory.impl" -> "example.RedirectedClientFactory",
        "fs.s3a.accesspoint.arn" -> "arn:aws:s3:us-east-1:123456789012:accesspoint/example",
        "fs.s3a.bucket.bucket.accesspoint.arn" -> "arn:aws:s3:us-east-1:123456789012:accesspoint/example"
      ).foreach { setting =>
        val selected = target(fixture, Seq(setting))
        intercept[IllegalArgumentException] { selected.read(selected.proof.manifest_location) }
        intercept[IllegalArgumentException] {
          GCTarget.bootstrapRead(selected.proof.manifest_location,
                                 selected.namespace,
                                 "s3",
                                 selected.settings
                                )
        }
      }
      fixture.server.getRequestCount should be(0)
    } finally fixture.close()
  }

  it("preserves resolved operational settings when removing Hadoop default resources") {
    val conf = new org.apache.hadoop.conf.Configuration(false)
    conf.set("hadoop.tmp.dir", "/tmp/gc-buffer-test")
    conf.set("fs.s3a.buffer.dir", "${hadoop.tmp.dir}/s3a")
    val resolved = GCTarget.resolvedSettings(conf).toMap
    resolved("fs.s3a.buffer.dir") should be("/tmp/gc-buffer-test/s3a")
    resolved("hadoop.tmp.dir") should be("/tmp/gc-buffer-test")
  }

  it("keeps the initial cutoff when preparation takes longer than the minimum age") {
    val fixture = new S3Fixture(Seq("repo/data/old", "repo/data/during-scan"))
    try withSparkSession { spark =>
      val base = target(fixture)
      val started = Instant.parse(base.manifest.started_at)
      val completed = started.plusSeconds(base.manifest.minimum_age_seconds * 2)
      fixture.modified = Map("repo/data/old" -> started.minusSeconds(86401).toString,
                             "repo/data/during-scan" -> started.plusSeconds(1).toString
                            )
      val manifest = base.manifest.copy(completed_at = completed.toString)
      fixture.manifestBytes = GCManifest.encode(manifest)
      val selected =
        new GCTarget(manifest,
                     base.proof.copy(manifest_sha256 = GCManifest.sha256(fixture.manifestBytes)),
                     base.settings
                    )
      GCManifest.validateReferences(manifest, "repo", completed)
      val native = selected.nativeClient(spark.sparkContext, "us-east-1")
      try GCInventory.addresses(native, selected).toSeq should be(Seq("data/old"))
      finally native.close()
    } finally fixture.close()
  }

  it("canonicalizes Azure host case and S3 endpoint scheme and default port") {
    val fixture = new S3Fixture(Seq.empty)
    try {
      val base = target(fixture)
      val azureManifest = base.manifest.copy(
        storage_namespace = "https://ACCOUNT.BLOB.CORE.WINDOWS.NET/container/repo/",
        target = GCTargetDescriptor(1,
                                    "azure",
                                    "blob.core.windows.net",
                                    Seq("blob.core.windows.net"),
                                    "repo/",
                                    account = "account",
                                    container = "container"
                                   )
      )
      val azure = new GCTarget(azureManifest, base.proof, Array.empty)
      azure.checkConfiguration(azure.configuration)
      io.treeverse.clients.StorageUtils.AzureBlob
        .uriToStorageAccountName(new java.net.URI(azure.namespace)) should be("account")
      io.treeverse.clients.ApiClient
        .translateURI(new java.net.URI(azure.namespace), "azure")
        .getAuthority should be("container@account.dfs.core.windows.net")
      azure.validateLocation("https://account.blob.core.windows.net/container/repo/_lakefs/part")
      val aws = new GCTarget(
        base.manifest.copy(target = base.descriptor.copy(service = "aws", routes = Seq("aws"))),
        base.proof,
        Array("fs.s3a.endpoint" -> "HTTPS://S3.US-EAST-1.AMAZONAWS.COM:443/")
      )
      aws.checkConfiguration(aws.configuration)
      fixture.server.getRequestCount should be(0)
    } finally fixture.close()
  }

  it("uses an explicitly resolved custom S3 endpoint alias without an identity declaration") {
    val original = new S3Fixture(Seq("repo/data/a"))
    val alias = new S3Fixture(Seq("repo/data/a"))
    try withSparkSession { spark =>
      val base = target(original, Seq("fs.s3a.endpoint" -> alias.endpoint))
      val manifest = base.manifest.copy(target =
        base.descriptor.copy(
          service = "aws",
          routes = Seq("aws", original.endpoint, alias.endpoint)
        )
      )
      alias.manifestBytes = GCManifest.encode(manifest)
      original.manifestBytes = alias.manifestBytes.clone()
      new String(alias.manifestBytes,
                 java.nio.charset.StandardCharsets.UTF_8
                ) should not include "identity_basis"
      val selected = new GCTarget(
        manifest,
        base.proof.copy(manifest_sha256 = GCManifest.sha256(alias.manifestBytes)),
        base.settings
      )
      selected.read(selected.proof.manifest_location).toSeq should be(alias.manifestBytes.toSeq)
      val native = selected.nativeClient(spark.sparkContext, "us-east-1")
      try {
        GCInventory.addresses(native, selected).toSeq should be(Seq("data/a"))
        BulkRemoverFactory(native, selected.namespace).deleteObjects(Seq("data/a"),
                                                                     selected.namespace
                                                                    )
        alias.deleted.asScala.toSeq should be(Seq("repo/data/a"))
        original.server.getRequestCount should be(0)
      } finally native.close()
    } finally { original.close(); alias.close() }
  }

  it("uses explicit environment session credentials in both Hadoop and native S3 clients") {
    val fixture = new S3Fixture(Seq.empty)
    val output = java.nio.file.Files.createTempFile("gc-environment-credentials-", ".log")
    try {
      val base = target(fixture)
      val javaExecutable =
        java.nio.file.Paths.get(System.getProperty("java.home"), "bin", "java").toString
      val builder = new ProcessBuilder(
        javaExecutable,
        "-cp",
        System.getProperty("java.class.path"),
        "io.treeverse.gc.GCEnvironmentCredentialsProbe",
        fixture.endpoint,
        java.util.Base64.getEncoder.encodeToString(fixture.manifestBytes),
        base.proof.manifest_location
      ).redirectErrorStream(true).redirectOutput(output.toFile)
      builder.environment().put("AWS_ACCESS_KEY_ID", "gc-environment-access")
      builder.environment().put("AWS_SECRET_ACCESS_KEY", "gc-environment-secret")
      builder.environment().put("AWS_SESSION_TOKEN", "gc-environment-session")
      val process = builder.start()
      try {
        process.waitFor(60, java.util.concurrent.TimeUnit.SECONDS) should be(true)
        withClue(
          new String(java.nio.file.Files.readAllBytes(output),
                     java.nio.charset.StandardCharsets.UTF_8
                    )
        ) {
          process.exitValue() should be(0)
        }
        val requests = fixture.credentials.asScala.toSeq
        requests.size should be >= 2
        requests.foreach { case (authorization, token) =>
          authorization should include("Credential=gc-environment-access/")
          token should be("gc-environment-session")
        }
      } finally if (process.isAlive) process.destroyForcibly()
    } finally {
      fixture.close()
      java.nio.file.Files.deleteIfExists(output)
    }
  }

  it("rejects unsupported GCS connector routing before reading a manifest") {
    val fixture = new S3Fixture(Seq.empty)
    try {
      val base = target(fixture)
      val manifest =
        base.manifest.copy(storage_namespace = "gs://bucket/repo/",
                           target =
                             GCTargetDescriptor(1, "gs", "gcs", Seq("gcs"), "repo/", "bucket")
                          )
      val location = "gs://bucket/repo/_lakefs/manifest.json"
      Seq(
        "fs.gs.grpc.enable" -> "true",
        "fs.gs.grpc.server.address" -> "elsewhere:443",
        "fs.gs.storage.service.path" -> "tenant/storage/v1/",
        "fs.gs.client.type" -> "STORAGE_CLIENT",
        "fs.gs.storage.root.url" -> "https://elsewhere/"
      ).foreach { option =>
        val selected = new GCTarget(
          manifest,
          base.proof.copy(manifest_location = location),
          Array(option, "google.cloud.auth.service.account.json.keyfile" -> "fixture.json")
        )
        intercept[IllegalArgumentException] { selected.checkConfiguration(selected.configuration) }
        intercept[IllegalArgumentException] {
          GCTarget.bootstrapRead(location, selected.namespace, "gs", selected.settings)
        }
      }
      fixture.server.getRequestCount should be(0)
    } finally fixture.close()
  }

}

/** Isolate environment credentials from the test runner and other provider tests. */
object GCEnvironmentCredentialsProbe {
  def main(args: Array[String]): Unit = {
    val bytes = java.util.Base64.getDecoder.decode(args(1))
    val manifest = GCManifest.decode[GCReferenceManifest](bytes)
    val proof = GCPreparedReferences(args(2), GCManifest.sha256(bytes), manifest.expires_at)
    val settings = Array(
      "fs.s3a.endpoint" -> args(0),
      "fs.s3a.path.style.access" -> "true",
      "fs.s3a.connection.ssl.enabled" -> "false",
      "fs.s3a.access.key" -> "conflicting-static-access",
      "fs.s3a.secret.key" -> "conflicting-static-secret",
      "fs.s3a.aws.credentials.provider" -> "com.amazonaws.auth.EnvironmentVariableCredentialsProvider",
      "fs.s3a.bucket.probe" -> "0",
      "fs.s3a.connection.maximum" -> "4"
    )
    val target = new GCTarget(manifest, proof, settings)
    require(target.read(proof.manifest_location).sameElements(bytes))
    val client =
      io.treeverse.clients.S3ClientBuilder.build(target.configuration, "bucket", "us-east-1", 0)
    try {
      val obj = client.getObject("bucket",
                                 new java.net.URI(proof.manifest_location).getPath.stripPrefix("/")
                                )
      try require(GCManifest.readBytes(obj.getObjectContent).sameElements(bytes))
      finally obj.close()
    } finally client.shutdown()
  }
}
