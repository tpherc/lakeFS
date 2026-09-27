package io.treeverse.gc

import com.azure.storage.blob.BlobServiceClientBuilder
import com.azure.storage.common.StorageSharedKeyCredential
import com.google.cloud.NoCredentials
import com.google.cloud.storage.StorageOptions
import io.treeverse.clients.{
  BulkDeleteFailure,
  BulkRemoverFactory,
  ConfigMapper,
  SparkSessionSetup,
  StorageClients
}
import java.nio.charset.StandardCharsets.UTF_8
import okhttp3.mockwebserver.{Dispatcher, MockResponse, MockWebServer, RecordedRequest}
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers

class GCBulkRemoverSpec extends AnyFunSpec with Matchers with SparkSessionSetup {
  private def batchResponse(request: RecordedRequest, azure: Boolean): MockResponse = {
    val body = request.getBody.readUtf8()
    val requests = "(?is)Content-ID: ([^\\r\\n]+).*?DELETE ([^ ]+) HTTP/1.1".r
      .findAllMatchIn(body)
      .map(m => (m.group(1), m.group(2)))
      .toSeq
    require(requests.size == 3, s"Expected three batch requests, got ${requests.size}")
    val boundary = "fixture_response_boundary"
    val parts = requests
      .map { case (id, path) =>
        val status =
          if (path.contains("deleted")) 204 else if (path.contains("absent")) 404 else 403
        (id, status)
      }
      .map { case (id, status) =>
        val content =
          if (status == 204) ""
          else if (azure)
            s"<Error><Code>${if (status == 404) "BlobNotFound" else "AuthorizationFailure"}</Code><Message>fixture error</Message></Error>"
          else s"""{"error":{"code":$status,"message":"fixture error"}}"""
        val responseID = if (azure) id else "response-" + id
        s"--$boundary\r\nContent-Type: application/http\r\nContent-ID: $responseID\r\n\r\n" +
          s"HTTP/1.1 $status Fixture\r\nContent-Type: ${if (azure) "application/xml"
          else "application/json"}\r\n" +
          s"Content-Length: ${content.getBytes(UTF_8).length}\r\n\r\n$content\r\n"
      }
      .mkString + s"--$boundary--\r\n"
    new MockResponse()
      .setResponseCode(if (azure) 202 else 200)
      .addHeader("Content-Type", s"multipart/mixed; boundary=$boundary")
      .setBody(parts)
  }

  it("keeps GCS confirmed success and absence while surfacing per-object access denial") {
    val server = new MockWebServer()
    server.setDispatcher(new Dispatcher {
      override def dispatch(request: RecordedRequest): MockResponse =
        batchResponse(request, azure = false)
    })
    server.start()
    try withSparkSession { spark =>
      val config = new ConfigMapper(spark.sparkContext.broadcast(Array.empty[(String, String)]))
      val storage = StorageOptions
        .newBuilder()
        .setHost(server.url("/").toString)
        .setCredentials(NoCredentials.getInstance())
        .build()
        .getService
      val client = new StorageClients.GCS(config) {
        override lazy val gcsClient = storage
      }
      try {
        val error = intercept[BulkDeleteFailure] {
          BulkRemoverFactory(client, "gs://bucket/repo/")
            .deleteObjects(Seq("data/deleted", "data/absent", "data/denied"), "gs://bucket/repo/")
        }
        withClue(s"Provider batch failure: ${error.outcome.failed}; cause=${error.getCause}") {
          error.outcome.deleted should be(Seq("data/deleted"))
        }
        error.outcome.alreadyAbsent should be(Seq("data/absent"))
        error.outcome.failed.keySet should be(Set("data/denied"))
        server.getRequestCount should be(1)
      } finally client.close()
    } finally server.shutdown()
  }

  it("keeps Azure confirmed success and absence while surfacing per-object access denial") {
    val server = new MockWebServer()
    server.setDispatcher(new Dispatcher {
      override def dispatch(request: RecordedRequest): MockResponse =
        batchResponse(request, azure = true)
    })
    server.start()
    try withSparkSession { spark =>
      val config = new ConfigMapper(spark.sparkContext.broadcast(Array.empty[(String, String)]))
      val service = new BlobServiceClientBuilder()
        .endpoint(server.url("/").toString)
        .credential(new StorageSharedKeyCredential("account", "dGVzdA=="))
        .buildClient()
      val namespace = "https://account.blob.core.windows.net/container/repo/"
      val client = new StorageClients.Azure(config, namespace) {
        override lazy val blobServiceClient = service
      }
      val error = intercept[BulkDeleteFailure] {
        BulkRemoverFactory(client, namespace)
          .deleteObjects(Seq("data/deleted", "data/absent", "data/denied"), namespace)
      }
      withClue(s"Provider batch failure: ${error.outcome.failed}; cause=${error.getCause}") {
        error.outcome.deleted should be(Seq("data/deleted"))
      }
      error.outcome.alreadyAbsent should be(Seq("data/absent"))
      error.outcome.failed.keySet should be(Set("data/denied"))
      server.getRequestCount should be(1)
    } finally server.shutdown()
  }
}
