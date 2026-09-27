package io.treeverse.clients

import io.lakefs.clients.sdk.ApiException
import okhttp3.mockwebserver.{MockResponse, MockWebServer}
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers

class GCReferenceApiSpec extends AnyFunSpec with Matchers {
  private val completed =
    """{"task_id":"task","completed":true,"progress":1,"update_time":"2026-09-27T00:00:00Z","result":{"manifest_location":"s3://bucket/repo/manifest.json","manifest_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","expires_at":"2099-01-01T00:00:00Z"}}"""

  it("uses only the versioned prepare references endpoint and revalidates completed task status") {
    val server = new MockWebServer()
    server.start()
    try {
      server.enqueue(
        new MockResponse()
          .setResponseCode(202)
          .setBody("""{"id":"task"}""")
          .addHeader("Content-Type", "application/json")
      )
      server.enqueue(
        new MockResponse().setBody(completed).addHeader("Content-Type", "application/json")
      )
      server.enqueue(
        new MockResponse().setBody(completed).addHeader("Content-Type", "application/json")
      )
      val client = ApiClient.get(APIConfigurations(server.url("/api/v1").toString, "key", "secret"))
      val (id, proof) = client.prepareGarbageCollectionReferences("repo", 7, 10)
      id should be("task")
      proof.manifest_location should be("s3://bucket/repo/manifest.json")
      val request = server.takeRequest()
      request.getPath should be("/api/v1/repositories/repo/gc/prepare_references/async")
      request.getBody.readUtf8() should include("\"minimum_age_seconds\":7")
      server.takeRequest().getPath should be(
        "/api/v1/repositories/repo/gc/prepare_references/status?id=task"
      )
      server.takeRequest().getPath should be(
        "/api/v1/repositories/repo/gc/prepare_references/status?id=task"
      )
    } finally server.shutdown()
  }

  it("does not fall back when a server does not implement binding-aware GC") {
    val server = new MockWebServer()
    server.start()
    try {
      server.enqueue(
        new MockResponse().setResponseCode(404).setBody("""{"message":"not supported"}""")
      )
      val client = ApiClient.get(APIConfigurations(server.url("/api/v1").toString, "key", "secret"))
      intercept[ApiException] { client.prepareGarbageCollectionReferences("repo", 86400, 10) }
      server.getRequestCount should be(1)
    } finally server.shutdown()
  }
}
