package io.treeverse.gc

import io.treeverse.clients.{StorageClient, StorageClients}
import com.amazonaws.services.s3.model.{ListObjectsV2Request, ListObjectsV2Result}
import com.azure.storage.blob.models.ListBlobsOptions
import com.google.cloud.storage.Storage
import java.time.Instant
import scala.jdk.CollectionConverters._

/** Native SDK listings preserve keys that Hadoop Path would normalize (for example a//b). */
object GCInventory {
  private[gc] def managedKey(fullKey: String, prefix: String): Option[String] = {
    require(fullKey.startsWith(prefix),
            "Storage inventory returned a key outside the target prefix"
           )
    val relative = fullKey.substring(prefix.length)
    if (GCManifest.isManagedDataKey(relative)) {
      GCManifest.validateDataKey(relative)
      Some(relative)
    } else None
  }

  def addresses(client: StorageClient, target: GCTarget): Iterator[String] = {
    val prefix = target.descriptor.namespace_prefix
    val before = Instant.parse(target.manifest.cutoff_time)
    val objects: Iterator[(String, Instant)] = client match {
      case s3: StorageClients.S3 =>
        new Iterator[(String, Instant)] {
          private var nextToken: String = null
          private var finished = false
          private var page: Iterator[(String, Instant)] = Iterator.empty
          private var pages = 0
          override def hasNext: Boolean = {
            while (!page.hasNext && !finished) {
              val request = new ListObjectsV2Request()
                .withBucketName(target.descriptor.bucket)
                .withPrefix(prefix)
                .withMaxKeys(1000)
                .withContinuationToken(nextToken)
              val response: ListObjectsV2Result = s3.s3Client.listObjectsV2(request)
              page = response.getObjectSummaries.asScala.iterator.map(o =>
                (o.getKey, o.getLastModified.toInstant)
              )
              finished = !response.isTruncated
              val previous = nextToken
              nextToken = response.getNextContinuationToken
              pages += 1
              require(pages <= 1000000, "S3 inventory exceeded its page limit")
              if (!finished) {
                require(nextToken != null && nextToken.nonEmpty && nextToken != previous,
                        "S3 inventory returned an invalid continuation token"
                       )
              }
            }
            page.hasNext
          }
          override def next(): (String, Instant) = {
            if (!hasNext) throw new NoSuchElementException("Inventory exhausted")
            page.next()
          }
        }
      case gs: StorageClients.GCS =>
        gs.gcsClient
          .list(target.descriptor.bucket,
                Storage.BlobListOption.prefix(prefix),
                Storage.BlobListOption.pageSize(1000)
               )
          .iterateAll()
          .iterator()
          .asScala
          .map(blob => (blob.getName, blob.getUpdateTimeOffsetDateTime.toInstant))
      case azure: StorageClients.Azure =>
        azure.blobServiceClient
          .getBlobContainerClient(target.descriptor.container)
          .listBlobs(new ListBlobsOptions().setPrefix(prefix).setMaxResultsPerPage(1000), null)
          .iterator()
          .asScala
          .map(blob => (blob.getName, blob.getProperties.getLastModified.toInstant))
      case _ => throw new IllegalArgumentException("Unsupported native GC inventory client")
    }
    objects.filter(_._2.isBefore(before)).flatMap { case (key, _) => managedKey(key, prefix) }
  }
}
