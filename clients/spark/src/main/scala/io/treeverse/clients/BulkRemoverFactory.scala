package io.treeverse.clients

import com.amazonaws.services.s3.model
import com.amazonaws.services.s3.model.MultiObjectDeleteException
import com.azure.storage.blob.models.DeleteSnapshotsOptionType
import com.google.cloud.storage.BlobId
import io.treeverse.clients.StorageClients.{Azure, GCS, S3}
import java.net.URI
import scala.jdk.CollectionConverters._

case class DeleteOutcome(
    deleted: Seq[String],
    alreadyAbsent: Seq[String],
    failed: Map[String, String]
)
class BulkDeleteFailure(val outcome: DeleteOutcome, cause: Throwable = null)
    extends RuntimeException(s"GC deletion failed for ${outcome.failed.size} objects", cause)

trait BulkRemover {
  def getMaxBulkSize: Int
  def constructRemoveKeyNames(
      keys: Seq[String],
      storageNamespace: String,
      keepNsSchemeAndHost: Boolean,
      applyUTF8Encoding: Boolean
  ): Seq[String] =
    StorageUtils.concatKeysToStorageNamespace(keys, storageNamespace, keepNsSchemeAndHost)

  def deleteObjects(keys: Seq[String], storageNamespace: String): DeleteOutcome
}

object BulkRemoverFactory {
  private def requireSuccess(outcome: DeleteOutcome): DeleteOutcome = {
    if (outcome.failed.nonEmpty) throw new BulkDeleteFailure(outcome)
    outcome
  }

  private def failedBatch(keys: Seq[String], error: Throwable): Nothing =
    throw new BulkDeleteFailure(
      DeleteOutcome(Seq.empty,
                    Seq.empty,
                    keys.map(_ -> Option(error.getMessage).getOrElse(error.getClass.getName)).toMap
                   ),
      error
    )

  private class S3BulkRemover(namespace: String, client: StorageClients.S3) extends BulkRemover {
    private val bucket = new URI(namespace).getHost
    override def getMaxBulkSize: Int = StorageUtils.S3.S3MaxBulkSize
    override def deleteObjects(keys: Seq[String], storageNamespace: String): DeleteOutcome = {
      val names = constructRemoveKeyNames(keys, storageNamespace, false, false)
      val original = names.zip(keys).toMap
      val request = new model.DeleteObjectsRequest(bucket)
        .withKeys(names.map(new model.DeleteObjectsRequest.KeyVersion(_)).asJava)
      try {
        val response = client.s3Client.deleteObjects(request)
        val acknowledged = response.getDeletedObjects.asScala.map(_.getKey).toSet
        requireSuccess(
          DeleteOutcome(names.filter(acknowledged).map(original),
                        Seq.empty,
                        names
                          .filterNot(acknowledged)
                          .map(n => original(n) -> "Missing S3 deletion acknowledgment")
                          .toMap
                       )
        )
      } catch {
        case partial: MultiObjectDeleteException =>
          val deleted = partial.getDeletedObjects.asScala.map(_.getKey).toSet
          val errors = partial.getErrors.asScala.map(e => e.getKey -> e.getCode).toMap
          throw new BulkDeleteFailure(
            DeleteOutcome(names.filter(deleted).map(original),
                          Seq.empty,
                          names
                            .filterNot(deleted)
                            .map(n => original(n) -> errors.getOrElse(n, "Missing acknowledgment"))
                            .toMap
                         ),
            partial
          )
        case known: BulkDeleteFailure => throw known
        case error: Exception         => failedBatch(keys, error)
      }
    }
  }

  private class AzureBulkRemover(client: StorageClients.Azure) extends BulkRemover {
    override def getMaxBulkSize: Int = StorageUtils.AzureBlob.AzureBlobMaxBulkSize
    override def deleteObjects(keys: Seq[String], storageNamespace: String): DeleteOutcome = {
      val uri = new URI(storageNamespace)
      val container = StorageUtils.AzureBlob.uriToContainerName(uri)
      val prefix = uri.getPath.stripPrefix("/" + container + "/")
      val containerClient = client.blobServiceClient.getBlobContainerClient(container)
      val names = keys.map(key => containerClient.getBlobClient(prefix + key).getBlobUrl)
      try {
        val batch = client.blobBatchClient.getBlobBatch()
        val responses =
          names.map(name => batch.deleteBlob(name, DeleteSnapshotsOptionType.INCLUDE, null))
        client.blobBatchClient.submitBatchWithResponse(batch,
                                                       false,
                                                       null,
                                                       com.azure.core.util.Context.NONE
                                                      )
        require(responses.size == keys.size, "Azure batch response count mismatch")
        val status = keys.zip(responses.map { response =>
          try response.getStatusCode
          catch {
            case error: com.azure.storage.blob.models.BlobStorageException => error.getStatusCode
          }
        })
        requireSuccess(
          DeleteOutcome(
            status.collect { case (key, code) if code >= 200 && code < 300 => key },
            status.collect { case (key, 404) => key },
            status.collect {
              case (key, code) if (code < 200 || code >= 300) && code != 404 =>
                key -> s"Azure status $code"
            }.toMap
          )
        )
      } catch {
        case known: BulkDeleteFailure => throw known
        case error: Exception         => failedBatch(keys, error)
      }
    }
  }

  private class GCSBulkRemover(namespace: String, client: StorageClients.GCS) extends BulkRemover {
    private val bucket = new URI(namespace).getHost
    override def getMaxBulkSize: Int = StorageUtils.GCS.GCSMaxBulkSize
    override def deleteObjects(keys: Seq[String], storageNamespace: String): DeleteOutcome = {
      val names = constructRemoveKeyNames(keys, storageNamespace, false, false)
      try {
        val batch = client.gcsClient.batch()
        val pending = keys.zip(names.map(name => batch.delete(BlobId.of(bucket, name))))
        batch.submit()
        // StorageBatch preserves individual errors; the convenience bulk-delete API
        // turns every error into false and cannot distinguish absence from denial.
        val outcomes = pending.map { case (key, result) =>
          try {
            val removed = result.get()
            require(removed != null, "Missing GCS deletion acknowledgment")
            if (removed.booleanValue()) DeleteOutcome(Seq(key), Seq.empty, Map.empty)
            else DeleteOutcome(Seq.empty, Seq(key), Map.empty)
          } catch {
            case absent: com.google.cloud.storage.StorageException if absent.getCode == 404 =>
              DeleteOutcome(Seq.empty, Seq(key), Map.empty)
            case error: Exception =>
              DeleteOutcome(Seq.empty,
                            Seq.empty,
                            Map(key -> Option(error.getMessage).getOrElse(error.getClass.getName))
                           )
          }
        }
        requireSuccess(
          DeleteOutcome(outcomes.flatMap(_.deleted),
                        outcomes.flatMap(_.alreadyAbsent),
                        outcomes.flatMap(_.failed).toMap
                       )
        )
      } catch {
        case known: BulkDeleteFailure => throw known
        case error: Exception         => failedBatch(keys, error)
      }
    }
  }

  def apply(client: StorageClient, namespace: String): BulkRemover = client match {
    case s3: S3       => new S3BulkRemover(namespace, s3)
    case azure: Azure => new AzureBulkRemover(azure)
    case gs: GCS      => new GCSBulkRemover(namespace, gs)
    case _            => throw new IllegalArgumentException("Unsupported GC delete client")
  }
}
