package io.treeverse.gc

import io.treeverse.clients.{BulkDeleteFailure, BulkRemover}
import java.time.Instant
import java.util.UUID
import org.apache.spark.sql.DataFrame
import scala.jdk.CollectionConverters._

object GCSweeper {
  private val logger = org.slf4j.LoggerFactory.getLogger(getClass)
  def sweep(target: GCTarget, candidates: DataFrame, remover: BulkRemover): Unit = {
    // Even direct callers must validate all keys before the first side effect.
    candidates
      .select("address")
      .rdd
      .foreachPartition(_.foreach(row => GCManifest.validateDataKey(row.getString(0))))
    val attempt = UUID.randomUUID().toString
    val started = Instant.now()
    var attempted = 0L
    var deleted = 0L
    var absent = 0L
    var failed = 0L
    var error: Throwable = null
    try {
      val keys = candidates.select("address").toLocalIterator().asScala.map(_.getString(0))
      require(remover.getMaxBulkSize > 0, "Invalid GC delete batch size")
      keys.grouped(remover.getMaxBulkSize).foreach { chunk =>
        attempted += chunk.size
        try {
          val outcome = remover.deleteObjects(chunk.toSeq, target.namespace)
          val reported = outcome.deleted ++ outcome.alreadyAbsent ++ outcome.failed.keys.toSeq
          require(reported.distinct.size == reported.size && reported.toSet == chunk.toSet,
                  "Incomplete or extraneous GC deletion outcome"
                 )
          if (outcome.failed.nonEmpty) throw new BulkDeleteFailure(outcome)
          deleted += outcome.deleted.size
          absent += outcome.alreadyAbsent.size
        } catch {
          case partial: BulkDeleteFailure =>
            val reported =
              partial.outcome.deleted ++ partial.outcome.alreadyAbsent ++ partial.outcome.failed.keys.toSeq
            if (reported.distinct.size == reported.size && reported.toSet == chunk.toSet) {
              deleted += partial.outcome.deleted.size
              absent += partial.outcome.alreadyAbsent.size
              failed += partial.outcome.failed.size
            } else failed += chunk.size
            throw partial
          case other: Exception =>
            failed += chunk.size
            throw other
        }
      }
    } catch { case scala.util.control.NonFatal(failure) => error = failure }
    val failures = error match {
      case partial: BulkDeleteFailure =>
        partial.outcome.failed
          .take(1000)
          .map { case (key, reason) =>
            key -> Option(reason).getOrElse("Unspecified provider failure").take(1024)
          }
      case _ => Map.empty[String, String]
    }
    val report = GCSweepReport(
      1,
      target.manifest.run_id,
      attempt,
      error == null,
      attempted,
      deleted,
      absent,
      failed,
      started.toString,
      Instant.now().toString,
      Option(error).map(e => Option(e.getMessage).getOrElse(e.getClass.getName)).getOrElse(""),
      failures
    )
    val reportLocation =
      s"${target.namespace}_lakefs/retention/gc/unified/${target.manifest.run_id}/sweeps/$attempt.json"
    try target.write(reportLocation, GCManifest.encode(report))
    catch {
      case scala.util.control.NonFatal(reportFailure) =>
        if (error != null) error.addSuppressed(reportFailure) else throw reportFailure
    }
    val summary = s"GC sweep: run_id=${target.manifest.run_id} attempt_id=$attempt " +
      s"success=${report.sweep_success} attempted=$attempted deleted=$deleted absent=$absent failed=$failed " +
      s"report=$reportLocation"
    if (error != null) {
      logger.error(summary, error)
      throw error
    }
    logger.info(summary)
  }
}
