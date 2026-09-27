package io.treeverse.gc

import io.treeverse.clients.LakeFSContext._
import io.treeverse.clients._
import org.apache.hadoop.fs.Path
import org.apache.spark.sql.functions._
import org.apache.spark.sql.{DataFrame, SparkSession}

import java.util.Date
import org.slf4j.LoggerFactory
import org.slf4j.Logger

object GarbageCollection {
  private final val logger: Logger = LoggerFactory.getLogger(getClass.toString)
  private final val UNIFIED_GC_SOURCE_NAME = "unified_gc"
  private final val DATA_PREFIX = "data/"

  lazy val spark: SparkSession =
    SparkSession
      .builder()
      .appName("GarbageCollection")
      .getOrCreate()

  // exclude list of old data location
  private val excludeFromOldData = Seq("dummy")

  /** list repository objects directly from object store.
   *  Reads the objects from both old repository structure and new repository structure
   *
   *  @param storageNamespace The storageNamespace to read from
   *  @param before Exclude objects which last_modified date is newer than before Date
   *  @return DF listing all objects under given storageNamespace
   */
  def listObjects(storageNamespace: String, before: Date): DataFrame = {
    // TODO(niro): parallelize reads from root and data paths
    val sc = spark.sparkContext
    val oldDataPath = new Path(storageNamespace)
    val dataPath = new Path(storageNamespace, DATA_PREFIX)
    val parallelism =
      sc.hadoopConfiguration.getInt(LAKEFS_CONF_JOB_RANGE_READ_PARALLELISM, sc.defaultParallelism)

    val configMapper = new ConfigMapper(
      sc.broadcast(
        HadoopUtils.getHadoopConfigurationValues(sc.hadoopConfiguration,
                                                 "fs.",
                                                 "lakefs.",
                                                 "google.cloud."
                                                )
      )
    )
    // Read objects from data path (new repository structure)
    var dataDF = new ParallelDataLister().listData(configMapper, dataPath, parallelism)
    dataDF = dataDF
      .withColumn(
        "address",
        concat(lit(DATA_PREFIX), col("base_address"))
      )

    // Read objects from namespace root, for old structured repositories

    // TODO (niro): implement parallel lister for old repositories (https://github.com/treeverse/lakeFS/issues/4620)
    val oldDataDF = new NaiveDataLister()
      .listData(configMapper, oldDataPath, parallelism)
      .withColumn("address", col("base_address"))
      .filter(!col("address").isin(excludeFromOldData: _*))
    dataDF = dataDF.union(oldDataDF).filter(col("last_modified") < before.getTime)
    dataDF
  }

  def getFirstSlice(dataDF: DataFrame, repo: String): String = {
    var firstSlice = ""
    // Need the before filter to to exclude slices that are not actually read
    val slices =
      dataDF.filter(col("address").startsWith(DATA_PREFIX) && !col("base_address").startsWith(repo))
    if (!slices.isEmpty) {
      firstSlice = slices.first.getAs[String]("base_address").split("/")(0)
    }
    firstSlice
  }

  def validateRunModeConfigs(
      shouldMark: Boolean,
      shouldSweep: Boolean,
      markID: String
  ): Unit = {
    if (!shouldMark && !shouldSweep) {
      throw new ParameterValidationException(
        "Nothing to do, must specify at least one of mark, sweep. Exiting..."
      )
    }
    if (!shouldMark && markID.isEmpty) { // Sweep-only mode but no mark ID to sweep
      throw new ParameterValidationException(
        s"Please provide a mark ID ($LAKEFS_CONF_GC_MARK_ID) for sweep-only mode. Exiting...\n"
      )
    }
    if (shouldMark && markID.nonEmpty) {
      throw new ParameterValidationException("Can't provide mark ID for mark mode. Exiting...")
    }
  }

  def main(args: Array[String]): Unit = {
    val region = if (args.length == 2) args(1) else ""
    val repo = args(0)
    try run(region, repo)
    finally spark.stop()
  }

  private def run(region: String, repo: String): Unit = {
    val hc = spark.sparkContext.hadoopConfiguration
    val shouldMark = hc.getBoolean(LAKEFS_CONF_GC_DO_MARK, true)
    val shouldSweep = hc.getBoolean(LAKEFS_CONF_GC_DO_SWEEP, true)
    val markID = hc.get(LAKEFS_CONF_GC_MARK_ID, "")
    validateRunModeConfigs(shouldMark, shouldSweep, markID)
    val apiClient = ApiClient.get(
      APIConfigurations(
        hc.get(LAKEFS_CONF_API_URL_KEY),
        hc.get(LAKEFS_CONF_API_ACCESS_KEY_KEY),
        hc.get(LAKEFS_CONF_API_SECRET_KEY_KEY),
        hc.get(LAKEFS_CONF_API_CONNECTION_TIMEOUT_SEC_KEY),
        hc.get(LAKEFS_CONF_API_READ_TIMEOUT_SEC_KEY),
        UNIFIED_GC_SOURCE_NAME
      )
    )
    val repository = apiClient.getRepository(repo)
    val provider = apiClient.getBlockstoreType(repository.getStorageId)
    val namespace = repository.getStorageNamespace.stripSuffix("/") + "/"
    val settings = GCTarget.resolvedSettings(hc)
    val existing =
      if (shouldMark) None
      else {
        val location = s"${namespace}_lakefs/retention/gc/unified/$markID/candidates.json"
        Some(
          GCManifest.decode[GCCandidateManifest](
            GCTarget.bootstrapRead(location, namespace, provider, settings)
          )
        )
      }
    val (runID, proof) = if (shouldMark) {
      val age = hc.getLong(LAKEFS_CONF_DEBUG_GC_UNCOMMITTED_MIN_AGE_SECONDS_KEY,
                           DEFAULT_GC_UNCOMMITTED_MIN_AGE_SECONDS.toLong
                          )
      apiClient.prepareGarbageCollectionReferences(
        repo,
        age,
        hc.getInt(LAKEFS_CONF_GC_PREPARE_COMMITS_TIMEOUT_SECONDS,
                  DEFAULT_LAKEFS_CONF_GC_PREPARE_COMMITS_TIMEOUT_SECONDS
                 )
      )
    } else {
      val candidate = existing.get
      require(candidate.run_id == markID, "GC mark ID mismatch")
      (markID, apiClient.requireGarbageCollectionReferences(repo, candidate.references.task_id))
    }
    logger.info(
      s"GC preparation completed: repository=$repo run_id=$runID manifest=${proof.manifest_location}"
    )
    val bytes = GCTarget.bootstrapRead(proof.manifest_location, namespace, provider, settings)
    require(GCManifest.sha256(bytes) == proof.manifest_sha256,
            "GC reference manifest checksum mismatch"
           )
    val reference = GCManifest.decode[GCReferenceManifest](bytes)
    GCManifest.validateReferences(reference, repo, java.time.Instant.now())
    require(
      reference.run_id == runID && reference.storage_namespace.stripSuffix(
        "/"
      ) + "/" == namespace &&
        reference.storage_id == Option(repository.getStorageId).getOrElse(""),
      "GC reference target does not match repository"
    )
    logger.info(
      s"GC certified references: run_id=$runID cutoff=${reference.cutoff_time} " +
        s"sources=${reference.source_count} commits=${reference.commit_count} entries=${reference.entry_count} " +
        s"retained_rows=${reference.total_rows}"
    )
    val target = new GCTarget(reference, proof, settings)
    target.read(proof.manifest_location)
    val nativeClient = target.nativeClient(spark.sparkContext, region)
    try {
      if (shouldMark) {
        val retained = GCArtifacts.validatedReferences(spark, target)
        try {
          // The cutoff belongs to the original server request and never advances during retries or sweeping.
          val inventoryPrefix = s"${target.namespace}_lakefs/retention/gc/unified/$runID/inventory/"
          val inventoryParts = GCArtifacts
            .writeAddressParts(target, inventoryPrefix, GCInventory.addresses(nativeClient, target))
            .toVector
          val inventory = GCArtifacts.readParts(spark,
                                                target,
                                                inventoryParts,
                                                inventoryParts.map(_.row_count).sum,
                                                "address"
                                               )
          val candidate =
            GCArtifacts.writeCandidates(spark, target, inventory.select("address").except(retained))
          logger.info(
            s"GC mark successful: run_id=$runID candidates=${candidate.total_rows} " +
              s"manifest=${GCArtifacts.candidateLocation(target, runID)}"
          )
        } finally retained.unpersist()
      }
      if (shouldSweep) {
        // Both run modes reopen the same immutable candidate artifact; no inventory/classification lineage survives.
        val candidate = GCManifest.decode[GCCandidateManifest](
          target.read(GCArtifacts.candidateLocation(target, runID))
        )
        val candidates = GCArtifacts.validatedSweepCandidates(spark, target, candidate)
        try {
          val current = apiClient.requireGarbageCollectionReferences(repo, reference.task_id)
          require(current == proof, "GC reference certification changed before sweep")
          GCSweeper.sweep(target, candidates, BulkRemoverFactory(nativeClient, namespace))
        } finally candidates.unpersist()
      }
    } finally nativeClient.close()
  }

}
