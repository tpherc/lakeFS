package io.treeverse.gc

import io.treeverse.clients._
import java.net.URI
import org.apache.hadoop.conf.Configuration
import org.apache.hadoop.fs.{FileSystem, Path}
import org.apache.spark.SparkContext
import scala.jdk.CollectionConverters._

/** All GC I/O uses these exact handles, after checking the server manifest through each handle. */
class GCTarget(
    val manifest: GCReferenceManifest,
    val proof: GCPreparedReferences,
    val settings: Array[(String, String)],
    private val allowLocal: Boolean = false
) extends Serializable {
  val namespace: String = manifest.storage_namespace.stripSuffix("/") + "/"
  val descriptor: GCTargetDescriptor = manifest.target

  def hadoopPath(location: String): Path = {
    validateLocation(location)
    val translated = ApiClient.translateURI(new URI(location), descriptor.provider)
    val path = new Path(translated)
    require(path.toUri.getPath == translated.getPath, "Hadoop would normalize the GC artifact key")
    path
  }

  def validateLocation(location: String): Unit = {
    val uri = new URI(location)
    val base = new URI(namespace)
    require(uri.getUserInfo == null && uri.getQuery == null && uri.getFragment == null,
            "GC location contains unsupported URI components"
           )
    require(
      (if (descriptor.provider == "azure")
         Option(uri.getAuthority).exists(_.equalsIgnoreCase(base.getAuthority))
       else
         uri.getAuthority == base.getAuthority) && uri.getScheme.equalsIgnoreCase(base.getScheme) &&
        (uri.getRawPath
          .startsWith(base.getRawPath) || uri.getRawPath == base.getRawPath.stripSuffix("/")),
      "GC location is outside the target repository namespace"
    )
    require(!uri.getRawPath.split("/", -1).exists(p => p == "." || p == ".."),
            "GC location contains dot path components"
           )
  }

  def configuration: Configuration = {
    val conf = new Configuration(false)
    settings.foreach { case (key, value) => conf.set(key, value) }
    // Resolve bucket overrides once for both S3A and the native client, then remove the overrides.
    if (descriptor.provider == "s3") {
      val prefix = s"fs.s3a.bucket.${descriptor.bucket}."
      settings.filter(_._1.startsWith(prefix)).foreach { case (key, value) =>
        conf.set("fs.s3a." + key.substring(prefix.length), value)
      }
      conf
        .iterator()
        .asScala
        .map(_.getKey)
        .filter(_.startsWith("fs.s3a.bucket."))
        .toList
        .foreach(conf.unset)
    }
    conf.setBoolean("spark.sql.files.ignoreMissingFiles", false)
    conf.setBoolean("spark.sql.files.ignoreCorruptFiles", false)
    conf
  }

  private def expectedFileSystem: (String, String) = descriptor.provider match {
    case "s3"                  => ("s3a", "org.apache.hadoop.fs.s3a.S3AFileSystem")
    case "gs"                  => ("gs", "com.google.cloud.hadoop.fs.gcs.GoogleHadoopFileSystem")
    case "azure"               => ("abfs", "org.apache.hadoop.fs.azurebfs.AzureBlobFileSystem")
    case "local" if allowLocal => ("file", "org.apache.hadoop.fs.LocalFileSystem")
    case other => throw new IllegalArgumentException(s"Unsupported GC target provider $other")
  }

  private[gc] def checkConfiguration(conf: Configuration): Unit = {
    require(descriptor.resolver_version == 1 && descriptor.routes.nonEmpty,
            "Unsupported or empty GC target descriptor"
           )
    val uri = new URI(namespace)
    // Existing Hadoop/native URI translation is not byte preserving for escaped namespace prefixes.
    require(uri.getRawPath == uri.getPath, "Escaped GC namespace prefixes are not supported")
    descriptor.provider match {
      case "s3" =>
        GCTarget.checkS3RoutingConfiguration(conf, descriptor.bucket)
        require(uri.getHost == descriptor.bucket, "GC target bucket mismatch")
        require(uri.getPath.stripPrefix("/") == descriptor.namespace_prefix,
                "GC target namespace prefix mismatch"
               )
        val endpoint = Option(conf.get("fs.s3a.endpoint")).filter(_.nonEmpty)
        endpoint match {
          case Some(value) =>
            require(s3RouteAllowed(value), "S3 endpoint is not approved by server")
          case None =>
            require(descriptor.routes.exists(_.startsWith("aws")),
                    "An explicit S3 endpoint is required for this GC target"
                   )
        }
        val provider = Option(conf.get("fs.s3a.aws.credentials.provider")).getOrElse("")
        val supported = Set(
          "",
          "org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider",
          "com.amazonaws.auth.DefaultAWSCredentialsProviderChain",
          "com.amazonaws.auth.EnvironmentVariableCredentialsProvider",
          "org.apache.hadoop.fs.s3a.auth.AssumedRoleCredentialProvider"
        )
        require(supported(provider), "Unsupported GC S3 credentials provider")
        require(Option(conf.get("fs.s3a.session.token")).forall(_.isEmpty),
                "Explicit session credentials are not supported by the GC native client"
               )
      case "azure" =>
        require(descriptor.routes.contains("blob.core.windows.net"),
                "Only verified Azure public-cloud routing is supported by GC"
               )
        require(uri.getHost.equalsIgnoreCase(s"${descriptor.account}.blob.core.windows.net"),
                "Azure blob endpoint does not match GC target"
               )
        require(
          uri.getPath.stripPrefix("/") == descriptor.container + "/" + descriptor.namespace_prefix,
          "Azure GC container or prefix mismatch"
        )
        require(Option(conf.get("fs.azure.abfs.endpoint")).forall(_.isEmpty),
                "Custom ABFS endpoints are not supported by GC"
               )
      case "gs" =>
        GCTarget.checkGCSRoutingConfiguration(conf)
        require(descriptor.routes.contains("gcs") && uri.getHost == descriptor.bucket,
                "GCS target mismatch"
               )
        require(uri.getPath.stripPrefix("/") == descriptor.namespace_prefix,
                "GCS target prefix mismatch"
               )
        require(
          Option(conf.get("google.cloud.auth.service.account.json.keyfile")).exists(_.nonEmpty),
          "GC requires configured GCS service account credentials"
        )
      case "local" if allowLocal => ()
      case other => throw new IllegalArgumentException(s"Unsupported GC target $other")
    }
  }

  private def normalizedEndpoint(value: String): String = {
    val uri = new URI(if (value.contains("://")) value else "https://" + value)
    require(uri.getUserInfo == null && uri.getQuery == null && uri.getFragment == null,
            "Invalid storage endpoint"
           )
    val scheme = uri.getScheme.toLowerCase(java.util.Locale.ROOT)
    require(scheme == "http" || scheme == "https", "Unsupported storage endpoint scheme")
    val port =
      if (
        (scheme == "https" && uri.getPort == 443) ||
        (scheme == "http" && uri.getPort == 80)
      ) -1
      else uri.getPort
    new URI(scheme,
            null,
            uri.getHost.toLowerCase,
            port,
            Option(uri.getPath).getOrElse("").stripSuffix("/"),
            null,
            null
           ).toString
  }

  private def s3RouteAllowed(endpoint: String): Boolean = {
    val normalized = normalizedEndpoint(endpoint)
    val uri = new URI(normalized)
    if (descriptor.routes.contains(normalized)) return true
    if (uri.getPort != -1 || Option(uri.getPath).exists(_.nonEmpty)) return false
    val host = uri.getHost
    val region =
      "^s3(?:-fips)?(?:[.-](?:dualstack\\.)?([a-z]+(?:-[a-z0-9]+)*-[0-9]+))?\\.amazonaws\\.com(\\.cn)?$".r
    host match {
      case region(area, china) =>
        val partition =
          if (china != null) "aws-cn"
          else {
            val value = Option(area).getOrElse("")
            Seq("cn-", "us-gov-", "us-iso-", "us-isob-", "eu-isoe-", "us-isof-")
              .find(value.startsWith)
              .map(p => "aws-" + p.stripSuffix("-"))
              .getOrElse("aws")
          }
        descriptor.routes.contains(partition)
      case _ => false
    }
  }

  def withFileSystem[A](location: String)(f: (FileSystem, Path) => A): A = {
    val path = hadoopPath(location)
    val conf = configuration
    checkConfiguration(conf)
    val (scheme, implementation) = expectedFileSystem
    require(Option(conf.get(s"fs.$scheme.impl")).forall(_ == implementation),
            "Unverified Hadoop filesystem implementation"
           )
    conf.set(s"fs.$scheme.impl", implementation)
    val fs = FileSystem.newInstance(path.toUri, conf)
    try {
      require(fs.getClass.getName == implementation, "Unexpected actual Hadoop filesystem")
      val bytes = GCManifest.readBytes(fs.open(hadoopPath(proof.manifest_location)))
      require(GCManifest.sha256(bytes) == proof.manifest_sha256,
              "Actual Hadoop filesystem does not read the certified GC manifest"
             )
      f(fs, path)
    } finally fs.close()
  }

  def read(location: String): Array[Byte] = withFileSystem(location) { (fs, path) =>
    GCManifest.readBytes(fs.open(path))
  }

  def write(location: String, bytes: Array[Byte]): Unit = withFileSystem(location) { (fs, path) =>
    val out = fs.create(path, false)
    try out.write(bytes)
    finally out.close()
  }

  def nativeClient(sc: SparkContext, region: String): StorageClient = {
    val conf = configuration
    checkConfiguration(conf)
    val config = new ConfigMapper(
      sc.broadcast(conf.iterator().asScala.map(e => (e.getKey, e.getValue)).toArray)
    )
    val client = StorageClients(descriptor.provider, config, namespace, region)
    try {
      val proofURI = new URI(proof.manifest_location)
      val key = proofURI.getPath.stripPrefix("/")
      val bytes = client match {
        case s3: StorageClients.S3 =>
          val actual = s3.s3Client.getUrl(descriptor.bucket, key).toURI
          val expected = new URI(namespace)
          require(actual.getHost != null && expected.getHost == descriptor.bucket,
                  "Invalid actual S3 target"
                 )
          val endpoint = Option(conf.get("fs.s3a.endpoint")).filter(_.nonEmpty)
          if (endpoint.nonEmpty) {
            val ep = new URI(normalizedEndpoint(endpoint.get))
            require(Option(ep.getPath).forall(_.isEmpty),
                    "S3 endpoint path prefixes are not supported by GC"
                   )
            require(
              actual.getScheme == ep.getScheme && actual.getPort == ep.getPort &&
                (actual.getHost == ep.getHost || actual.getHost == descriptor.bucket + "." + ep.getHost),
              "Actual native S3 client endpoint mismatch"
            )
          } else {
            val serviceHost = actual.getHost.stripPrefix(descriptor.bucket + ".")
            require(s3RouteAllowed("https://" + serviceHost), "Actual AWS S3 route is not approved")
          }
          val obj = s3.s3Client.getObject(descriptor.bucket, key)
          try GCManifest.readBytes(obj.getObjectContent)
          finally obj.close()
        case gs: StorageClients.GCS =>
          require(gs.gcsClient.getOptions.getHost == "https://storage.googleapis.com",
                  "Actual GCS endpoint is not approved"
                 )
          GCManifest.readBytes(
            java.nio.channels.Channels.newInputStream(
              gs.gcsClient.reader(com.google.cloud.storage.BlobId.of(descriptor.bucket, key))
            )
          )
        case azure: StorageClients.Azure =>
          val blob = azure.blobServiceClient
            .getBlobContainerClient(descriptor.container)
            .getBlobClient(key.stripPrefix(descriptor.container + "/"))
          require(
            new URI(blob.getBlobUrl).getHost
              .equalsIgnoreCase(s"${descriptor.account}.blob.core.windows.net"),
            "Actual Azure endpoint is not approved"
          )
          GCManifest.readBytes(blob.openInputStream())
        case _ => throw new IllegalArgumentException("Unsupported native GC client")
      }
      require(GCManifest.sha256(bytes) == proof.manifest_sha256,
              "Actual deletion client does not read the certified GC manifest"
             )
      client
    } catch {
      case scala.util.control.NonFatal(error) =>
        try client.close()
        catch { case scala.util.control.NonFatal(closeError) => error.addSuppressed(closeError) }
        throw error
    }
  }
}

object GCTarget {
  def resolvedSettings(conf: Configuration): Array[(String, String)] =
    conf
      .iterator()
      .asScala
      .map(_.getKey)
      .filter(key => Seq("fs.", "lakefs.", "google.cloud.", "hadoop.").exists(key.startsWith))
      .map(key => key -> conf.get(key))
      .toArray

  private[gc] def checkGCSRoutingConfiguration(conf: Configuration): Unit = {
    require(
      !conf.getBoolean("fs.gs.grpc.enable", false) &&
        Option(conf.get("fs.gs.grpc.server.address")).forall(_.isEmpty),
      "GCS gRPC routing is not supported by GC"
    )
    require(Option(conf.get("fs.gs.storage.service.path")).forall(_ == "storage/v1/"),
            "Custom GCS service paths are not supported by GC"
           )
    require(Option(conf.get("fs.gs.client.type")).forall(_ == "HTTP_API_CLIENT"),
            "Alternative GCS connector clients are not supported by GC"
           )
    require(
      conf.iterator().asScala.forall { entry =>
        !((entry.getKey.startsWith("fs.gs.") || entry.getKey.startsWith("google.cloud.")) &&
          (entry.getKey.contains("endpoint") || entry.getKey.contains("root.url")))
      },
      "Custom GCS routing is not supported by GC"
    )
  }

  private[gc] def checkS3RoutingConfiguration(conf: Configuration, bucket: String): Unit = {
    def effective(suffix: String): Option[String] =
      Option(conf.get(s"fs.s3a.bucket.$bucket.$suffix"))
        .orElse(Option(conf.get(s"fs.s3a.$suffix")))
        .filter(_.nonEmpty)
    require(
      effective("s3.client.factory.impl").forall(
        _ == "org.apache.hadoop.fs.s3a.DefaultS3ClientFactory"
      ),
      "Custom S3A client factories are not supported by GC"
    )
    require(effective("accesspoint.arn").isEmpty, "S3A access point routing is not supported by GC")
  }

  /** Bootstrap only metadata; its digest and target identity are verified before any inventory or delete. */
  def bootstrapRead(
      location: String,
      namespace: String,
      provider: String,
      settings: Array[(String, String)]
  ): Array[Byte] = {
    val base = namespace.stripSuffix("/") + "/"
    require(location.startsWith(base), "GC manifest location is outside the repository")
    val conf = new Configuration(false)
    settings.foreach { case (key, value) => conf.set(key, value) }
    if (provider == "s3") checkS3RoutingConfiguration(conf, new URI(namespace).getHost)
    if (provider == "gs") checkGCSRoutingConfiguration(conf)
    val implementation = provider match {
      case "s3"    => ("s3a", "org.apache.hadoop.fs.s3a.S3AFileSystem")
      case "gs"    => ("gs", "com.google.cloud.hadoop.fs.gcs.GoogleHadoopFileSystem")
      case "azure" => ("abfs", "org.apache.hadoop.fs.azurebfs.AzureBlobFileSystem")
      case other   => throw new IllegalArgumentException(s"Unsupported GC provider $other")
    }
    require(Option(conf.get(s"fs.${implementation._1}.impl")).forall(_ == implementation._2),
            "Unsupported Hadoop filesystem for GC manifest"
           )
    conf.set(s"fs.${implementation._1}.impl", implementation._2)
    val translated = ApiClient.translateURI(new URI(location), provider)
    val path = new Path(translated)
    require(path.toUri.getPath == translated.getPath, "Hadoop would normalize the GC manifest key")
    val fs = FileSystem.newInstance(path.toUri, conf)
    try GCManifest.readBytes(fs.open(path))
    finally fs.close()
  }
}
