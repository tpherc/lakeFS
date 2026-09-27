package catalog

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/config"
)

// storageOwnership contains only immutable physical-service identifiers, never credentials.
// Missing or unrecognizable context must not turn a potential retention reference into an external object.
type storageOwnership map[string]physicalService

type physicalService struct {
	provider string
	service  string
}

func newStorageOwnership(cfg config.StorageConfig) storageOwnership {
	result := make(storageOwnership)
	s3Aliases := make(serviceAliases)
	ignoreSDKEndpoints := strings.EqualFold(os.Getenv("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"), "true")
	sdkEndpointAmbiguity := !ignoreSDKEndpoints && hasSDKEndpointContext()
	for _, id := range cfg.GetStorageIDs() {
		storage := cfg.GetStorageByID(id)
		if storage == nil {
			continue
		}
		service := physicalService{provider: storage.BlockstoreType()}
		switch service.provider {
		case block.BlockstoreTypeS3:
			params, err := storage.BlockstoreS3Params()
			if err == nil {
				implicitEndpoint := params.Endpoint == "" && !ignoreSDKEndpoints && (sdkEndpointAmbiguity || params.Profile != "" || params.CredentialsFile != "")
				if !implicitEndpoint {
					service.service = s3ServiceIdentity(params.Endpoint, params.Region)
					if params.PreSignedEndpoint != "" {
						publicService := s3ServiceIdentity(params.PreSignedEndpoint, params.Region)
						if publicService == "" {
							service.service = ""
						} else if service.service != "" {
							s3Aliases.join(service.service, publicService)
						}
					}
				}
			}
		case block.BlockstoreTypeGS:
			service.service = "gcs"
		case block.BlockstoreTypeAzure:
			params, err := storage.BlockstoreAzureParams()
			if err == nil {
				service.service = strings.ToLower(params.Domain)
				if service.service == "" {
					service.service = "blob.core.windows.net"
				}
				if params.TestEndpointURL != "" {
					service.service = normalizedServiceEndpoint(params.TestEndpointURL)
				}
			}
		case block.BlockstoreTypeMem:
			// Each memory adapter owns a separate map, even when its configuration is identical.
			service.service = id
		}
		result[id] = service
	}
	for id, service := range result {
		if service.provider == block.BlockstoreTypeS3 {
			service.service = s3Aliases.canonical(service.service)
			result[id] = service
		}
	}
	return result
}

// A configured presigning endpoint names the same objects through another service URL.
// Fold the explicit relationships transitively so aliases do not depend on storage ID order.
type serviceAliases map[string]string

func (a serviceAliases) canonical(service string) string {
	for a[service] != "" {
		service = a[service]
	}
	return service
}

func (a serviceAliases) join(first, second string) {
	first, second = a.canonical(first), a.canonical(second)
	if first != second {
		a[second] = first
	}
}

// SDK profiles can override service endpoints. Snapshot only their presence; do not
// read credential files or resolve another SDK configuration just to establish ownership.
func hasSDKEndpointContext() bool {
	for _, key := range []string{"AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL", "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	for _, files := range [][]string{awsconfig.DefaultSharedConfigFiles, awsconfig.DefaultSharedCredentialsFiles} {
		for _, name := range files {
			if _, err := os.Stat(name); !os.IsNotExist(err) {
				return true
			}
		}
	}
	return false
}

var awsS3Endpoint = regexp.MustCompile(`^s3(?:-fips)?(?:[.-](?:dualstack\.)?([a-z]+(?:-[a-z0-9]+)*-[0-9]+))?\.amazonaws\.com(\.cn)?$`)

func s3ServiceIdentity(endpoint, region string) string {
	if endpoint == "" {
		return awsPartition(region)
	}
	normalized := normalizedServiceEndpoint(endpoint)
	if normalized == "" {
		return ""
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return ""
	}
	if (u.Path == "" || u.Path == "/") && u.Port() == "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
		matches := awsS3Endpoint.FindStringSubmatch(strings.ToLower(u.Host))
		if matches != nil {
			if matches[2] != "" {
				return "aws-cn"
			}
			if matches[1] == "" {
				return "aws"
			}
			return awsPartition(matches[1])
		}
	}
	return normalized
}

func awsPartition(region string) string {
	if region == "" {
		// An SDK-selected region is not known from this immutable configuration.
		return ""
	}
	for _, prefix := range []string{"cn-", "us-gov-", "us-iso-", "us-isob-", "eu-isoe-", "us-isof-"} {
		if strings.HasPrefix(region, prefix) {
			return "aws-" + strings.TrimSuffix(prefix, "-")
		}
	}
	return "aws"
}

func normalizedServiceEndpoint(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	u.Host = strings.ToLower(u.Host)
	if (u.Scheme == "https" && u.Port() == "443") || (u.Scheme == "http" && u.Port() == "80") {
		u.Host = u.Hostname()
		if strings.Contains(u.Host, ":") {
			u.Host = "[" + u.Host + "]"
		}
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = strings.TrimSuffix(u.RawPath, "/")
	return u.String()
}

func (o storageOwnership) sameService(homeID, sourceID string) (bool, error) {
	if homeID == sourceID {
		return true, nil
	}
	home, homeOK := o[homeID]
	source, sourceOK := o[sourceID]
	if !homeOK || !sourceOK {
		return false, fmt.Errorf("cannot establish ownership for storage ids %q and %q: %w", homeID, sourceID, config.ErrNoStorageConfig)
	}
	if home.provider != source.provider {
		return false, nil
	}
	if home.service == "" || source.service == "" {
		return false, fmt.Errorf("cannot establish physical service for storage ids %q and %q: %w", homeID, sourceID, ErrUnknownStorageOwnership)
	}
	return home.service == source.service, nil
}

type physicalLocation struct {
	provider  string
	container string
	key       string
}

func parsePhysicalLocation(address, provider string) (physicalLocation, error) {
	u, err := url.ParseRequestURI(address)
	if err != nil {
		return physicalLocation{}, fmt.Errorf("invalid physical location: %w", block.ErrInvalidAddress)
	}
	kind, err := block.GetStorageType(u)
	if err != nil {
		return physicalLocation{}, err
	}
	switch provider {
	case block.BlockstoreTypeS3:
		// S3 reads use the selected adapter's host/key and accept any recognized URI scheme.
		kind = block.StorageTypeS3
	case block.BlockstoreTypeGS, block.BlockstoreTypeAzure:
		if kind.BlockstoreType() != provider {
			return physicalLocation{}, fmt.Errorf("expected storage type %s: %w", provider, block.ErrInvalidAddress)
		}
	}
	if u.Host == "" && kind != block.StorageTypeLocal {
		return physicalLocation{}, fmt.Errorf("missing physical storage host: %w", block.ErrInvalidAddress)
	}
	key := strings.TrimPrefix(block.RawPathFromURI(u), "/")
	container := kind.BlockstoreType() + "://" + strings.ToLower(u.Host)
	if kind == block.StorageTypeAzure {
		// Azure clients use the configured cloud/endpoint and the URI's account name.
		// The URI domain itself is not used to select the service for object reads.
		account, _, ok := strings.Cut(u.Host, ".")
		name, rest, _ := strings.Cut(strings.Trim(u.Path, "/"), "/")
		if !ok || account == "" || name == "" {
			return physicalLocation{}, fmt.Errorf("missing Azure account or container: %w", block.ErrInvalidAddress)
		}
		container = "azure://" + strings.ToLower(account) + "/" + name
		key = rest
	}
	return physicalLocation{provider: kind.BlockstoreType(), container: container, key: key}, nil
}

// OwnedRelativeAddress classifies a FULL address using configured physical identity.
// false means known external; an error means ownership cannot safely be established.
// The returned suffix is relative to the repository namespace, including any data prefix.
func (c *Catalog) OwnedRelativeAddress(repo *Repository, sourceID, fullAddress string) (string, bool, error) {
	return c.ownership.ownedRelativeAddress(repo.StorageID, repo.StorageNamespace, sourceID, fullAddress)
}

func (o storageOwnership) ownedRelativeAddress(homeID, namespace, sourceID, fullAddress string) (string, bool, error) {
	same, err := o.sameService(homeID, block.EffectiveStorageID(sourceID, homeID))
	if err != nil || !same {
		return "", false, err
	}
	home, err := parsePhysicalLocation(namespace, o[homeID].provider)
	if err != nil {
		return "", false, err
	}
	source, err := parsePhysicalLocation(fullAddress, home.provider)
	if err != nil {
		return "", false, err
	}
	prefix := strings.TrimSuffix(home.key, "/")
	if prefix != "" {
		prefix += "/"
	}
	if home.container != source.container || !strings.HasPrefix(source.key, prefix) {
		return "", false, nil
	}
	return strings.TrimPrefix(source.key, prefix), true, nil
}

func (o storageOwnership) verifyImportPaths(homeID, namespace string, params ImportRequest) error {
	home, err := parsePhysicalLocation(namespace, o[homeID].provider)
	if err != nil {
		return err
	}
	for _, source := range params.Paths {
		same, err := o.sameService(homeID, block.EffectiveStorageID(source.StorageID, homeID))
		if err != nil {
			return err
		}
		if !same {
			continue
		}
		location, err := parsePhysicalLocation(source.Path, home.provider)
		if err != nil {
			return err
		}
		if home.container != location.container {
			continue
		}
		if strings.HasPrefix(location.key, home.key) || (source.Type == ImportPathTypePrefix && strings.HasPrefix(home.key, location.key)) {
			return fmt.Errorf("import path %q overlaps repository namespace %q: %w", source.Path, namespace, ErrInvalidImportSource)
		}
	}
	return nil
}
