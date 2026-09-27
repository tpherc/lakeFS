package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/treeverse/lakefs/pkg/block"
	"github.com/treeverse/lakefs/pkg/config"
)

// GCOwnershipResolverVersion changes when physical identity or key interpretation changes.
const GCOwnershipResolverVersion = 1

// GCTargetDescriptor identifies the physical namespace a collector may sweep.
// Routes are explicit endpoint URLs or recognized native service/partition names.
// Matching object bytes never establishes an additional route alias.
type GCTargetDescriptor struct {
	ResolverVersion int      `json:"resolver_version"`
	Provider        string   `json:"provider"`
	Service         string   `json:"service"`
	Routes          []string `json:"routes"`
	Bucket          string   `json:"bucket,omitempty"`
	Account         string   `json:"account,omitempty"`
	Container       string   `json:"container,omitempty"`
	NamespacePrefix string   `json:"namespace_prefix"`
}

// GCOwnershipFingerprint binds a GC run to the immutable nonsecret physical mappings.
// Credentials are excluded; physical namespaces come from configured service routes.
func (c *Catalog) GCOwnershipFingerprint() string {
	return c.ownership.gcFingerprint()
}

// GCTargetDescriptor refuses uncertain ownership even for a repository's own ID.
// The same-ID shortcut used for ordinary admission cannot certify a deletion target.
func (c *Catalog) GCTargetDescriptor(repo *Repository) (GCTargetDescriptor, error) {
	return c.ownership.gcTargetDescriptor(repo)
}

// GCOwnedRelativeAddress rejects uncertain source mappings before deciding that a
// reference is external. Ordinary Link admission deliberately has a looser contract.
func (c *Catalog) GCOwnedRelativeAddress(repo *Repository, sourceID, fullAddress string) (string, bool, error) {
	if _, err := c.ownership.gcKnownService(repo.StorageID); err != nil {
		return "", false, err
	}
	effectiveID := block.EffectiveStorageID(sourceID, repo.StorageID)
	if _, err := c.ownership.gcKnownService(effectiveID); err != nil {
		return "", false, err
	}
	return c.ownership.ownedRelativeAddress(repo.StorageID, repo.StorageNamespace, effectiveID, fullAddress)
}

func (o storageOwnership) gcKnownService(storageID string) (physicalService, error) {
	service, ok := o[storageID]
	if !ok {
		return physicalService{}, fmt.Errorf("GC storage %q: %w", storageID, config.ErrNoStorageConfig)
	}
	if !service.hasGCIdentity() {
		return physicalService{}, fmt.Errorf("GC storage %q: %w", storageID, ErrUnknownStorageOwnership)
	}
	return service, nil
}

func (s physicalService) hasGCIdentity() bool {
	return s.provider != "" && s.service != "" && !s.gcUnknown && len(s.routes) != 0
}

func s3OwnershipRoutes(endpoint, service string) []string {
	if service == "" {
		return nil
	}
	routes := []string{service}
	if normalized := normalizedServiceEndpoint(endpoint); normalized != "" {
		routes = append(routes, normalized)
	}
	return routes
}

func (o storageOwnership) collectGCRoutes() {
	type aliasGroup struct {
		routes  []string
		unknown bool
	}
	groups := make(map[string]aliasGroup)
	for _, service := range o {
		if service.provider != block.BlockstoreTypeS3 || service.service == "" {
			continue
		}
		group := groups[service.service]
		group.routes = append(group.routes, service.routes...)
		group.unknown = group.unknown || !service.hasGCIdentity()
		groups[service.service] = group
	}
	for id, service := range o {
		if service.provider == block.BlockstoreTypeS3 {
			group := groups[service.service]
			service.routes = slices.Clone(group.routes)
			service.gcUnknown = service.gcUnknown || group.unknown
		}
		slices.Sort(service.routes)
		service.routes = slices.Compact(service.routes)
		o[id] = service
	}
}

func (o storageOwnership) gcFingerprint() string {
	type mapping struct {
		ID       string   `json:"id"`
		Provider string   `json:"provider"`
		Service  string   `json:"service"`
		Routes   []string `json:"routes"`
		Unknown  bool     `json:"unknown"`
	}
	ids := make([]string, 0, len(o))
	for id := range o {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	mappings := make([]mapping, 0, len(ids))
	for _, id := range ids {
		service := o[id]
		routes := slices.Clone(service.routes)
		slices.Sort(routes)
		mappings = append(mappings, mapping{
			ID: id, Provider: service.provider, Service: service.service,
			Routes: slices.Compact(routes), Unknown: !service.hasGCIdentity(),
		})
	}
	// This fixed schema contains only strings, booleans, integers and slices.
	data, _ := json.Marshal(struct {
		Version  int       `json:"resolver_version"`
		Mappings []mapping `json:"mappings"`
	}{Version: GCOwnershipResolverVersion, Mappings: mappings})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (o storageOwnership) gcTargetDescriptor(repo *Repository) (GCTargetDescriptor, error) {
	service, err := o.gcKnownService(repo.StorageID)
	if err != nil {
		return GCTargetDescriptor{}, err
	}
	switch service.provider {
	case block.BlockstoreTypeS3, block.BlockstoreTypeGS, block.BlockstoreTypeAzure:
	default:
		return GCTargetDescriptor{}, fmt.Errorf("GC target provider %q: %w", service.provider, block.ErrOperationNotSupported)
	}
	location, err := parsePhysicalLocation(repo.StorageNamespace, service.provider)
	if err != nil {
		return GCTargetDescriptor{}, err
	}
	uri, err := url.ParseRequestURI(repo.StorageNamespace)
	if err != nil || uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" {
		return GCTargetDescriptor{}, fmt.Errorf("GC target namespace: %w", block.ErrInvalidAddress)
	}
	prefix := strings.TrimSuffix(location.key, "/")
	if prefix != "" {
		prefix += "/"
	}
	descriptor := GCTargetDescriptor{
		ResolverVersion: GCOwnershipResolverVersion,
		Provider:        service.provider, Service: service.service,
		Routes: slices.Clone(service.routes), NamespacePrefix: prefix,
	}
	if service.provider == block.BlockstoreTypeAzure {
		accountAndContainer := strings.TrimPrefix(location.container, "azure://")
		descriptor.Account, descriptor.Container, _ = strings.Cut(accountAndContainer, "/")
	} else {
		descriptor.Bucket = uri.Host
	}
	return descriptor, nil
}
