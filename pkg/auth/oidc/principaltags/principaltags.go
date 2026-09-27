// Package principaltags validates AWS-format OIDC PrincipalTags and normalizes
// them for storage in the existing OIDC claims document.
package principaltags

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
)

const (
	NamespaceClaim     = "https://aws.amazon.com/tags"
	principalTagsClaim = "principal_tags"
	flattenedPrefix    = NamespaceClaim + "/" + principalTagsClaim + "/"
	maxTags            = 50
	maxKeyLength       = 128
	maxValueLength     = 256
)

var ErrInvalidTags = errors.New("invalid OIDC PrincipalTags")

// Tags contains one value per tag. Keys retain the spelling asserted by the IdP.
type Tags map[string]string

// Extract accepts the published nested AWS example (one string per array) or
// flattened string claims. A token containing both forms is ambiguous.
func Extract(claims encoding.Claims) (Tags, error) {
	nested, err := FromNormalizedClaims(claims)
	if err != nil {
		return nil, err
	}

	flattened := make(map[string]any)
	for claimName, value := range claims {
		if !strings.HasPrefix(claimName, flattenedPrefix) {
			continue
		}
		if len(nested) != 0 {
			return nil, invalidTags("nested and flattened PrincipalTags cannot be combined")
		}
		flattened[strings.TrimPrefix(claimName, flattenedPrefix)] = value
		if len(flattened) > maxTags {
			return nil, invalidTags("tag count exceeds 50")
		}
	}
	if len(flattened) == 0 {
		return nested, nil
	}
	return validateTags(flattened, flattenedValue)
}

// FromNormalizedClaims reads only the canonical nested claim. Configured
// flattened claims may survive normalization but are not authorization inputs.
func FromNormalizedClaims(claims encoding.Claims) (Tags, error) {
	value, exists := claims[NamespaceClaim]
	if !exists {
		return nil, nil
	}
	namespace, ok := value.(map[string]any)
	if !ok {
		return nil, invalidTags("AWS tags namespace must be an object")
	}
	value, exists = namespace[principalTagsClaim]
	if !exists {
		return nil, nil
	}
	entries, ok := value.(map[string]any)
	if !ok {
		return nil, invalidTags("principal_tags must be an object")
	}
	return validateTags(entries, nestedValue)
}

// ToNestedClaim creates an independent canonical claim from validated tags.
// Transitive tag keys are not meaningful to lakeFS and are never included.
func ToNestedClaim(tags Tags) map[string]any {
	entries := make(map[string]any, len(tags))
	for key, value := range tags {
		entries[key] = []any{value}
	}
	return map[string]any{principalTagsClaim: entries}
}

// FoldKey returns a canonical identity for Unicode case-insensitive keys.
// SimpleFold includes equivalences missed by ToLower, such as sigma/final sigma.
func FoldKey(key string) string {
	return strings.Map(func(r rune) rune {
		canonical := r
		for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
			if folded < canonical {
				canonical = folded
			}
		}
		return canonical
	}, key)
}

func validateTags(entries map[string]any, readValue func(any) (string, error)) (Tags, error) {
	if len(entries) > maxTags {
		return nil, invalidTags("tag count exceeds 50")
	}
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	tags := make(Tags, len(entries))
	identities := make(map[string]struct{}, len(entries))
	for _, key := range keys {
		if err := validateText(key, 1, maxKeyLength); err != nil {
			return nil, fmt.Errorf("PrincipalTag key: %w", err)
		}
		identity := FoldKey(key)
		if _, exists := identities[identity]; exists {
			return nil, invalidTags("tag keys collide under case-insensitive comparison")
		}
		identities[identity] = struct{}{}

		value, err := readValue(entries[key])
		if err != nil {
			return nil, err
		}
		if err := validateText(value, 0, maxValueLength); err != nil {
			return nil, fmt.Errorf("PrincipalTag value: %w", err)
		}
		tags[key] = value
	}
	return tags, nil
}

func nestedValue(value any) (string, error) {
	// The v1 input contract follows the published AWS nested example. Scalar
	// nested values are deliberately unsupported despite ambiguous AWS prose.
	values, ok := value.([]any)
	if !ok || len(values) != 1 {
		return "", invalidTags("nested tag value must be a one-element array")
	}
	result, ok := values[0].(string)
	if !ok {
		return "", invalidTags("nested tag array element must be a string")
	}
	return result, nil
}

func flattenedValue(value any) (string, error) {
	result, ok := value.(string)
	if !ok {
		return "", invalidTags("flattened tag value must be a string")
	}
	return result, nil
}

func validateText(value string, minLength, maxLength int) error {
	length := utf8.RuneCountInString(value)
	if length < minLength || length > maxLength {
		return invalidTags("tag length is outside the permitted Unicode character range")
	}
	if strings.HasPrefix(FoldKey(value), "AWS:") {
		return invalidTags("aws: is a reserved tag prefix")
	}
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.Is(unicode.Z, r) || unicode.IsNumber(r) || strings.ContainsRune("_.:/=+-@", r) {
			continue
		}
		return invalidTags("tag contains a character outside the AWS tag character set")
	}
	return nil
}

func invalidTags(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidTags, reason)
}
