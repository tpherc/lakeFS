// Package policytemplate compiles policy variable references separately from
// request-local attribute resolution. Policy positions and ARN matching belong
// to the authorization layer.
package policytemplate

import (
	"errors"
	"fmt"
	"strings"

	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/auth/wildcard"
)

const (
	// MaxSourceBytes bounds dynamic template source text. Static patterns retain
	// their existing behavior and are not subject to template limits.
	MaxSourceBytes = 64 * 1024
	// MaxReferences bounds reference occurrences, including repeated keys.
	MaxReferences = 128
	// MaxResolvedBytes bounds dynamic output before allocation.
	MaxResolvedBytes = 256 * 1024

	principalTagPrefix = "aws:PrincipalTag/"
	userKey            = "user"
)

var (
	ErrInvalidTemplate = errors.New("invalid policy variable template")
	ErrLimitExceeded   = errors.New("policy variable template limit exceeded")
	ErrInvalidLookup   = errors.New("policy variable lookup is required")
	ErrWildcardValue   = errors.New("policy variable PrincipalTag contains a wildcard")
)

// Lookup reads one scalar attribute from an authorization snapshot. The bool
// distinguishes an absent attribute from an existing empty string. Implementations
// must not fetch data, mutate the snapshot, or choose one value from a collection.
// PrincipalTag names arrive with their namespace and tag key canonicalized.
type Lookup func(key string) (value string, present bool)

// MatchResult distinguishes an unavailable variable from a resolved mismatch.
// The caller rejects unresolved conditions before applying negation. Otherwise,
// it negates only after combining all candidate results.
type MatchResult uint8

const (
	NoMatch MatchResult = iota
	Matched
	Unresolved
)

type reference struct {
	start    int
	end      int
	keyIndex int
}

// Template is immutable and safe to reuse across requests. Reference offsets
// always address the original source, so replacement data cannot become syntax.
type Template struct {
	source       string
	references   []reference
	keys         []string
	literalBytes int
	usesUser     bool
}

// Compile accepts PrincipalTag references and the legacy, case-sensitive user
// alias. The caller must restrict user references to resource policies. Defaults,
// special character references, nested references and other namespaces are invalid.
func Compile(source string) (*Template, error) {
	start := strings.Index(source, "${")
	if start < 0 {
		return &Template{source: source}, nil
	}
	if len(source) > MaxSourceBytes {
		return nil, fmt.Errorf("%w: source bytes", ErrLimitExceeded)
	}

	template := &Template{source: source, literalBytes: len(source)}
	keyIndices := make(map[string]int)
	for start >= 0 {
		if len(template.references) == MaxReferences {
			return nil, fmt.Errorf("%w: reference count", ErrLimitExceeded)
		}
		closing := strings.IndexByte(source[start+2:], '}')
		if closing < 0 {
			return nil, fmt.Errorf("%w at byte %d", ErrInvalidTemplate, start)
		}
		end := start + 2 + closing + 1
		key, valid := canonicalKey(source[start+2 : end-1])
		if !valid {
			return nil, fmt.Errorf("%w at byte %d", ErrInvalidTemplate, start)
		}
		index, exists := keyIndices[key]
		if !exists {
			index = len(template.keys)
			keyIndices[key] = index
			template.keys = append(template.keys, key)
		}
		template.references = append(template.references, reference{start: start, end: end, keyIndex: index})
		template.literalBytes -= end - start
		template.usesUser = template.usesUser || key == userKey

		next := strings.Index(source[end:], "${")
		if next < 0 {
			break
		}
		start = end + next
	}
	return template, nil
}

func canonicalKey(key string) (string, bool) {
	if key == userKey {
		return key, true
	}
	namespace, tag, found := strings.Cut(key, "/")
	if !found || !strings.EqualFold(namespace+"/", principalTagPrefix) || tag == "" || strings.ContainsAny(tag, "{}'\",") {
		return "", false
	}
	return principalTagPrefix + principaltags.FoldKey(tag), true
}

// UsesUser reports whether the original template contains the legacy user alias.
func (t *Template) UsesUser() bool {
	return t.usesUser
}

// Resolve reads each distinct reference once and returns request-local text.
// Missing attributes return an unresolved result; present-empty attributes are
// real values. All present values and the output size are checked before a
// missing attribute is reported, so unresolved references cannot conceal errors.
// Errors never contain attribute values.
func (t *Template) Resolve(lookup Lookup) (value string, resolved bool, err error) {
	if len(t.references) == 0 {
		return t.source, true, nil
	}
	if lookup == nil {
		return "", false, ErrInvalidLookup
	}

	var values [MaxReferences]string
	allPresent := true
	for index, key := range t.keys {
		value, present := lookup(key)
		if !present {
			allPresent = false
			continue
		}
		if len(value) > MaxResolvedBytes {
			return "", false, fmt.Errorf("%w: resolved bytes", ErrLimitExceeded)
		}
		if key != userKey && strings.ContainsAny(value, "*?") {
			return "", false, ErrWildcardValue
		}
		values[index] = value
	}
	length := t.literalBytes
	for _, ref := range t.references {
		if len(values[ref.keyIndex]) > MaxResolvedBytes-length {
			return "", false, fmt.Errorf("%w: resolved bytes", ErrLimitExceeded)
		}
		length += len(values[ref.keyIndex])
	}
	if !allPresent {
		return "", false, nil
	}

	var result strings.Builder
	result.Grow(length)
	start := 0
	for _, ref := range t.references {
		result.WriteString(t.source[start:ref.start])
		result.WriteString(values[ref.keyIndex])
		start = ref.end
	}
	result.WriteString(t.source[start:])
	return result.String(), true, nil
}

// MatchExact compares with resolved text without wildcard interpretation.
// Negation and aggregation belong to the caller.
func (t *Template) MatchExact(value string, lookup Lookup) (MatchResult, error) {
	pattern, resolved, err := t.Resolve(lookup)
	if err != nil {
		return NoMatch, err
	}
	if !resolved {
		return Unresolved, nil
	}
	if pattern == value {
		return Matched, nil
	}
	return NoMatch, nil
}

// MatchLike applies the existing wildcard matcher to resolved text. PrincipalTag
// values cannot introduce wildcards; user values retain legacy resource behavior.
func (t *Template) MatchLike(value string, lookup Lookup) (MatchResult, error) {
	pattern, resolved, err := t.Resolve(lookup)
	if err != nil {
		return NoMatch, err
	}
	if !resolved {
		return Unresolved, nil
	}
	if wildcard.Match(pattern, value) {
		return Matched, nil
	}
	return NoMatch, nil
}
