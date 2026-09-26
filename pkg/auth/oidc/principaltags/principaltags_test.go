package principaltags_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
)

const flattenedPrefix = principaltags.NamespaceClaim + "/principal_tags/"

func TestExtractAWSForms(t *testing.T) {
	t.Parallel()
	want := principaltags.Tags{
		"Project":    "Automation",
		"CostCenter": "987654",
		"Department": "Engineering",
	}
	fixtures := []string{
		`{"https://aws.amazon.com/tags":{"principal_tags":{"Project":["Automation"],"CostCenter":["987654"],"Department":["Engineering"]},"transitive_tag_keys":["Project"]}}`,
		`{"https://aws.amazon.com/tags/principal_tags/Project":"Automation","https://aws.amazon.com/tags/principal_tags/CostCenter":"987654","https://aws.amazon.com/tags/principal_tags/Department":"Engineering"}`,
	}
	for i, fixture := range fixtures {
		t.Run(fmt.Sprintf("form_%d", i), func(t *testing.T) {
			claims := decodeClaims(t, fixture)
			tags, err := principaltags.Extract(claims)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(tags, want) {
				t.Fatalf("tags = %#v, want %#v", tags, want)
			}
			canonical := principaltags.ToNestedClaim(tags)
			if _, found := canonical["transitive_tag_keys"]; found {
				t.Fatal("canonical claim retained transitive tag keys")
			}
			canonicalJSON, err := json.Marshal(encoding.Claims{principaltags.NamespaceClaim: canonical})
			if err != nil {
				t.Fatal(err)
			}
			roundTrip, err := principaltags.FromNormalizedClaims(decodeClaims(t, string(canonicalJSON)))
			if err != nil || !reflect.DeepEqual(roundTrip, want) {
				t.Fatalf("canonical round-trip = %#v, %v", roundTrip, err)
			}
		})
	}
}

func TestExtractTagless(t *testing.T) {
	t.Parallel()
	fixtures := []string{
		`{}`,
		`{"iss":"issuer","sub":"subject"}`,
		`{"https://aws.amazon.com/tags":{}}`,
		`{"https://aws.amazon.com/tags":{"transitive_tag_keys":["Project"]}}`,
		`{"https://aws.amazon.com/tags":{"principal_tags":{}}}`,
	}
	for _, fixture := range fixtures {
		tags, err := principaltags.Extract(decodeClaims(t, fixture))
		if err != nil || len(tags) != 0 {
			t.Errorf("Extract(%s) = %#v, %v", fixture, tags, err)
		}
	}
}

func TestExtractNamespaceWithoutTagsAllowsFlattenedTags(t *testing.T) {
	t.Parallel()
	for _, namespace := range []map[string]any{
		{"transitive_tag_keys": []any{"Project"}},
		{"principal_tags": map[string]any{}},
	} {
		tags, err := principaltags.Extract(encoding.Claims{
			principaltags.NamespaceClaim: namespace,
			flattenedPrefix + "Project":  "Automation",
		})
		if err != nil || !reflect.DeepEqual(tags, principaltags.Tags{"Project": "Automation"}) {
			t.Fatalf("Extract = %#v, %v", tags, err)
		}
	}
}

func TestExtractMalformedStructures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		claims encoding.Claims
	}{
		{"null namespace", encoding.Claims{principaltags.NamespaceClaim: nil}},
		{"scalar namespace", encoding.Claims{principaltags.NamespaceClaim: "invalid"}},
		{"array namespace", encoding.Claims{principaltags.NamespaceClaim: []any{}}},
		{"null principal tags", namespaceClaims(nil)},
		{"scalar principal tags", namespaceClaims("invalid")},
		{"array principal tags", namespaceClaims([]any{})},
		{"nested scalar deliberately unsupported in v1", nestedClaims("Project", "Automation")},
		{"nested null", nestedClaims("Project", nil)},
		{"nested empty array", nestedClaims("Project", []any{})},
		{"nested multiple values", nestedClaims("Project", []any{"A", "B"})},
		{"nested number", nestedClaims("Project", []any{42.0})},
		{"nested boolean", nestedClaims("Project", []any{true})},
		{"nested null element", nestedClaims("Project", []any{nil})},
		{"nested object", nestedClaims("Project", []any{map[string]any{}})},
		{"flattened array", encoding.Claims{flattenedPrefix + "Project": []any{"Automation"}}},
		{"flattened number", encoding.Claims{flattenedPrefix + "Project": 42.0}},
		{"flattened boolean", encoding.Claims{flattenedPrefix + "Project": true}},
		{"flattened null", encoding.Claims{flattenedPrefix + "Project": nil}},
		{"flattened empty key", encoding.Claims{flattenedPrefix: "Automation"}},
		{"ambiguous forms", encoding.Claims{
			principaltags.NamespaceClaim:   principaltags.ToNestedClaim(principaltags.Tags{"Project": "Automation"}),
			flattenedPrefix + "Department": "Engineering",
		}},
		{"ambiguous identical tags", encoding.Claims{
			principaltags.NamespaceClaim: principaltags.ToNestedClaim(principaltags.Tags{"Project": "Automation"}),
			flattenedPrefix + "Project":  "Automation",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tags, err := principaltags.Extract(tt.claims)
			if !errors.Is(err, principaltags.ErrInvalidTags) || tags != nil {
				t.Fatalf("Extract = %#v, %v; want no partial tags and ErrInvalidTags", tags, err)
			}
		})
	}
}

func TestExtractTagValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		key   string
		value string
		valid bool
	}{
		{"empty value", "Project", "", true},
		{"empty key", "", "A", false},
		{"128 Unicode key characters", strings.Repeat("界", 128), "A", true},
		{"129 Unicode key characters", strings.Repeat("界", 129), "A", false},
		{"256 Unicode value characters", "Project", strings.Repeat("界", 256), true},
		{"257 Unicode value characters", "Project", strings.Repeat("界", 257), false},
		{"Unicode letters and numbers", "Équipe日本", "Ⅷ１２٣", true},
		{"spaces and separators", "Project Team", "A\u00a0B\u2028C", true},
		{"allowed punctuation", "_.:/=+-@", "_.:/=+-@", true},
		{"asterisk in key", "Project*", "A", false},
		{"asterisk in value", "Project", "A*", false},
		{"question mark in key", "Project?", "A", false},
		{"question mark in value", "Project", "A?", false},
		{"tab", "Project", "A\tB", false},
		{"newline", "Project", "A\nB", false},
		{"combining mark", "Project", "e\u0301", false},
		{"emoji", "Project", "😀", false},
		{"invalid UTF-8 key", "\xff", "A", false},
		{"invalid UTF-8 value", "Project", "\xff", false},
		{"reserved lowercase key", "aws:Project", "A", false},
		{"reserved uppercase key", "AWS:Project", "A", false},
		{"reserved mixed-case key", "aWs:Project", "A", false},
		{"reserved lowercase value", "Project", "aws:restricted", false},
		{"reserved uppercase value", "Project", "AWS:restricted", false},
		{"reserved mixed-case value", "Project", "aWs:restricted", false},
		{"reserved prefix Unicode equivalent", "awſ:Project", "A", false},
		{"prefix only reserved at start", "myaws:Project", "notaws:reserved", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forms := []encoding.Claims{
				nestedClaims(tt.key, []any{tt.value}),
				{flattenedPrefix + tt.key: tt.value},
			}
			for _, claims := range forms {
				tags, err := principaltags.Extract(claims)
				if tt.valid {
					if err != nil || !reflect.DeepEqual(tags, principaltags.Tags{tt.key: tt.value}) {
						t.Fatalf("Extract = %#v, %v", tags, err)
					}
				} else if !errors.Is(err, principaltags.ErrInvalidTags) || tags != nil {
					t.Fatalf("Extract = %#v, %v; want no partial tags and ErrInvalidTags", tags, err)
				}
			}
		})
	}
}

func TestExtractTagCount(t *testing.T) {
	t.Parallel()
	for _, count := range []int{50, 51} {
		tags := make(principaltags.Tags, count)
		flattened := make(encoding.Claims, count)
		for i := range count {
			key := fmt.Sprintf("tag-%02d", i)
			tags[key] = "value"
			flattened[flattenedPrefix+key] = "value"
		}
		for _, claims := range []encoding.Claims{
			{principaltags.NamespaceClaim: principaltags.ToNestedClaim(tags)},
			flattened,
		} {
			got, err := principaltags.Extract(claims)
			if count == 50 {
				if err != nil || !reflect.DeepEqual(got, tags) {
					t.Fatalf("50 tags = %#v, %v", got, err)
				}
			} else if !errors.Is(err, principaltags.ErrInvalidTags) || got != nil {
				t.Fatalf("51 tags = %#v, %v; want complete-set rejection", got, err)
			}
		}
	}
}

func TestExtractCaseCollisions(t *testing.T) {
	t.Parallel()
	for _, pair := range [][2]string{{"Project", "project"}, {"Σ", "ς"}, {"K", "K"}, {"S", "ſ"}} {
		t.Run(pair[0]+"_"+pair[1], func(t *testing.T) {
			for _, claims := range []encoding.Claims{
				{principaltags.NamespaceClaim: principaltags.ToNestedClaim(principaltags.Tags{pair[0]: "A", pair[1]: "B"})},
				{flattenedPrefix + pair[0]: "A", flattenedPrefix + pair[1]: "B"},
			} {
				for range 10 {
					tags, err := principaltags.Extract(claims)
					if !errors.Is(err, principaltags.ErrInvalidTags) || tags != nil {
						t.Fatalf("case collision = %#v, %v", tags, err)
					}
				}
			}
		})
	}
}

func TestFromNormalizedClaimsCanonicalAuthority(t *testing.T) {
	t.Parallel()
	want := principaltags.Tags{"Project": "Trusted"}
	claims := encoding.Claims{
		principaltags.NamespaceClaim: principaltags.ToNestedClaim(want),
		flattenedPrefix + "Project":  "Other",
		flattenedPrefix + "Invalid":  false,
	}
	tags, err := principaltags.FromNormalizedClaims(claims)
	if err != nil || !reflect.DeepEqual(tags, want) {
		t.Fatalf("canonical authority = %#v, %v", tags, err)
	}
	delete(claims, principaltags.NamespaceClaim)
	tags, err = principaltags.FromNormalizedClaims(claims)
	if err != nil || len(tags) != 0 {
		t.Fatalf("flattened claims became authorization inputs: %#v, %v", tags, err)
	}
	claims[principaltags.NamespaceClaim] = map[string]any{"principal_tags": "malformed"}
	tags, err = principaltags.FromNormalizedClaims(claims)
	if !errors.Is(err, principaltags.ErrInvalidTags) || tags != nil {
		t.Fatalf("malformed canonical claim = %#v, %v", tags, err)
	}
}

func TestToNestedClaimIndependentSnapshot(t *testing.T) {
	t.Parallel()
	tags := principaltags.Tags{"Project": "Original"}
	claim := principaltags.ToNestedClaim(tags)
	tags["Project"] = "Changed"
	tags["Added"] = "Later"
	got, err := principaltags.FromNormalizedClaims(encoding.Claims{principaltags.NamespaceClaim: claim})
	if err != nil || !reflect.DeepEqual(got, principaltags.Tags{"Project": "Original"}) {
		t.Fatalf("canonical claim changed with source tags: %#v, %v", got, err)
	}
	got["Project"] = "Caller mutation"
	again, err := principaltags.FromNormalizedClaims(encoding.Claims{principaltags.NamespaceClaim: claim})
	if err != nil || again["Project"] != "Original" {
		t.Fatalf("parsed result mutated stored claim: %#v, %v", again, err)
	}
}

func TestFoldKey(t *testing.T) {
	t.Parallel()
	for _, pair := range [][2]string{
		{"aws:PrincipalTag/Project", "AWS:PRINCIPALTAG/project"},
		{"Σ", "σ"}, {"σ", "ς"}, {"K", "K"}, {"S", "ſ"},
		{"Équipe", "éQUIPE"}, {"项目", "项目"},
		{"I", "ı"}, {"I", "İ"}, {"ss", "ß"}, {"A", "B"},
	} {
		got := principaltags.FoldKey(pair[0]) == principaltags.FoldKey(pair[1])
		if got != strings.EqualFold(pair[0], pair[1]) {
			t.Errorf("FoldKey(%q) == FoldKey(%q) is %v, disagrees with EqualFold", pair[0], pair[1], got)
		}
	}
}

func TestErrorsDoNotExposeTagContents(t *testing.T) {
	t.Parallel()
	const privateKey = "private-directory-attribute"
	const privateValue = "confidential-idp-value?"
	claims := nestedClaims(privateKey, []any{privateValue})
	_, err := principaltags.Extract(claims)
	if err == nil {
		t.Fatal("expected invalid-character error")
	}
	if strings.Contains(err.Error(), privateKey) || strings.Contains(err.Error(), privateValue) {
		t.Fatalf("error exposed tag contents: %v", err)
	}
}

func decodeClaims(t *testing.T, raw string) encoding.Claims {
	t.Helper()
	var claims encoding.Claims
	if err := json.Unmarshal([]byte(raw), &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func namespaceClaims(entries any) encoding.Claims {
	return encoding.Claims{principaltags.NamespaceClaim: map[string]any{"principal_tags": entries}}
}

func nestedClaims(key string, value any) encoding.Claims {
	return namespaceClaims(map[string]any{key: value})
}
