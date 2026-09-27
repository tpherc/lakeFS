package policytemplate_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/auth/policytemplate"
)

func TestStaticTemplateMatchLike(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		pattern string
		value   string
		want    policytemplate.MatchResult
	}{
		{"exact", "team-a", "team-a", policytemplate.Matched},
		{"different team", "team-a", "team-b", policytemplate.NoMatch},
		{"case sensitive", "Team-a", "team-a", policytemplate.NoMatch},
		{"authored wildcard", "team-a/*", "team-a/path/file", policytemplate.Matched},
		{"asterisk matches empty", "team-a/*", "team-a/", policytemplate.Matched},
		{"question mark requires a character", "team-?", "team-", policytemplate.NoMatch},
		{"question mark requires only one character", "team-?", "team-ab", policytemplate.NoMatch},
		{"single rune", "team-?", "team-\u03b1", policytemplate.Matched},
		{"empty literal", "", "", policytemplate.Matched},
		{"ordinary dollar", "$5", "$5", policytemplate.Matched},
	} {
		t.Run(tt.name, func(t *testing.T) {
			template, err := policytemplate.Compile(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			got, err := template.MatchLike(tt.value, func(string) (string, bool) {
				t.Fatal("a static template must not read request attributes")
				return "", false
			})
			if err != nil || got != tt.want {
				t.Fatalf("MatchLike() = %v, %v; want %v, nil", got, err, tt.want)
			}
		})
	}
}

func TestStaticTemplateMatchExact(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		pattern string
		value   string
		want    policytemplate.MatchResult
	}{
		{"exact", "team-a", "team-a", policytemplate.Matched},
		{"case sensitive", "Team-a", "team-a", policytemplate.NoMatch},
		{"asterisk is literal", "team-*", "team-a", policytemplate.NoMatch},
		{"literal asterisk matches", "team-*", "team-*", policytemplate.Matched},
		{"question mark is literal", "team-?", "team-a", policytemplate.NoMatch},
		{"empty string", "", "", policytemplate.Matched},
	} {
		t.Run(tt.name, func(t *testing.T) {
			template, err := policytemplate.Compile(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			got, err := template.MatchExact(tt.value, func(string) (string, bool) {
				t.Fatal("a static template must not read request attributes")
				return "", false
			})
			if err != nil || got != tt.want {
				t.Fatalf("MatchExact() = %v, %v; want %v, nil", got, err, tt.want)
			}
		})
	}
}

func TestCompileRejectsInvalidTemplates(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"${aws:PrincipalTag/}", "${aws:PrincipalTag}", "${AWS:PrincipalTags/team}",
		"${aws:PrincipalTag/team, 'shared'}", "${aws:PrincipalTag/team,shared}",
		"${aws:PrincipalTag/'team'}", "${aws:PrincipalTag/\"team\"}",
		"${lakefs:ObjectMetadata/team}", "${SourceIp}", "${User}",
		"${*}", "${?}", "${$}", "${unknown}", "${}", "${unterminated", "${",
		"${aws:PrincipalTag/${user}}", "${aws:PrincipalTag/team}${", "${user, 'shared'}",
	} {
		t.Run(source, func(t *testing.T) {
			template, err := policytemplate.Compile(source)
			if template != nil || !errors.Is(err, policytemplate.ErrInvalidTemplate) {
				t.Fatalf("Compile() = %v, %v; want nil, ErrInvalidTemplate", template, err)
			}
		})
	}
}

func TestResolve(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		source   string
		tags     map[string]string
		want     string
		resolved bool
	}{
		{"embedded", "prefix/${aws:PrincipalTag/team}/*", map[string]string{"team": "blue"}, "prefix/blue/*", true},
		{"adjacent and repeated", "${aws:PrincipalTag/a}${aws:PrincipalTag/b}${aws:PrincipalTag/a}", map[string]string{"a": "one", "b": "two"}, "onetwoone", true},
		{"missing", "prefix/${aws:PrincipalTag/team}/*", nil, "", false},
		{"present empty", "prefix/${aws:PrincipalTag/team}/*", map[string]string{"team": ""}, "prefix//*", true},
		{"case folding", "${AWS:PRINCIPALTAG/TeAm}", map[string]string{"team": "Blue"}, "Blue", true},
		{"unicode folding", "${aws:PrincipalTag/ς}", map[string]string{"σ": "alpha"}, "alpha", true},
		{"unicode offsets", "α/${aws:PrincipalTag/team}/β", map[string]string{"team": "γ"}, "α/γ/β", true},
		{"no recursion", "${aws:PrincipalTag/team}", map[string]string{"team": "${user}"}, "${user}", true},
		{"inserted malformed syntax is text", "${aws:PrincipalTag/team}", map[string]string{"team": "${broken"}, "${broken", true},
		{"no normalization", "${aws:PrincipalTag/team}/x", map[string]string{"team": `../blue\folder`}, `../blue\folder/x`, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			template := compileTemplate(t, tt.source)
			got, resolved, err := template.Resolve(tagLookup(tt.tags))
			if err != nil || resolved != tt.resolved || got != tt.want {
				t.Fatalf("Resolve() = %q, %v, %v; want %q, %v, nil", got, resolved, err, tt.want, tt.resolved)
			}
		})
	}
}

func TestResolveReadsEachCanonicalKeyOnce(t *testing.T) {
	t.Parallel()
	template := compileTemplate(t, "${aws:PrincipalTag/Team}/${AWS:PRINCIPALTAG/team}/${aws:PrincipalTag/TEAM}")
	calls := 0
	got, resolved, err := template.Resolve(func(key string) (string, bool) {
		calls++
		if key != "aws:PrincipalTag/"+principaltags.FoldKey("team") {
			t.Fatalf("unexpected lookup key %q", key)
		}
		return "blue", true
	})
	if err != nil || !resolved || got != "blue/blue/blue" || calls != 1 {
		t.Fatalf("Resolve() = %q, %v, %v; calls = %d", got, resolved, err, calls)
	}
}

func TestUserCompatibility(t *testing.T) {
	t.Parallel()
	template := compileTemplate(t, "${user}/${aws:PrincipalTag/team}/${user}")
	if !template.UsesUser() || compileTemplate(t, "${aws:PrincipalTag/user}").UsesUser() {
		t.Fatal("UsesUser must identify the original user alias only")
	}
	for _, username := range []string{"", "alice", "*?", "${aws:PrincipalTag/team}"} {
		t.Run(username, func(t *testing.T) {
			lookup := func(key string) (string, bool) {
				if key == "user" {
					return username, true
				}
				return "blue", true
			}
			got, resolved, err := template.Resolve(lookup)
			want := username + "/blue/" + username
			if err != nil || !resolved || got != want {
				t.Fatalf("Resolve() = %q, %v, %v; want %q, true, nil", got, resolved, err, want)
			}
		})
	}
	got, err := compileTemplate(t, "${user}").MatchLike("alice", func(string) (string, bool) { return "*", true })
	if err != nil || got != policytemplate.Matched {
		t.Fatalf("legacy username wildcard = %v, %v", got, err)
	}
}

func TestResolveErrorsOutrankMissing(t *testing.T) {
	t.Parallel()
	for _, source := range []string{
		"${aws:PrincipalTag/missing}${aws:PrincipalTag/present}",
		"${aws:PrincipalTag/present}${aws:PrincipalTag/missing}",
	} {
		for _, tt := range []struct {
			name  string
			value string
			err   error
		}{
			{"asterisk", "private*value", policytemplate.ErrWildcardValue},
			{"question mark", "private?value", policytemplate.ErrWildcardValue},
			{"resolved size", strings.Repeat("x", policytemplate.MaxResolvedBytes+1), policytemplate.ErrLimitExceeded},
		} {
			t.Run(source+"/"+tt.name, func(t *testing.T) {
				template := compileTemplate(t, source)
				lookup := tagLookup(map[string]string{"present": tt.value})
				got, resolved, err := template.Resolve(lookup)
				if got != "" || resolved || !errors.Is(err, tt.err) {
					t.Fatalf("Resolve() = %q, %v, %v; want empty, false, %v", got, resolved, err, tt.err)
				}
				if strings.Contains(err.Error(), tt.value) {
					t.Fatal("error exposes a private attribute value")
				}
				for _, match := range []func(string, policytemplate.Lookup) (policytemplate.MatchResult, error){template.MatchExact, template.MatchLike} {
					result, err := match("anything", lookup)
					if result != policytemplate.NoMatch || !errors.Is(err, tt.err) {
						t.Fatalf("match = %v, %v; want NoMatch, %v", result, err, tt.err)
					}
				}
			})
		}
	}
}

func TestDynamicMatch(t *testing.T) {
	t.Parallel()
	template := compileTemplate(t, "prefix/${aws:PrincipalTag/team}/*")
	for _, tt := range []struct {
		name  string
		tags  map[string]string
		value string
		exact policytemplate.MatchResult
		like  policytemplate.MatchResult
	}{
		{"like wildcard", map[string]string{"team": "blue"}, "prefix/blue/file", policytemplate.NoMatch, policytemplate.Matched},
		{"exact authored wildcard", map[string]string{"team": "blue"}, "prefix/blue/*", policytemplate.Matched, policytemplate.Matched},
		{"different tag", map[string]string{"team": "blue"}, "prefix/red/file", policytemplate.NoMatch, policytemplate.NoMatch},
		{"case sensitive value", map[string]string{"team": "Blue"}, "prefix/blue/file", policytemplate.NoMatch, policytemplate.NoMatch},
		{"missing", nil, "prefix//file", policytemplate.Unresolved, policytemplate.Unresolved},
		{"present empty", map[string]string{"team": ""}, "prefix//file", policytemplate.NoMatch, policytemplate.Matched},
	} {
		t.Run(tt.name, func(t *testing.T) {
			exact, err := template.MatchExact(tt.value, tagLookup(tt.tags))
			if err != nil || exact != tt.exact {
				t.Fatalf("MatchExact() = %v, %v; want %v, nil", exact, err, tt.exact)
			}
			like, err := template.MatchLike(tt.value, tagLookup(tt.tags))
			if err != nil || like != tt.like {
				t.Fatalf("MatchLike() = %v, %v; want %v, nil", like, err, tt.like)
			}
		})
	}
}

func TestDynamicLimits(t *testing.T) {
	t.Parallel()
	const ref = "${aws:PrincipalTag/team}"
	for _, tt := range []struct {
		name   string
		source string
	}{
		{"source boundary", strings.Repeat("x", policytemplate.MaxSourceBytes-len(ref)) + ref},
		{"reference boundary", strings.Repeat(ref, policytemplate.MaxReferences)},
	} {
		t.Run(tt.name, func(t *testing.T) { compileTemplate(t, tt.source) })
	}
	for _, tt := range []struct {
		name   string
		source string
	}{
		{"source over boundary", strings.Repeat("x", policytemplate.MaxSourceBytes-len(ref)+1) + ref},
		{"reference over boundary", strings.Repeat(ref, policytemplate.MaxReferences+1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			template, err := policytemplate.Compile(tt.source)
			if template != nil || !errors.Is(err, policytemplate.ErrLimitExceeded) {
				t.Fatalf("Compile() = %v, %v; want nil, ErrLimitExceeded", template, err)
			}
		})
	}
	template := compileTemplate(t, "x"+ref+ref)
	atLimit := strings.Repeat("v", (policytemplate.MaxResolvedBytes-1)/2)
	for _, value := range []string{atLimit, atLimit + "v"} {
		got, resolved, err := template.Resolve(tagLookup(map[string]string{"team": value}))
		if 1+2*len(value) > policytemplate.MaxResolvedBytes {
			if got != "" || resolved || !errors.Is(err, policytemplate.ErrLimitExceeded) {
				t.Fatalf("repeated expansion over limit = %d, %v, %v", len(got), resolved, err)
			}
		} else if err != nil || !resolved || got != "x"+value+value {
			t.Fatalf("repeated expansion within limit = %d, %v, %v", len(got), resolved, err)
		}
	}
	atExactLimit := strings.Repeat("v", policytemplate.MaxResolvedBytes)
	got, resolved, err := compileTemplate(t, ref).Resolve(tagLookup(map[string]string{"team": atExactLimit}))
	if err != nil || !resolved || got != atExactLimit {
		t.Fatalf("exact output limit = %d, %v, %v", len(got), resolved, err)
	}
}

func TestStaticTemplatesKeepExistingLimits(t *testing.T) {
	t.Parallel()
	source := strings.Repeat("x", policytemplate.MaxResolvedBytes+1)
	template := compileTemplate(t, source)
	got, resolved, err := template.Resolve(nil)
	if err != nil || !resolved || got != source {
		t.Fatalf("static template = %d, %v, %v", len(got), resolved, err)
	}
	if template.UsesUser() {
		t.Fatal("static template uses no variables")
	}
}

func TestDynamicTemplateRequiresLookup(t *testing.T) {
	t.Parallel()
	template := compileTemplate(t, "${aws:PrincipalTag/team}")
	value, resolved, err := template.Resolve(nil)
	if value != "" || resolved || !errors.Is(err, policytemplate.ErrInvalidLookup) {
		t.Fatalf("Resolve(nil) = %q, %v, %v", value, resolved, err)
	}
}

func TestTemplateConcurrentRequestIsolation(t *testing.T) {
	t.Parallel()
	template := compileTemplate(t, "prefix/${aws:PrincipalTag/team}/${user}")
	for i := range 32 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			value := fmt.Sprint(i)
			lookup := func(string) (string, bool) { return value, true }
			for range 20 {
				got, resolved, err := template.Resolve(lookup)
				if err != nil || !resolved || got != "prefix/"+value+"/"+value {
					t.Fatalf("Resolve() = %q, %v, %v", got, resolved, err)
				}
			}
		})
	}
}

func compileTemplate(t testing.TB, source string) *policytemplate.Template {
	t.Helper()
	template, err := policytemplate.Compile(source)
	if err != nil {
		t.Fatal(err)
	}
	return template
}

func tagLookup(tags map[string]string) policytemplate.Lookup {
	canonical := make(map[string]string, len(tags))
	for key, value := range tags {
		canonical["aws:PrincipalTag/"+principaltags.FoldKey(key)] = value
	}
	return func(key string) (string, bool) {
		value, present := canonical[key]
		return value, present
	}
}
