package policytemplate_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/treeverse/lakefs/pkg/auth/policytemplate"
	"github.com/treeverse/lakefs/pkg/auth/wildcard"
)

func FuzzCompileResolve(f *testing.F) {
	for _, source := range []string{
		"", "plain/*", "${", "${aws:PrincipalTag/team}", "${user}",
		"before/${AWS:PRINCIPALTAG/σ}/${aws:PrincipalTag/ς}",
		"${aws:PrincipalTag/${user}}", "${aws:PrincipalTag/team, 'default'}",
	} {
		f.Add(source)
	}
	f.Fuzz(func(t *testing.T, source string) {
		if len(source) > policytemplate.MaxSourceBytes*2 {
			t.Skip()
		}
		template, err := policytemplate.Compile(source)
		if err != nil {
			if template != nil || (!errors.Is(err, policytemplate.ErrInvalidTemplate) && !errors.Is(err, policytemplate.ErrLimitExceeded)) {
				t.Fatalf("Compile() = %v, %v", template, err)
			}
			return
		}
		lookup := func(string) (string, bool) { return "value", true }
		got, resolved, err := template.Resolve(lookup)
		if err != nil || !resolved {
			t.Fatalf("accepted template failed resolution: %v, %v", resolved, err)
		}
		if !strings.Contains(source, "${") && got != source {
			t.Fatal("static source changed")
		}
		if strings.Contains(source, "${") && len(got) > policytemplate.MaxResolvedBytes {
			t.Fatal("dynamic result exceeds its size limit")
		}
		other, resolved, err := template.Resolve(lookup)
		if err != nil || !resolved || other != got {
			t.Fatal("template resolution changed across identical requests")
		}
	})
}

func FuzzResolvePreservesReplacement(f *testing.F) {
	for _, value := range []string{"", "blue", "α", "${user}", "${broken", `../a\b`, "*", "?", "a\x00b"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > policytemplate.MaxResolvedBytes {
			t.Skip()
		}
		template := compileTemplate(t, "before/${aws:PrincipalTag/team}/after")
		got, resolved, err := template.Resolve(func(string) (string, bool) { return value, true })
		switch {
		case strings.ContainsAny(value, "*?"):
			if !errors.Is(err, policytemplate.ErrWildcardValue) || resolved || got != "" {
				t.Fatalf("wildcard value accepted: %v, %v", resolved, err)
			}
		case len("before//after")+len(value) > policytemplate.MaxResolvedBytes:
			if !errors.Is(err, policytemplate.ErrLimitExceeded) || resolved || got != "" {
				t.Fatalf("oversized value accepted: %v, %v", resolved, err)
			}
		default:
			if err != nil || !resolved || got != "before/"+value+"/after" {
				t.Fatalf("replacement was interpreted: %v, %v", resolved, err)
			}
		}
	})
}

func FuzzStaticMatchParity(f *testing.F) {
	for _, pair := range [][2]string{{"", ""}, {"*", ""}, {"?", "α"}, {"a/*", "a/b/c"}, {`a\?`, `a\x`}} {
		f.Add(pair[0], pair[1])
	}
	f.Fuzz(func(t *testing.T, pattern, value string) {
		if strings.Contains(pattern, "${") || len(pattern) > 1024 || len(value) > 1024 {
			t.Skip()
		}
		template := compileTemplate(t, pattern)
		got, err := template.MatchLike(value, nil)
		if err != nil || (got == policytemplate.Matched) != wildcard.Match(pattern, value) {
			t.Fatalf("static Like changed: %v, %v", got, err)
		}
		got, err = template.MatchExact(value, nil)
		if err != nil || (got == policytemplate.Matched) != (pattern == value) {
			t.Fatalf("static Equals changed: %v, %v", got, err)
		}
	})
}
