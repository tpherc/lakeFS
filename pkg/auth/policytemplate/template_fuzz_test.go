package policytemplate_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
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
			require.Nil(t, template)
			require.True(t, errors.Is(err, policytemplate.ErrInvalidTemplate) || errors.Is(err, policytemplate.ErrLimitExceeded), "unexpected compile error: %v", err)
			return
		}
		lookup := func(string) (string, bool) { return "value", true }
		got, resolved, err := template.Resolve(lookup)
		require.NoError(t, err)
		require.True(t, resolved, "accepted template must resolve")
		if strings.Contains(source, "${") {
			require.LessOrEqual(t, len(got), policytemplate.MaxResolvedBytes)
		} else {
			require.Equal(t, source, got, "static source changed")
		}
		other, resolved, err := template.Resolve(lookup)
		require.NoError(t, err)
		require.True(t, resolved)
		require.Equal(t, got, other, "template resolution changed across identical requests")
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
			require.ErrorIs(t, err, policytemplate.ErrWildcardValue)
			require.False(t, resolved)
			require.Empty(t, got)
		case len("before//after")+len(value) > policytemplate.MaxResolvedBytes:
			require.ErrorIs(t, err, policytemplate.ErrLimitExceeded)
			require.False(t, resolved)
			require.Empty(t, got)
		default:
			require.NoError(t, err)
			require.True(t, resolved)
			require.Equal(t, "before/"+value+"/after", got, "replacement was interpreted")
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
