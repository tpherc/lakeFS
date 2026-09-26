package policytemplate_test

import (
	"strings"
	"testing"

	"github.com/treeverse/lakefs/pkg/auth/policytemplate"
	"github.com/treeverse/lakefs/pkg/auth/wildcard"
)

func BenchmarkCompile(b *testing.B) {
	for _, tt := range []struct{ name, source string }{
		{"static", "repository/data/object/team/*"},
		{"tag", "repository/data/object/${aws:PrincipalTag/team}/*"},
		{"repeated", strings.Repeat("${aws:PrincipalTag/team}/", 8)},
	} {
		b.Run(tt.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := policytemplate.Compile(tt.source); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkResolve(b *testing.B) {
	for _, tt := range []struct{ name, source string }{
		{"static", "repository/data/object/team/*"},
		{"tag", "repository/data/object/${aws:PrincipalTag/team}/*"},
		{"repeated", strings.Repeat("${aws:PrincipalTag/team}/", 8)},
	} {
		b.Run(tt.name, func(b *testing.B) {
			template := compileTemplate(b, tt.source)
			lookup := tagLookup(map[string]string{"team": "blue"})
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, resolved, err := template.Resolve(lookup); err != nil || !resolved {
					b.Fatalf("Resolve() = %v, %v", resolved, err)
				}
			}
		})
	}
}

func BenchmarkMatchLike(b *testing.B) {
	const pattern = "repository/data/object/blue/*"
	const value = "repository/data/object/blue/path/file"
	b.Run("wildcard_baseline", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if !wildcard.Match(pattern, value) {
				b.Fatal("no match")
			}
		}
	})
	b.Run("static_template", func(b *testing.B) {
		template := compileTemplate(b, pattern)
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if result, err := template.MatchLike(value, nil); err != nil || result != policytemplate.Matched {
				b.Fatalf("MatchLike() = %v, %v", result, err)
			}
		}
	})
	b.Run("dynamic_template", func(b *testing.B) {
		template := compileTemplate(b, "repository/data/object/${aws:PrincipalTag/team}/*")
		lookup := tagLookup(map[string]string{"team": "blue"})
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if result, err := template.MatchLike(value, lookup); err != nil || result != policytemplate.Matched {
				b.Fatalf("MatchLike() = %v, %v", result, err)
			}
		}
	})
}
