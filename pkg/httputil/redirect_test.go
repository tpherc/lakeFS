package httputil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSafeRelativeRedirect(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "empty"},
		{name: "absolute URL", raw: "https://evil.example/path"},
		{name: "protocol relative URL", raw: "//evil.example/path"},
		{name: "literal backslash open redirect", raw: `/\evil.example`},
		{name: "encoded backslash open redirect", raw: `/%5Cevil.example`},
		{name: "double encoded backslash open redirect", raw: `/%255Cevil.example`},
		{name: "encoded protocol relative URL", raw: `/%2Fevil.example`},
		{name: "blocked login page", raw: "/auth/login"},
		{name: "blocked login page with query", raw: "/auth/login?x=1"},
		{name: "normalized blocked page", raw: "/x/../auth/login"},
		{name: "control character", raw: "/repositories\nnext"},
		{name: "valid path", raw: "/repositories/repo/objects?prefix=data#files", want: "/repositories/repo/objects?prefix=data#files"},
		{name: "valid encoded path", raw: "/repositories/repo%20one/objects", want: "/repositories/repo%20one/objects"},
		{name: "valid root", raw: "/", want: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, SafeRelativeRedirect(tt.raw, "/auth/login"))
		})
	}
}
