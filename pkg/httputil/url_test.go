package httputil

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequestBaseURLIgnoresForwardedHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://lakefs.example/repositories", nil)
	req.Header.Set("X-Forwarded-Host", "evil.example")
	req.Header.Set("Forwarded", "host=evil.example;proto=http")
	req.Header.Set("X-Forwarded-Proto", "http")
	got, err := RequestBaseURL(req)
	require.NoError(t, err)
	require.Equal(t, "https://lakefs.example", got)
}

func TestRequestBaseURLUsesObservedTLS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://lakefs.example/repositories", nil)
	req.TLS = &tls.ConnectionState{}
	got, err := RequestBaseURL(req)
	require.NoError(t, err)
	require.Equal(t, "https://lakefs.example", got)
}

func TestRequestBaseURLUsesForwardedHTTPS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://lakefs.example/repositories", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	got, err := RequestBaseURL(req)
	require.NoError(t, err)
	require.Equal(t, "https://lakefs.example", got)
}

func TestNormalizeBaseURLDefaultPortsCompareEquivalently(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{raw: "https://lakefs.example:443", want: "https://lakefs.example"},
		{raw: "http://lakefs.example:80", want: "http://lakefs.example"},
		{raw: "https://lakefs.example:8443", want: "https://lakefs.example:8443"},
		{raw: "https://[::1]:443", want: "https://[::1]"},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := NormalizeBaseURL(tt.raw)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestBaseURLUsesLoopbackHTTP(t *testing.T) {
	tests := []struct {
		raw  string
		want bool
	}{
		{raw: "http://localhost:8000", want: true},
		{raw: "http://127.0.0.1:8000", want: true},
		{raw: "http://[::1]:8000", want: true},
		{raw: "https://localhost:8000"},
		{raw: "http://localhost.example.com"},
		{raw: "http://127.0.0.1.example.com"},
		{raw: "http://10.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := BaseURLUsesLoopbackHTTP(tt.raw)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
