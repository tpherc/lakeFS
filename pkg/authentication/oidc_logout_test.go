package authentication

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/config"
)

func TestOIDCLogoutRedirectURL(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		provider  config.OIDCProvider
		wantURL   string
		wantQuery map[string]string
		wantErr   bool
	}{
		{
			name:    "relative default with no OIDC logout parameters",
			raw:     "/auth/login",
			wantURL: "/auth/login",
		},
		{
			name: "configured absolute URL preserves existing query",
			raw:  "https://configured.example.com/logout?existing=true",
			provider: config.OIDCProvider{
				ClientID:                     "lakefs-client",
				LogoutClientIDQueryParameter: "client_id",
				LogoutEndpointQueryParameters: []string{
					"returnTo", "https://lakefs.example.com/auth/login",
				},
			},
			wantURL: "https://configured.example.com/logout",
			wantQuery: map[string]string{
				"client_id": "lakefs-client",
				"existing":  "true",
				"returnTo":  "https://lakefs.example.com/auth/login",
			},
		},
		{
			name: "client id parameter is applied last",
			raw:  "https://configured.example.com/logout?client_id=old",
			provider: config.OIDCProvider{
				ClientID:                     "lakefs-client",
				LogoutClientIDQueryParameter: "client_id",
				LogoutEndpointQueryParameters: []string{
					"client_id", "static-client",
				},
			},
			wantURL: "https://configured.example.com/logout",
			wantQuery: map[string]string{
				"client_id": "lakefs-client",
			},
		},
		{
			name: "trims provider logout query parameter keys",
			raw:  "https://idp.example.com/logout",
			provider: config.OIDCProvider{
				ClientID:                     "lakefs-client",
				LogoutClientIDQueryParameter: " client_id ",
				LogoutEndpointQueryParameters: []string{
					" returnTo ", "https://lakefs.example.com/auth/login",
				},
			},
			wantURL: "https://idp.example.com/logout",
			wantQuery: map[string]string{
				"client_id": "lakefs-client",
				"returnTo":  "https://lakefs.example.com/auth/login",
			},
		},
		{
			name: "rejects unmatched query parameter list",
			raw:  "https://idp.example.com/logout",
			provider: config.OIDCProvider{
				LogoutEndpointQueryParameters: []string{"returnTo"},
			},
			wantErr: true,
		},
		{
			name: "rejects empty query parameter key",
			raw:  "https://idp.example.com/logout",
			provider: config.OIDCProvider{
				LogoutEndpointQueryParameters: []string{"", "https://lakefs.example.com/auth/login"},
			},
			wantErr: true,
		},
		{name: "rejects empty URL", raw: "  ", wantErr: true},
		{name: "rejects invalid URL", raw: "://bad", wantErr: true},
		{name: "rejects rootless relative URL", raw: "logout", wantErr: true},
		{name: "rejects network path URL", raw: "//idp.example.com/logout", wantErr: true},
		{name: "rejects unsupported absolute scheme", raw: "ftp://idp.example.com/logout", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := compileOIDCLogoutURL(tt.raw, tt.provider)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assertLogoutURL(t, got, tt.wantURL, tt.wantQuery)
		})
	}
}

func assertLogoutURL(t *testing.T, got, wantURL string, wantQuery map[string]string) {
	t.Helper()
	gotParsed, err := url.Parse(got)
	require.NoError(t, err)
	wantParsed, err := url.Parse(wantURL)
	require.NoError(t, err)
	require.Equal(t, wantParsed.Scheme, gotParsed.Scheme)
	require.Equal(t, wantParsed.Host, gotParsed.Host)
	require.Equal(t, wantParsed.Path, gotParsed.Path)
	for key, wantValue := range wantQuery {
		require.Equal(t, wantValue, gotParsed.Query().Get(key), "query %q", key)
	}
}
