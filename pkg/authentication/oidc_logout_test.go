package authentication

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/config"
)

func TestOIDCLogoutRedirectURL(t *testing.T) {
	tests := []struct {
		name               string
		fallbackURL        string
		endSessionEndpoint string
		provider           config.OIDCProvider
		wantURL            string
		wantQuery          map[string]string
		wantErr            bool
	}{
		{
			name:        "no OIDC logout parameters",
			fallbackURL: "/auth/login",
			wantURL:     "/auth/login",
		},
		{
			name:               "uses discovered end session endpoint",
			fallbackURL:        "/auth/login",
			endSessionEndpoint: "https://idp.example.com/logout?existing=true",
			provider: config.OIDCProvider{
				ClientID:                     "lakefs-client",
				LogoutClientIDQueryParameter: "client_id",
				LogoutEndpointQueryParameters: []string{
					"returnTo", "https://lakefs.example.com/auth/login",
				},
			},
			wantURL: "https://idp.example.com/logout",
			wantQuery: map[string]string{
				"client_id": "lakefs-client",
				"existing":  "true",
				"returnTo":  "https://lakefs.example.com/auth/login",
			},
		},
		{
			name:        "falls back when endpoint is not discovered",
			fallbackURL: "https://configured.example.com/logout?existing=true",
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
			name:               "trims provider logout query parameter keys",
			fallbackURL:        "/auth/login",
			endSessionEndpoint: "https://idp.example.com/logout",
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
			name:        "rejects unmatched query parameter list",
			fallbackURL: "https://idp.example.com/logout",
			provider: config.OIDCProvider{
				LogoutEndpointQueryParameters: []string{"returnTo"},
			},
			wantErr: true,
		},
		{
			name:        "rejects empty query parameter key",
			fallbackURL: "https://idp.example.com/logout",
			provider: config.OIDCProvider{
				LogoutEndpointQueryParameters: []string{"", "https://lakefs.example.com/auth/login"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newOIDCLogoutRedirect(tt.provider, tt.endSessionEndpoint).URL(tt.fallbackURL)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assertLogoutURL(t, got, tt.wantURL, tt.wantQuery)
		})
	}
}

func TestNormalizeEndSessionEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "empty", raw: "  "},
		{name: "valid", raw: " HTTPS://IDP.EXAMPLE.COM/logout?x=1 ", want: "https://idp.example.com/logout?x=1"},
		{name: "rejects relative", raw: "/logout", wantErr: true},
		{name: "rejects user info", raw: "https://user@idp.example.com/logout", wantErr: true},
		{name: "rejects fragment", raw: "https://idp.example.com/logout#fragment", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeEndSessionEndpoint(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
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
