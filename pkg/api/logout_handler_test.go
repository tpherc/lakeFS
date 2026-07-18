package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/logging"
)

func TestLogoutHandlerClearsSessionsAndRedirectsToOIDCProviderLogout(t *testing.T) {
	authConfig := &config.BaseAuth{LogoutRedirectURL: "https://idp.example.com/logout"}
	authConfig.Providers.OIDC = &config.OIDCProvider{
		ClientID:                     "lakefs-client",
		LogoutClientIDQueryParameter: "client_id",
		LogoutEndpointQueryParameters: []string{
			"returnTo", "https://lakefs.example.com/oidc/login",
		},
	}
	handler := NewLogoutHandler(
		testSessionStore(t),
		logging.ContextUnavailable(),
		authConfig,
	)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oidc/logout", nil)
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusTemporaryRedirect)
	}
	assertURL(t, recorder.Header().Get("Location"), "https://idp.example.com/logout", map[string]string{
		"client_id": "lakefs-client",
		"returnTo":  "https://lakefs.example.com/oidc/login",
	})

	setCookie := strings.Join(recorder.Header().Values("Set-Cookie"), "\n")
	for _, sessionName := range []string{auth.InternalAuthSessionName, auth.OIDCAuthSessionName, auth.SAMLAuthSessionName} {
		if !strings.Contains(setCookie, sessionName+"=") {
			t.Fatalf("missing cleared session cookie %q in %q", sessionName, setCookie)
		}
	}
}

func TestOIDCLogoutRedirectURL(t *testing.T) {
	tests := []struct {
		name              string
		logoutRedirectURL string
		provider          *config.OIDCProvider
		wantURL           string
		wantQuery         map[string]string
		wantErr           bool
	}{
		{
			name:              "no OIDC logout parameters",
			logoutRedirectURL: "/auth/login",
			provider:          &config.OIDCProvider{},
			wantURL:           "/auth/login",
		},
		{
			name:              "adds provider logout query parameters",
			logoutRedirectURL: "https://idp.example.com/logout?existing=true",
			provider: &config.OIDCProvider{
				ClientID:                     "lakefs-client",
				LogoutClientIDQueryParameter: "client_id",
				LogoutEndpointQueryParameters: []string{
					"returnTo", "https://lakefs.example.com/oidc/login",
				},
			},
			wantURL: "https://idp.example.com/logout",
			wantQuery: map[string]string{
				"client_id": "lakefs-client",
				"existing":  "true",
				"returnTo":  "https://lakefs.example.com/oidc/login",
			},
		},
		{
			name:              "trims provider logout query parameter keys",
			logoutRedirectURL: "https://idp.example.com/logout",
			provider: &config.OIDCProvider{
				ClientID:                     "lakefs-client",
				LogoutClientIDQueryParameter: " client_id ",
				LogoutEndpointQueryParameters: []string{
					" returnTo ", "https://lakefs.example.com/oidc/login",
				},
			},
			wantURL: "https://idp.example.com/logout",
			wantQuery: map[string]string{
				"client_id": "lakefs-client",
				"returnTo":  "https://lakefs.example.com/oidc/login",
			},
		},
		{
			name:              "rejects unmatched query parameter list",
			logoutRedirectURL: "https://idp.example.com/logout",
			provider: &config.OIDCProvider{
				LogoutEndpointQueryParameters: []string{"returnTo"},
			},
			wantErr: true,
		},
		{
			name:              "rejects empty query parameter key",
			logoutRedirectURL: "https://idp.example.com/logout",
			provider: &config.OIDCProvider{
				LogoutEndpointQueryParameters: []string{"", "https://lakefs.example.com/oidc/login"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := oidcLogoutRedirectURL(tt.logoutRedirectURL, tt.provider)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assertURL(t, got, tt.wantURL, tt.wantQuery)
		})
	}
}

func TestResolveLogoutRedirectURLIgnoresUnconfiguredOIDCProvider(t *testing.T) {
	authConfig := &config.BaseAuth{LogoutRedirectURL: "/auth/login"}
	authConfig.Providers.OIDC = &config.OIDCProvider{
		LogoutEndpointQueryParameters: []string{"returnTo", "https://lakefs.example.com/oidc/login"},
	}

	got, err := resolveLogoutRedirectURL(authConfig)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/auth/login" {
		t.Fatalf("unexpected logout redirect URL: got %q, want /auth/login", got)
	}
}

func assertURL(t *testing.T, got, wantURL string, wantQuery map[string]string) {
	t.Helper()
	gotParsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	wantParsed, err := url.Parse(wantURL)
	if err != nil {
		t.Fatal(err)
	}
	if gotParsed.Scheme != wantParsed.Scheme || gotParsed.Host != wantParsed.Host || gotParsed.Path != wantParsed.Path {
		t.Fatalf("unexpected URL: got %q, want base %q", got, wantURL)
	}
	for key, wantValue := range wantQuery {
		if gotValue := gotParsed.Query().Get(key); gotValue != wantValue {
			t.Fatalf("unexpected query %q: got %q, want %q", key, gotValue, wantValue)
		}
	}
}

func testSessionStore(t *testing.T) *sessions.CookieStore {
	t.Helper()
	store, err := auth.NewSessionStore([]byte("0123456789abcdef0123456789abcdef"), auth.SessionStoreOptions{
		MaxAge: 3600,
		Secure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}
