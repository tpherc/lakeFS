package api

import (
	"context"
	"errors"
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
	authConfig := &config.BaseAuth{LogoutRedirectURL: "/auth/login"}
	handler := NewLogoutHandler(
		testSessionStore(t),
		logging.ContextUnavailable(),
		authConfig,
		staticLogoutRedirectResolver{url: "https://idp.example.com/logout?client_id=lakefs-client&returnTo=https%3A%2F%2Flakefs.example.com%2Foidc%2Flogin"},
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

func TestLogoutHandlerAttemptsAllSessionClears(t *testing.T) {
	store := &recordingSessionStore{
		getErrors: map[string]error{
			auth.InternalAuthSessionName: errors.New("internal store failure"),
		},
	}
	handler := NewLogoutHandler(
		store,
		logging.ContextUnavailable(),
		&config.BaseAuth{LogoutRedirectURL: "/auth/login"},
		nil,
	)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/logout", nil)
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusTemporaryRedirect {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusTemporaryRedirect)
	}
	assertEqualStrings(t, store.gets, []string{
		auth.InternalAuthSessionName,
		auth.OIDCAuthSessionName,
		auth.SAMLAuthSessionName,
	})
	assertEqualStrings(t, store.saves, []string{
		auth.OIDCAuthSessionName,
		auth.SAMLAuthSessionName,
	})
}

func TestLogoutHandlerFailsOnlyWhenAllSessionClearsFail(t *testing.T) {
	store := &recordingSessionStore{
		getErrors: map[string]error{
			auth.InternalAuthSessionName: errors.New("internal store failure"),
			auth.OIDCAuthSessionName:     errors.New("oidc store failure"),
			auth.SAMLAuthSessionName:     errors.New("saml store failure"),
		},
	}
	handler := NewLogoutHandler(
		store,
		logging.ContextUnavailable(),
		&config.BaseAuth{LogoutRedirectURL: "/auth/login"},
		nil,
	)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/logout", nil)
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("unexpected status: got %d, want %d", recorder.Code, http.StatusInternalServerError)
	}
	assertEqualStrings(t, store.gets, []string{
		auth.InternalAuthSessionName,
		auth.OIDCAuthSessionName,
		auth.SAMLAuthSessionName,
	})
}

func TestResolveLogoutRedirectURLUsesResolver(t *testing.T) {
	authConfig := &config.BaseAuth{LogoutRedirectURL: "/auth/login"}

	got, err := resolveLogoutRedirectURL(context.Background(), authConfig, staticLogoutRedirectResolver{url: "https://idp.example.com/logout"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://idp.example.com/logout" {
		t.Fatalf("unexpected logout redirect URL: got %q", got)
	}
}

func TestResolveLogoutRedirectURLReturnsFallbackWithoutResolver(t *testing.T) {
	authConfig := &config.BaseAuth{LogoutRedirectURL: "/auth/login"}

	got, err := resolveLogoutRedirectURL(context.Background(), authConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "/auth/login" {
		t.Fatalf("unexpected logout redirect URL: got %q, want /auth/login", got)
	}
}

func assertEqualStrings(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("unexpected length: got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("unexpected strings: got %v, want %v", got, want)
		}
	}
}

type staticLogoutRedirectResolver struct {
	url string
}

func (r staticLogoutRedirectResolver) LogoutRedirectURL(_ context.Context, _ string) (string, error) {
	return r.url, nil
}

type recordingSessionStore struct {
	getErrors  map[string]error
	saveErrors map[string]error
	gets       []string
	saves      []string
}

func (s *recordingSessionStore) Get(_ *http.Request, name string) (*sessions.Session, error) {
	s.gets = append(s.gets, name)
	if err := s.getErrors[name]; err != nil {
		return nil, err
	}
	return sessions.NewSession(s, name), nil
}

func (s *recordingSessionStore) New(r *http.Request, name string) (*sessions.Session, error) {
	return s.Get(r, name)
}

func (s *recordingSessionStore) Save(_ *http.Request, _ http.ResponseWriter, session *sessions.Session) error {
	name := session.Name()
	s.saves = append(s.saves, name)
	if err := s.saveErrors[name]; err != nil {
		return err
	}
	return nil
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
