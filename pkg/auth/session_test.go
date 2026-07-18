package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/sessions"
	"github.com/stretchr/testify/require"
)

func TestNewSessionStoreDecodesLegacySignedCookieAndReissuesEncrypted(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	newStore, err := NewSessionStore(secret, SessionStoreOptions{MaxAge: 3600, Secure: true})
	require.NoError(t, err)
	legacyStore := sessions.NewCookieStore(secret)
	legacyStore.Options = &sessions.Options{Path: "/", MaxAge: 3600, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode}

	legacyReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example", nil)
	legacyRec := httptest.NewRecorder()
	legacySession, err := legacyStore.Get(legacyReq, OIDCAuthSessionName)
	require.NoError(t, err)
	legacySession.Values[IDTokenClaimsSessionKey] = `{"sub":"alice","email":"alice@example.com"}`
	require.NoError(t, legacySession.Save(legacyReq, legacyRec))

	req := httptest.NewRequest(http.MethodGet, "https://lakefs.example", nil)
	req.AddCookie(legacyRec.Result().Cookies()[0])
	session, err := newStore.Get(req, OIDCAuthSessionName)
	require.NoError(t, err)
	require.Equal(t, `{"sub":"alice","email":"alice@example.com"}`, session.Values[IDTokenClaimsSessionKey])

	rec := httptest.NewRecorder()
	require.NoError(t, session.Save(req, rec))
	reissuedCookie := rec.Result().Cookies()[0]
	require.NotContains(t, reissuedCookie.Value, "alice")

	reissuedReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example", nil)
	reissuedReq.AddCookie(reissuedCookie)
	_, err = legacyStore.Get(reissuedReq, OIDCAuthSessionName)
	require.Error(t, err)
}

func TestClearSessionDeletesCorruptCookie(t *testing.T) {
	store, err := NewSessionStore([]byte("0123456789abcdef0123456789abcdef"), SessionStoreOptions{MaxAge: 3600})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://lakefs.example", nil)
	req.AddCookie(&http.Cookie{Name: OIDCAuthSessionName, Value: strings.Repeat("x", 32)})
	rec := httptest.NewRecorder()
	require.NoError(t, ClearSession(rec, req, store, OIDCAuthSessionName))

	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, OIDCAuthSessionName, cookies[0].Name)
	require.Equal(t, -1, cookies[0].MaxAge)
}

func TestSessionEncodingUpgradeMarker(t *testing.T) {
	store, err := NewSessionStore([]byte("0123456789abcdef0123456789abcdef"), SessionStoreOptions{MaxAge: 3600})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "https://lakefs.example", nil)
	session, err := store.Get(req, InternalAuthSessionName)
	require.NoError(t, err)
	require.True(t, SessionNeedsEncodingUpgrade(session))

	rec := httptest.NewRecorder()
	require.NoError(t, SaveSession(req, rec, session))

	nextReq := httptest.NewRequest(http.MethodGet, "https://lakefs.example", nil)
	nextReq.AddCookie(rec.Result().Cookies()[0])
	reissued, err := store.Get(nextReq, InternalAuthSessionName)
	require.NoError(t, err)
	require.False(t, SessionNeedsEncodingUpgrade(reissued))
}
