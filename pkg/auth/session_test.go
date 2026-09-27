package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/securecookie"
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

func TestSessionEncodingCannotFallBackToLegacySignedCookie(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	store, err := NewSessionStore(secret, SessionStoreOptions{MaxAge: 3600})
	require.NoError(t, err)
	legacyCodec := securecookie.New(secret, nil)
	req := httptest.NewRequest(http.MethodGet, "https://lakefs.example", nil)
	session, err := store.Get(req, OIDCAuthSessionName)
	require.NoError(t, err)
	PrepareSessionForSave(session)

	// Locate the actual production encrypted-codec boundary, without lowering it.
	low, high := 0, 4096
	for low < high {
		mid := low + (high-low)/2
		session.Values[IDTokenClaimsSessionKey] = strings.Repeat("x", mid)
		if ValidateEncryptedCookieSessionEncoding(store, session) == nil {
			low = mid + 1
		} else {
			high = mid
		}
	}
	session.Values[IDTokenClaimsSessionKey] = strings.Repeat("x", low)
	_, err = legacyCodec.Encode(session.Name(), session.Values)
	require.NoError(t, err, "the same payload fits the legacy signed-only cookie")
	require.Error(t, ValidateEncryptedCookieSessionEncoding(store, session))
	rec := httptest.NewRecorder()
	require.Error(t, SaveSession(req, rec, session))
	require.Empty(t, rec.Result().Cookies(), "encoding failure must not emit a signed-only fallback")
	_, err = store.Codecs[1].Encode(session.Name(), session.Values)
	require.ErrorIs(t, err, errLegacyCodecDecodeOnly)

	rec = httptest.NewRecorder()
	session.Values[IDTokenClaimsSessionKey] = strings.Repeat("x", low-1)
	require.NoError(t, ValidateEncryptedCookieSessionEncoding(store, session))
	require.NoError(t, SaveSession(req, rec, session))
	cookies := rec.Result().Cookies()
	require.Len(t, cookies, 1)
	require.LessOrEqual(t, len(cookies[0].Value), 4096)
	var decoded map[interface{}]interface{}
	require.NoError(t, store.Codecs[0].Decode(session.Name(), cookies[0].Value, &decoded))
	require.Error(t, legacyCodec.Decode(session.Name(), cookies[0].Value, &decoded))
}
