package auth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/hkdf"
)

const (
	sessionAuthKeyInfo  = "lakefs session cookie authentication key v1"
	sessionBlockKeyInfo = "lakefs session cookie encryption key v1"

	sessionAuthKeySize  = 64
	sessionBlockKeySize = 32

	sessionEncodingVersionKey     = "_lakefs_session_encoding_version"
	currentSessionEncodingVersion = 1
)

type SessionStoreOptions struct {
	MaxAge int
	Secure bool
}

func NewSessionStore(sharedSecret []byte, options SessionStoreOptions) (*sessions.CookieStore, error) {
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("empty session secret")
	}
	authKey, err := deriveSessionKey(sharedSecret, sessionAuthKeyInfo, sessionAuthKeySize)
	if err != nil {
		return nil, err
	}
	blockKey, err := deriveSessionKey(sharedSecret, sessionBlockKeyInfo, sessionBlockKeySize)
	if err != nil {
		return nil, err
	}
	store := sessions.NewCookieStore(
		authKey, blockKey, // new encrypted cookies
		sharedSecret, // decode-only fallback for old signed cookies
	)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   options.MaxAge,
		HttpOnly: true,
		Secure:   options.Secure,
		SameSite: http.SameSiteLaxMode,
	}
	return store, nil
}

func ClearSession(w http.ResponseWriter, r *http.Request, sessionStore sessions.Store, sessionName string) error {
	session, err := sessionStore.Get(r, sessionName)
	if err != nil && !IsSessionDecodeError(err) {
		return err
	}
	if session == nil {
		return fmt.Errorf("session store returned nil session for %q", sessionName)
	}
	session.Options.MaxAge = -1
	session.Values = make(map[interface{}]interface{})
	return session.Save(r, w)
}

func SessionForReplacement(sessionStore sessions.Store, r *http.Request, sessionName string) (*sessions.Session, error) {
	session, err := sessionStore.Get(r, sessionName)
	if err != nil && !IsSessionDecodeError(err) {
		return nil, err
	}
	if session == nil {
		return nil, fmt.Errorf("session store returned nil session for %q", sessionName)
	}
	session.Values = make(map[interface{}]interface{})
	session.IsNew = true
	return session, nil
}

func SessionNeedsEncodingUpgrade(session *sessions.Session) bool {
	if session == nil {
		return false
	}
	version, ok := session.Values[sessionEncodingVersionKey].(int)
	return !ok || version != currentSessionEncodingVersion
}

func SaveSession(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	if session == nil {
		return fmt.Errorf("cannot save nil session")
	}
	session.Values[sessionEncodingVersionKey] = currentSessionEncodingVersion
	return session.Save(r, w)
}

// IsSessionDecodeError reports whether err is a recoverable secure-cookie decode failure.
func IsSessionDecodeError(err error) bool {
	var cookieErr securecookie.Error
	return errors.As(err, &cookieErr) &&
		cookieErr.IsDecode() &&
		!cookieErr.IsUsage() &&
		!cookieErr.IsInternal()
}

func deriveSessionKey(secret []byte, info string, size int) ([]byte, error) {
	reader := hkdf.New(sha256.New, secret, nil, []byte(info))
	key := make([]byte, size)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	return key, nil
}
