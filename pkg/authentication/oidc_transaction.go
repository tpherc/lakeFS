package authentication

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
)

const (
	oidcTransactionSessionKey = "transaction"
	oidcTransactionTTL        = 10 * time.Minute
	oidcClaimsMaxJSONSize     = 2048
)

type oidcTransaction struct {
	StateValue   string `json:"state"`
	NonceValue   string `json:"nonce"`
	RedirectURI  string `json:"redirect_uri"`
	Next         string `json:"next,omitempty"`
	CodeVerifier string `json:"code_verifier"`
	StartedAt    int64  `json:"started_at"`
	MaxAge       *uint  `json:"max_age,omitempty"`
}

func (t *oidcTransaction) validateCallbackState(state string, now time.Time) error {
	if t == nil || t.StateValue == "" || t.NonceValue == "" || t.RedirectURI == "" || t.StartedAt == 0 {
		return fmt.Errorf("%w: incomplete OIDC login transaction", ErrInvalidRequest)
	}
	if t.CodeVerifier == "" {
		return fmt.Errorf("%w: OIDC login transaction missing PKCE verifier", ErrInvalidRequest)
	}
	if state == "" || state != t.StateValue {
		return fmt.Errorf("%w: OIDC callback state mismatch", ErrInvalidRequest)
	}
	if t.expiresAt().Before(now) || t.expiresAt().Equal(now) {
		return fmt.Errorf("%w: OIDC login transaction expired", ErrInvalidRequest)
	}
	return nil
}

func (t *oidcTransaction) expiresAt() time.Time {
	if t == nil || t.StartedAt == 0 {
		return time.Time{}
	}
	return time.Unix(t.StartedAt, 0).Add(oidcTransactionTTL)
}

func cloneUint(value *uint) *uint {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

type oidcSessionStore struct {
	store sessions.Store
}

type oidcSession struct {
	session *sessions.Session
	request *http.Request
	writer  http.ResponseWriter
}

func (s oidcSessionStore) Load(w http.ResponseWriter, r *http.Request) (*oidcSession, error) {
	session, err := s.store.Get(r, auth.OIDCAuthSessionName)
	if err != nil {
		return nil, err
	}
	return &oidcSession{
		session: session,
		request: r,
		writer:  w,
	}, nil
}

func (s oidcSessionStore) SaveTransaction(w http.ResponseWriter, r *http.Request, transaction *oidcTransaction) error {
	session, err := auth.SessionForReplacement(s.store, r, auth.OIDCAuthSessionName)
	if err != nil {
		return err
	}
	data, err := json.Marshal(transaction)
	if err != nil {
		return err
	}
	session.Values[oidcTransactionSessionKey] = string(data)
	delete(session.Values, auth.IDTokenClaimsSessionKey)
	return auth.SaveSession(r, w, session)
}

func (s *oidcSession) Transaction() (*oidcTransaction, error) {
	data, _ := s.session.Values[oidcTransactionSessionKey].(string)
	if data == "" {
		return nil, fmt.Errorf("%w: OIDC login transaction is missing", ErrInvalidRequest)
	}
	var transaction oidcTransaction
	if err := json.Unmarshal([]byte(data), &transaction); err != nil {
		return nil, fmt.Errorf("decode OIDC login transaction: %w", err)
	}
	return &transaction, nil
}

func (s *oidcSession) ClearTransactionAndSave() error {
	clearOIDCTransactionValue(s.session)
	return s.Save()
}

func (s *oidcSession) Save() error {
	return auth.SaveSession(s.request, s.writer, s.session)
}

func (s *oidcSession) SaveClaims(claims encoding.Claims, expiresAt time.Time) error {
	data, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	if len(data) > oidcClaimsMaxJSONSize {
		return fmt.Errorf("%w: normalized OIDC claims exceed %d bytes", ErrInvalidRequest, oidcClaimsMaxJSONSize)
	}
	s.session.Values[auth.IDTokenClaimsSessionKey] = string(data)
	auth.MarkOIDCSessionClaimsCurrent(s.session, expiresAt)
	clearOIDCTransactionValue(s.session)
	return s.Save()
}

func clearOIDCTransactionValue(session *sessions.Session) {
	delete(session.Values, oidcTransactionSessionKey)
}
