package authentication

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	capoidc "github.com/hashicorp/cap/oidc"
	"github.com/treeverse/lakefs/pkg/auth/oidc/encoding"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/httputil"
)

const oidcProviderDiscoveryTimeout = 30 * time.Second

type oidcBeginLoginInput struct {
	CallbackURL string
	Next        string
}

type oidcCallbackInput struct {
	State string
	Code  string
}

type oidcProtocolClient interface {
	BeginLogin(context.Context, oidcBeginLoginInput) (*oidcTransaction, string, error)
	Exchange(context.Context, *oidcTransaction, oidcCallbackInput) (encoding.Claims, error)
	Close()
}

type capOIDCClient struct {
	provider        *capoidc.Provider
	authorizeMaxAge *uint
	authorizeParams map[string]string
}

func newCAPOIDCClient(ctx context.Context, providerConfig config.OIDCProvider) (*capOIDCClient, error) {
	if err := providerConfig.Validate(); err != nil {
		return nil, err
	}
	maxAge, authorizeParams, err := providerConfig.SplitAuthorizeEndpointQueryParameters()
	if err != nil {
		return nil, err
	}
	discoveryCtx, cancel := context.WithTimeout(ctx, oidcProviderDiscoveryTimeout)
	defer cancel()
	capConfig, err := newCAPOIDCConfig(discoveryCtx, providerConfig)
	if err != nil {
		return nil, err
	}
	provider, err := capoidc.NewProvider(capConfig)
	if err != nil {
		return nil, fmt.Errorf("initialize OIDC provider: %w", err)
	}
	return &capOIDCClient{
		provider:        provider,
		authorizeMaxAge: maxAge,
		authorizeParams: authorizeParams,
	}, nil
}

func (c *capOIDCClient) BeginLogin(ctx context.Context, input oidcBeginLoginInput) (*oidcTransaction, string, error) {
	transaction, request, err := c.newRequest(input.CallbackURL, input.Next)
	if err != nil {
		return nil, "", err
	}
	authURL, err := c.provider.AuthURL(ctx, request)
	if err != nil {
		return nil, "", err
	}
	authURL, err = addAuthorizeEndpointQueryParameters(authURL, c.authorizeParams)
	if err != nil {
		return nil, "", err
	}
	return transaction, authURL, nil
}

func (c *capOIDCClient) Exchange(ctx context.Context, transaction *oidcTransaction, input oidcCallbackInput) (encoding.Claims, error) {
	request, err := capRequest(transaction)
	if err != nil {
		return nil, err
	}
	token, err := c.provider.Exchange(ctx, request, input.State, input.Code)
	if err != nil {
		return nil, err
	}
	var claims encoding.Claims
	if err := token.IDToken().Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (c *capOIDCClient) Close() {
	c.provider.Done()
}

func (c *capOIDCClient) newRequest(redirectURI, next string) (*oidcTransaction, capoidc.Request, error) {
	verifier, err := capoidc.NewCodeVerifier()
	if err != nil {
		return nil, nil, err
	}
	startedAt := time.Now().Truncate(time.Second)
	options := []capoidc.Option{
		capoidc.WithNow(func() time.Time { return startedAt }),
		capoidc.WithPKCE(verifier),
	}
	if c.authorizeMaxAge != nil {
		options = append(options, capoidc.WithMaxAge(*c.authorizeMaxAge))
	}
	request, err := capoidc.NewRequest(oidcTransactionTTL, redirectURI, options...)
	if err != nil {
		return nil, nil, err
	}
	return &oidcTransaction{
		StateValue:   request.State(),
		NonceValue:   request.Nonce(),
		RedirectURI:  redirectURI,
		Next:         next,
		CodeVerifier: verifier.Verifier(),
		StartedAt:    startedAt.Unix(),
		MaxAge:       cloneUint(c.authorizeMaxAge),
	}, request, nil
}

func capRequest(transaction *oidcTransaction) (capoidc.Request, error) {
	if transaction == nil {
		return nil, fmt.Errorf("%w: missing OIDC login transaction", ErrInvalidRequest)
	}
	verifier, err := capoidc.NewCodeVerifier(capoidc.WithVerifier(transaction.CodeVerifier))
	if err != nil {
		return nil, err
	}
	startedAt := time.Unix(transaction.StartedAt, 0)
	options := []capoidc.Option{
		capoidc.WithNow(func() time.Time { return startedAt }),
		capoidc.WithState(transaction.StateValue),
		capoidc.WithNonce(transaction.NonceValue),
		capoidc.WithPKCE(verifier),
	}
	if transaction.MaxAge != nil {
		options = append(options, capoidc.WithMaxAge(*transaction.MaxAge))
	}
	return capoidc.NewRequest(oidcTransactionTTL, transaction.RedirectURI, options...)
}

func newCAPOIDCConfig(ctx context.Context, providerConfig config.OIDCProvider) (*capoidc.Config, error) {
	allowedRedirectURLs, err := allowedOIDCRedirectURLs(providerConfig)
	if err != nil {
		return nil, err
	}
	scopes := []string{"profile"}
	scopes = append(scopes, providerConfig.AdditionalScopeClaims...)
	issuerURL, err := httputil.NormalizeBaseURL(providerConfig.URL)
	if err != nil {
		return nil, err
	}
	return capoidc.NewConfig(
		issuerURL,
		providerConfig.ClientID,
		capoidc.ClientSecret(providerConfig.ClientSecret.SecureValue()),
		supportedOIDCSigningAlgs(),
		allowedRedirectURLs,
		capoidc.WithScopes(scopes...),
		capoidc.WithRoundTripper(&boundedRoundTripper{
			startupCtx: ctx,
			next:       http.DefaultTransport,
			timeout:    oidcProviderDiscoveryTimeout,
		}),
	)
}

func supportedOIDCSigningAlgs() []capoidc.Alg {
	return []capoidc.Alg{
		// 128-bit-capable profiles
		capoidc.RS256,
		capoidc.PS256,
		capoidc.ES256,

		// 192-bit-capable profiles
		capoidc.RS384,
		capoidc.PS384,
		capoidc.ES384,
	}
}

func addAuthorizeEndpointQueryParameters(authURL string, params map[string]string) (string, error) {
	if len(params) == 0 {
		return authURL, nil
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	for key, value := range params {
		query.Set(key, value)
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

type boundedRoundTripper struct {
	startupCtx         context.Context
	next               http.RoundTripper
	timeout            time.Duration
	usedStartupContext atomic.Bool
}

func (t *boundedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	next := t.next
	if next == nil {
		next = http.DefaultTransport
	}
	ctx := req.Context()
	if t.startupCtx != nil && t.usedStartupContext.CompareAndSwap(false, true) {
		ctx = cancelWithParent(ctx, t.startupCtx)
	}
	if t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}
	return next.RoundTrip(req.WithContext(ctx))
}

func cancelWithParent(ctx, parent context.Context) context.Context {
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		select {
		case <-parent.Done():
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx
}
