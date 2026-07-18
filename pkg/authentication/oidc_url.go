package authentication

import (
	"fmt"
	"net/http"

	"github.com/treeverse/lakefs/pkg/api/apiutil"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/httputil"
)

const oidcCallbackPath = apiutil.BaseURL + "/oidc/callback"

type oidcCallbackResolver struct {
	fixedBaseURL    string
	allowedBaseURLs []string
}

func newOIDCCallbackResolver(providerConfig config.OIDCProvider) (oidcCallbackResolver, error) {
	if providerConfig.CallbackBaseURL != "" {
		baseURL, err := httputil.NormalizeBaseURL(providerConfig.CallbackBaseURL)
		if err != nil {
			return oidcCallbackResolver{}, err
		}
		return oidcCallbackResolver{fixedBaseURL: baseURL}, nil
	}
	allowedBaseURLs := make([]string, 0, len(providerConfig.CallbackBaseURLs))
	for _, rawBaseURL := range providerConfig.CallbackBaseURLs {
		baseURL, err := httputil.NormalizeBaseURL(rawBaseURL)
		if err != nil {
			return oidcCallbackResolver{}, err
		}
		allowedBaseURLs = append(allowedBaseURLs, baseURL)
	}
	return oidcCallbackResolver{allowedBaseURLs: allowedBaseURLs}, nil
}

func (r oidcCallbackResolver) RedirectURI(req *http.Request) (string, error) {
	baseURL, err := r.baseURL(req)
	if err != nil {
		return "", err
	}
	return baseURL + oidcCallbackPath, nil
}

func (r oidcCallbackResolver) RedirectURLs() []string {
	if r.fixedBaseURL != "" {
		return []string{r.fixedBaseURL + oidcCallbackPath}
	}
	redirectURLs := make([]string, 0, len(r.allowedBaseURLs))
	for _, baseURL := range r.allowedBaseURLs {
		redirectURLs = append(redirectURLs, baseURL+oidcCallbackPath)
	}
	return redirectURLs
}

func (r oidcCallbackResolver) baseURL(req *http.Request) (string, error) {
	if r.fixedBaseURL != "" {
		return r.fixedBaseURL, nil
	}
	current, err := currentRequestBaseURL(req)
	if err != nil {
		return "", err
	}
	for _, allowed := range r.allowedBaseURLs {
		if current == allowed {
			return current, nil
		}
	}
	return "", fmt.Errorf("%w: OIDC callback host is not allowed", ErrInvalidRequest)
}

func allowedOIDCRedirectURLs(providerConfig config.OIDCProvider) ([]string, error) {
	resolver, err := newOIDCCallbackResolver(providerConfig)
	if err != nil {
		return nil, err
	}
	return resolver.RedirectURLs(), nil
}

func currentRequestBaseURL(r *http.Request) (string, error) {
	baseURL, err := httputil.RequestBaseURL(r)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrInvalidRequest, err)
	}
	return baseURL, nil
}
