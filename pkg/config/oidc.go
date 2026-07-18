package config

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/treeverse/lakefs/pkg/httputil"
)

func (p *OIDCProvider) Validate() error {
	if p == nil {
		return nil
	}
	if err := p.validateLogoutEndpointQueryParameters(); err != nil {
		return err
	}
	if !p.IsConfigured() {
		return nil
	}
	switch {
	case strings.TrimSpace(p.URL) == "":
		return fmt.Errorf("%w: auth.providers.oidc.url is required", ErrBadConfiguration)
	case strings.TrimSpace(p.ClientID) == "":
		return fmt.Errorf("%w: auth.providers.oidc.client_id is required", ErrBadConfiguration)
	case strings.TrimSpace(p.ClientSecret.SecureValue()) == "":
		return fmt.Errorf("%w: auth.providers.oidc.client_secret is required", ErrBadConfiguration)
	case p.CallbackBaseURL != "" && len(p.CallbackBaseURLs) > 0:
		return fmt.Errorf("%w: auth.providers.oidc.callback_base_url and callback_base_urls are mutually exclusive", ErrBadConfiguration)
	case p.CallbackBaseURL == "" && len(p.CallbackBaseURLs) == 0:
		return fmt.Errorf("%w: auth.providers.oidc.callback_base_url or callback_base_urls is required", ErrBadConfiguration)
	}
	issuerURL, err := httputil.NormalizeBaseURL(p.URL)
	if err != nil {
		return fmt.Errorf("%w: invalid auth.providers.oidc.url: %s", ErrBadConfiguration, err)
	}
	if err := validateOIDCPublicBaseURL("auth.providers.oidc.url", issuerURL); err != nil {
		return err
	}
	if p.CallbackBaseURL != "" {
		baseURL, err := httputil.NormalizeBaseURL(p.CallbackBaseURL)
		if err != nil {
			return fmt.Errorf("%w: invalid auth.providers.oidc.callback_base_url: %s", ErrBadConfiguration, err)
		}
		if err := validateOIDCPublicBaseURL("auth.providers.oidc.callback_base_url", baseURL); err != nil {
			return err
		}
	}
	var sawHTTPSCallback, sawHTTPLoopbackCallback bool
	for _, callbackBaseURL := range p.CallbackBaseURLs {
		baseURL, err := httputil.NormalizeBaseURL(callbackBaseURL)
		if err != nil {
			return fmt.Errorf("%w: invalid auth.providers.oidc.callback_base_urls entry: %s", ErrBadConfiguration, err)
		}
		if err := validateOIDCPublicBaseURL("auth.providers.oidc.callback_base_urls entry", baseURL); err != nil {
			return err
		}
		usesHTTPS, _ := httputil.BaseURLUsesHTTPS(baseURL)
		usesLoopbackHTTP, _ := httputil.BaseURLUsesLoopbackHTTP(baseURL)
		sawHTTPSCallback = sawHTTPSCallback || usesHTTPS
		sawHTTPLoopbackCallback = sawHTTPLoopbackCallback || usesLoopbackHTTP
	}
	if sawHTTPSCallback && sawHTTPLoopbackCallback {
		return fmt.Errorf("%w: auth.providers.oidc.callback_base_urls cannot mix HTTPS and loopback HTTP URLs", ErrBadConfiguration)
	}
	if _, _, err := p.SplitAuthorizeEndpointQueryParameters(); err != nil {
		return err
	}
	return nil
}

func (p *OIDCProvider) SplitAuthorizeEndpointQueryParameters() (*uint, map[string]string, error) {
	if p == nil {
		return nil, nil, nil
	}
	passthrough := make(map[string]string, len(p.AuthorizeEndpointQueryParameters))
	var maxAge *uint
	for originalKey, value := range p.AuthorizeEndpointQueryParameters {
		key := strings.ToLower(strings.TrimSpace(originalKey))
		if key == "" {
			return nil, nil, fmt.Errorf("%w: auth.providers.oidc.authorize_endpoint_query_parameters contains an empty key", ErrBadConfiguration)
		}
		if _, ok := reservedOIDCAuthorizeEndpointQueryParameters[key]; ok {
			return nil, nil, fmt.Errorf("%w: auth.providers.oidc.authorize_endpoint_query_parameters cannot override %q", ErrBadConfiguration, key)
		}
		if key == "max_age" {
			if maxAge != nil {
				return nil, nil, fmt.Errorf("%w: auth.providers.oidc.authorize_endpoint_query_parameters contains duplicate max_age", ErrBadConfiguration)
			}
			parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
			if err != nil {
				return nil, nil, fmt.Errorf("%w: invalid auth.providers.oidc.authorize_endpoint_query_parameters max_age", ErrBadConfiguration)
			}
			v := uint(parsed)
			maxAge = &v
			continue
		}
		passthrough[strings.TrimSpace(originalKey)] = value
	}
	return maxAge, passthrough, nil
}

func (p *OIDCProvider) RequiresSecureCookies() bool {
	if p == nil || !p.IsConfigured() {
		return false
	}
	if p.CallbackBaseURL != "" {
		usesHTTPS, err := httputil.BaseURLUsesHTTPS(p.CallbackBaseURL)
		return err == nil && usesHTTPS
	}
	for _, callbackBaseURL := range p.CallbackBaseURLs {
		usesHTTPS, err := httputil.BaseURLUsesHTTPS(callbackBaseURL)
		if err == nil && usesHTTPS {
			return true
		}
	}
	return false
}

func (p *OIDCProvider) validateLogoutEndpointQueryParameters() error {
	if len(p.LogoutEndpointQueryParameters)%2 != 0 {
		return fmt.Errorf("%w: auth.providers.oidc.logout_endpoint_query_parameters must contain key/value pairs", ErrBadConfiguration)
	}
	for i := 0; i < len(p.LogoutEndpointQueryParameters); i += 2 {
		if strings.TrimSpace(p.LogoutEndpointQueryParameters[i]) == "" {
			return fmt.Errorf("%w: auth.providers.oidc.logout_endpoint_query_parameters contains an empty key", ErrBadConfiguration)
		}
	}
	if p.LogoutClientIDQueryParameter != "" && strings.TrimSpace(p.LogoutClientIDQueryParameter) == "" {
		return fmt.Errorf("%w: auth.providers.oidc.logout_client_id_query_parameter contains an empty key", ErrBadConfiguration)
	}
	return nil
}

func validateOIDCPublicBaseURL(name, baseURL string) error {
	usesHTTPS, err := httputil.BaseURLUsesHTTPS(baseURL)
	if err != nil {
		return fmt.Errorf("%w: invalid %s: %s", ErrBadConfiguration, name, err)
	}
	if usesHTTPS {
		return nil
	}
	usesLoopbackHTTP, err := httputil.BaseURLUsesLoopbackHTTP(baseURL)
	if err != nil {
		return fmt.Errorf("%w: invalid %s: %s", ErrBadConfiguration, name, err)
	}
	if usesLoopbackHTTP {
		return nil
	}
	return fmt.Errorf("%w: %s must use HTTPS unless it is an HTTP loopback development URL", ErrBadConfiguration, name)
}

var reservedOIDCAuthorizeEndpointQueryParameters = map[string]struct{}{
	"client_id":             {},
	"code_challenge":        {},
	"code_challenge_method": {},
	"nonce":                 {},
	"redirect_uri":          {},
	"request":               {},
	"request_uri":           {},
	"response_mode":         {},
	"response_type":         {},
	"scope":                 {},
	"state":                 {},
}
