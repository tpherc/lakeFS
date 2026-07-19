package factory

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/logging"
)

type mockAuthConfig struct {
	base config.BaseAuth
	ui   config.AuthUIConfig
}

func (m *mockAuthConfig) GetBaseAuthConfig() *config.BaseAuth   { return &m.base }
func (m *mockAuthConfig) GetAuthUIConfig() *config.AuthUIConfig { return &m.ui }
func (m *mockAuthConfig) GetLoginURLMethodConfigParam() string  { return "" }
func (m *mockAuthConfig) UseUILoginPlaceholders() bool          { return false }

type mockConfig struct {
	config.Config
	base config.BaseConfig
	auth mockAuthConfig
}

func (m *mockConfig) GetBaseConfig() *config.BaseConfig { return &m.base }
func (m *mockConfig) AuthConfig() config.AuthConfig     { return &m.auth }

func TestNewAuthService_InternalRBAC(t *testing.T) {
	ctx := context.Background()
	cfg := &mockConfig{}
	cfg.auth.ui.RBAC = config.AuthRBACInternal
	cfg.base.Features.LocalRBAC = true

	logger := logging.DummyLogger{}

	// We pass nil for kvStore and metadataManager as they are not used for the type check
	// but NewAuthService might panic if it tries to use them.
	// However, for internal RBAC, it only calls acl.NewAuthService and auth.NewMonitoredAuthService.

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewAuthService panicked: %v", r)
		}
	}()

	svc := NewAuthService(ctx, cfg, logger, nil, nil)

	if !svc.IsAdvancedAuth() {
		t.Errorf("expected IsAdvancedAuth() to be true for internal RBAC")
	}
}

func TestCheckAuthModeSupport_InternalRBACUsesExternalAPIWhenLocalRBACDisabled(t *testing.T) {
	cfg := &mockAuthConfig{}
	cfg.ui.RBAC = config.AuthRBACInternal
	cfg.base.API.Endpoint = "http://localhost:8000"

	if err := checkAuthModeSupport(cfg, false); err != nil {
		t.Fatalf("expected internal RBAC with features.local_rbac=false to use external auth API: %v", err)
	}
}

func TestCheckAuthModeSupport_InternalRBACRejectsAmbiguousLocalAndExternalConfig(t *testing.T) {
	cfg := &mockAuthConfig{}
	cfg.ui.RBAC = config.AuthRBACInternal
	cfg.base.API.Endpoint = "http://localhost:8000"

	if err := checkAuthModeSupport(cfg, true); err == nil {
		t.Fatal("expected internal RBAC with local RBAC enabled and auth API configured to fail")
	}
}

func TestCheckAuthModeSupportRejectsOIDCWithBasicAuth(t *testing.T) {
	cfg := &mockAuthConfig{}
	cfg.ui.RBAC = config.AuthRBACNone
	cfg.base.Providers.OIDC = &config.OIDCProvider{URL: "https://idp.example"}

	err := checkAuthModeSupport(cfg, true)
	require.ErrorIs(t, err, errOIDCRequiresLocalAuth)
}

func TestCheckAuthModeSupportAcceptsBasicAuthWithoutOIDC(t *testing.T) {
	cfg := &mockAuthConfig{}
	cfg.ui.RBAC = config.AuthRBACNone

	require.NoError(t, checkAuthModeSupport(cfg, true))
}

func TestCheckAuthModeSupportOIDCRBACCombinations(t *testing.T) {
	tests := []struct {
		name      string
		rbac      string
		localRBAC bool
		authAPI   string
		wantErr   error
	}{
		{name: "internal local", rbac: config.AuthRBACInternal, localRBAC: true},
		{name: "simplified", rbac: config.AuthRBACSimplified, localRBAC: true},
		{name: "external", rbac: config.AuthRBACExternal, localRBAC: true, authAPI: "http://localhost:8000"},
		{name: "internal external API when local RBAC disabled", rbac: config.AuthRBACInternal, authAPI: "http://localhost:8000"},
		{name: "internal local rejects auth API", rbac: config.AuthRBACInternal, localRBAC: true, authAPI: "http://localhost:8000", wantErr: errAmbiguousLocalRBAC},
		{name: "external without auth API", rbac: config.AuthRBACExternal, localRBAC: true, wantErr: errSimplifiedOrExternalAuth},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &mockAuthConfig{}
			cfg.ui.RBAC = tt.rbac
			cfg.base.API.Endpoint = tt.authAPI
			cfg.base.Providers.OIDC = &config.OIDCProvider{URL: "https://idp.example"}

			err := checkAuthModeSupport(cfg, tt.localRBAC)
			if tt.wantErr != nil {
				require.True(t, errors.Is(err, tt.wantErr), "got error %v", err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestNewAuthService_SimplifiedRBAC(t *testing.T) {
	ctx := context.Background()
	cfg := &mockConfig{}
	cfg.auth.ui.RBAC = config.AuthRBACSimplified

	logger := logging.DummyLogger{}

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("NewAuthService panicked: %v", r)
		}
	}()

	svc := NewAuthService(ctx, cfg, logger, nil, nil)

	if svc.IsAdvancedAuth() {
		t.Errorf("expected IsAdvancedAuth() to be false for simplified RBAC")
	}
}
