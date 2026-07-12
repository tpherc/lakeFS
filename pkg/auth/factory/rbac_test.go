package factory

import (
	"context"
	"testing"

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
	auth mockAuthConfig
}

func (m *mockConfig) AuthConfig() config.AuthConfig { return &m.auth }

func TestNewAuthService_InternalRBAC(t *testing.T) {
	ctx := context.Background()
	cfg := &mockConfig{}
	cfg.auth.ui.RBAC = config.AuthRBACInternal

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
