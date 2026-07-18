package config_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/go-test/deep"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/block"
	blockfactory "github.com/treeverse/lakefs/pkg/block/factory"
	"github.com/treeverse/lakefs/pkg/block/gs"
	"github.com/treeverse/lakefs/pkg/block/local"
	"github.com/treeverse/lakefs/pkg/config"
	"github.com/treeverse/lakefs/pkg/kv/kvparams"
	"github.com/treeverse/lakefs/pkg/logging"
	"github.com/treeverse/lakefs/pkg/testutil"
)

func newConfigFromFile(fn string) (config.Config, error) {
	viper.SetConfigFile(fn)
	err := viper.ReadInConfig()
	if err != nil {
		return nil, err
	}
	cfg, err := config.BuildConfig("")
	if err != nil {
		return nil, err
	}
	err = cfg.Validate()
	return cfg, err
}

func TestConfig_Setup(t *testing.T) {
	// test defaults
	cfg := &config.ConfigImpl{}
	baseCfg, err := config.NewConfig("", cfg)
	testutil.Must(t, err)
	// Don't validate, some tested configs don't have all required fields.
	if baseCfg.ListenAddress != config.DefaultListenAddress {
		t.Fatalf("expected listen addr '%s', got '%s'", config.DefaultListenAddress, baseCfg.ListenAddress)
	}
}

func TestConfig_NewFromFile(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		c, err := newConfigFromFile("testdata/valid_config.yaml")
		testutil.Must(t, err)
		baseConfig := c.GetBaseConfig()
		if baseConfig.ListenAddress != "0.0.0.0:8005" {
			t.Fatalf("expected listen addr 0.0.0.0:8005, got %s", baseConfig.ListenAddress)
		}
		if diffs := deep.Equal([]string(baseConfig.Gateways.S3.DomainNames), []string{"s3.example.com", "gs3.example.com", "gcp.example.net"}); diffs != nil {
			t.Fatalf("expected domain name s3.example.com, diffs %s", diffs)
		}
	})

	t.Run("invalid config", func(t *testing.T) {
		_, err := newConfigFromFile("testdata/invalid_config.yaml")
		// viper errors are not
		if err == nil || !strings.HasPrefix(err.Error(), "While parsing config:") {
			t.Fatalf("expected invalid configuration file to fail, got %v", err)
		}
	})

	t.Run("missing config", func(t *testing.T) {
		_, err := newConfigFromFile("testdata/valid_configgggggggggggggggg.yaml")
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected missing configuration file to fail, got %v", err)
		}
	})

	t.Run("auth fixture", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			c, err := newConfigFromFile("testdata/auth_fixture/basic_auth.yaml")
			require.NoError(t, err)
			require.Equal(t, "test value", c.AuthConfig().GetBaseAuthConfig().Encrypt.SecretKey.SecureValue())
		})
		t.Run("invalid auth", func(t *testing.T) {
			_, err := newConfigFromFile("testdata/auth_fixture/invalid_auth.yaml")
			require.Error(t, err)
		})
		t.Run("no auth", func(t *testing.T) {
			_, err := newConfigFromFile("testdata/auth_fixture/no_auth.yaml")
			require.Error(t, err)
		})
	})
}

func pushEnv(key, value string) func() {
	oldValue := os.Getenv(key)
	_ = os.Setenv(key, value)
	return func() {
		_ = os.Setenv(key, oldValue)
	}
}

func TestConfig_EnvironmentVariables(t *testing.T) {
	const dbString = "not://a/database"
	defer pushEnv("LAKEFS_DATABASE_POSTGRES_CONNECTION_STRING", dbString)()

	viper.SetEnvPrefix("LAKEFS")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_")) // support nested config
	// read in environment variables
	viper.AutomaticEnv()

	c, err := newConfigFromFile("testdata/valid_config.yaml")
	testutil.Must(t, err)
	kvParams, err := kvparams.NewConfig(&c.GetBaseConfig().Database)
	testutil.Must(t, err)
	if kvParams.Postgres.ConnectionString != dbString {
		t.Errorf("got DB connection string %s, expected to override to %s", kvParams.Postgres.ConnectionString, dbString)
	}
}

func TestConfig_DomainNamePrefix(t *testing.T) {
	_, err := newConfigFromFile("testdata/domain_name_prefix.yaml")
	if !errors.Is(err, config.ErrBadDomainNames) {
		t.Errorf("got error %s not %s", err, config.ErrBadDomainNames)
	}
}

func TestConfig_BuildBlockAdapter(t *testing.T) {
	ctx := t.Context()
	t.Run("local block adapter", func(t *testing.T) {
		c, err := newConfigFromFile("testdata/valid_config.yaml")
		testutil.Must(t, err)
		adapter, err := blockfactory.BuildBlockAdapterWithMetrics(ctx, nil, c)
		testutil.Must(t, err)
		metricsAdapter, ok := adapter.(*block.MetricsAdapter)
		if !ok {
			t.Fatalf("got a %T when expecting a MetricsAdapter", adapter)
		}
		if _, ok := metricsAdapter.InnerAdapter().(*local.Adapter); !ok {
			t.Fatalf("got %T expected a local block adapter", metricsAdapter.InnerAdapter())
		}
	})

	t.Run("s3 block adapter", func(t *testing.T) {
		c, err := newConfigFromFile("testdata/valid_s3_adapter_config.yaml")
		testutil.Must(t, err)

		_, err = blockfactory.BuildBlockAdapterWithMetrics(ctx, nil, c)
		var errProfileNotExists awsconfig.SharedConfigProfileNotExistError
		if !errors.As(err, &errProfileNotExists) {
			t.Fatalf("expected a config.SharedConfigProfileNotExistError, got '%v'", err)
		}
	})

	t.Run("gs block adapter", func(t *testing.T) {
		c, err := newConfigFromFile("testdata/valid_gs_adapter_config.yaml")
		testutil.Must(t, err)
		adapter, err := blockfactory.BuildBlockAdapterWithMetrics(ctx, nil, c)
		testutil.Must(t, err)

		metricsAdapter, ok := adapter.(*block.MetricsAdapter)
		if !ok {
			t.Fatalf("expected a metrics block adapter, got something else instead")
		}
		if _, ok := metricsAdapter.InnerAdapter().(*gs.Adapter); !ok {
			t.Fatalf("expected an gs block adapter, got something else instead")
		}
	})
}

func TestConfig_JSONLogger(t *testing.T) {
	logfile := "/tmp/lakefs_json_logger_test.log"
	_ = os.Remove(logfile)
	_, err := newConfigFromFile("testdata/valid_json_logger_config.yaml")
	testutil.Must(t, err)

	logging.ContextUnavailable().Info("some message that I should be looking for")

	content, err := os.Open(logfile)
	if err != nil {
		t.Fatalf("unexpected error reading log file: %s", err)
	}
	defer func() {
		_ = content.Close()
	}()
	reader := bufio.NewReader(content)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("could not read line from logfile: %s", err)
	}
	m := make(map[string]string)
	err = json.Unmarshal([]byte(line), &m)
	if err != nil {
		t.Fatalf("could not parse JSON line from logfile: %s", err)
	}
	if _, ok := m["msg"]; !ok {
		t.Fatalf("expected a msg field, could not find one")
	}
}

func TestAuth_GetLoginURLMethodConfigParam_ResolvesEmptyLoginURLToNone(t *testing.T) {
	authConfig := &config.Auth{}
	authConfig.LoginURLMethod = "redirect"

	require.Equal(t, "none", authConfig.GetLoginURLMethodConfigParam())

	authConfig.LoginURL = "/oidc/login"
	authConfig.LoginURLMethod = ""
	require.Equal(t, "redirect", authConfig.GetLoginURLMethodConfigParam())

	authConfig.LoginURLMethod = "select"
	require.Equal(t, "select", authConfig.GetLoginURLMethodConfigParam())
}

func TestAuth_ValidateLoginURLMethod(t *testing.T) {
	for _, method := range []string{"", "redirect", "select"} {
		t.Run(method, func(t *testing.T) {
			authConfig := &config.Auth{}
			authConfig.LoginURLMethod = method
			require.NoError(t, authConfig.Validate())
		})
	}

	authConfig := &config.Auth{}
	authConfig.LoginURLMethod = "popup"
	require.Error(t, authConfig.Validate())
}

func TestOIDCProviderValidateAuthorizeAndLogoutParameters(t *testing.T) {
	base := validOIDCProviderConfig()
	tests := []struct {
		name string
		mut  func(*config.OIDCProvider)
	}{
		{
			name: "reserved parameter with whitespace",
			mut: func(p *config.OIDCProvider) {
				p.AuthorizeEndpointQueryParameters = map[string]string{" STATE ": "value"}
			},
		},
		{
			name: "negative max age",
			mut: func(p *config.OIDCProvider) {
				p.AuthorizeEndpointQueryParameters = map[string]string{"max_age": "-1"}
			},
		},
		{
			name: "non numeric max age",
			mut: func(p *config.OIDCProvider) {
				p.AuthorizeEndpointQueryParameters = map[string]string{"max_age": "soon"}
			},
		},
		{
			name: "overflow max age",
			mut: func(p *config.OIDCProvider) {
				p.AuthorizeEndpointQueryParameters = map[string]string{"max_age": "999999999999999999999"}
			},
		},
		{
			name: "odd logout query pairs",
			mut: func(p *config.OIDCProvider) {
				p.LogoutEndpointQueryParameters = []string{"returnTo"}
			},
		},
		{
			name: "empty logout query key",
			mut: func(p *config.OIDCProvider) {
				p.LogoutEndpointQueryParameters = []string{" ", "https://lakefs.example"}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mut(&cfg)
			require.ErrorIs(t, cfg.Validate(), config.ErrBadConfiguration)
		})
	}

	cfg := base
	cfg.AuthorizeEndpointQueryParameters = map[string]string{"max_age": "0", " login_hint ": "alice@example.com"}
	maxAge, params, err := cfg.SplitAuthorizeEndpointQueryParameters()
	require.NoError(t, err)
	require.NotNil(t, maxAge)
	require.Equal(t, uint(0), *maxAge)
	require.Equal(t, map[string]string{"login_hint": "alice@example.com"}, params)
}

func TestOIDCProviderValidateLogoutParametersWithoutConfiguredProvider(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.OIDCProvider
	}{
		{
			name: "logout-only odd key value list",
			cfg: config.OIDCProvider{
				LogoutEndpointQueryParameters: []string{"returnTo"},
			},
		},
		{
			name: "logout-only whitespace key",
			cfg: config.OIDCProvider{
				LogoutEndpointQueryParameters: []string{" ", "https://lakefs.example/auth/login"},
			},
		},
		{
			name: "whitespace client ID key",
			cfg: config.OIDCProvider{
				LogoutClientIDQueryParameter: " ",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, tt.cfg.Validate(), config.ErrBadConfiguration)
		})
	}

	cfg := config.OIDCProvider{
		LogoutEndpointQueryParameters: []string{"returnTo", "https://lakefs.example/auth/login"},
	}
	require.NoError(t, cfg.Validate())
}

func TestOIDCProviderValidateHTTPSOrLoopback(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*config.OIDCProvider)
		want bool
	}{
		{
			name: "https provider and callback",
			want: true,
		},
		{
			name: "provider issuer may keep trailing slash",
			mut: func(p *config.OIDCProvider) {
				p.URL = "https://idp.example/tenant/"
			},
			want: true,
		},
		{
			name: "http loopback provider and callback",
			mut: func(p *config.OIDCProvider) {
				p.URL = "http://127.0.0.1:5556"
				p.CallbackBaseURL = "http://localhost:8000"
			},
			want: true,
		},
		{
			name: "http provider rejected",
			mut: func(p *config.OIDCProvider) {
				p.URL = "http://idp.example"
			},
		},
		{
			name: "http callback rejected",
			mut: func(p *config.OIDCProvider) {
				p.CallbackBaseURL = "http://lakefs.example"
			},
		},
		{
			name: "mixed https and loopback callbacks rejected",
			mut: func(p *config.OIDCProvider) {
				p.CallbackBaseURL = ""
				p.CallbackBaseURLs = []string{"https://lakefs.example", "http://127.0.0.1:8000"}
			},
		},
		{
			name: "provider issuer query rejected",
			mut: func(p *config.OIDCProvider) {
				p.URL = "https://idp.example?tenant=one"
			},
		},
		{
			name: "provider issuer fragment rejected",
			mut: func(p *config.OIDCProvider) {
				p.URL = "https://idp.example#issuer"
			},
		},
		{
			name: "plural callback path rejected",
			mut: func(p *config.OIDCProvider) {
				p.CallbackBaseURL = ""
				p.CallbackBaseURLs = []string{"https://lakefs.example/base"}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validOIDCProviderConfig()
			if tt.mut != nil {
				tt.mut(&cfg)
			}
			err := cfg.Validate()
			if tt.want {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, config.ErrBadConfiguration)
		})
	}
}

func TestOIDCProviderRequiresSecureCookies(t *testing.T) {
	cfg := validOIDCProviderConfig()
	require.True(t, cfg.RequiresSecureCookies())

	cfg.CallbackBaseURL = "http://127.0.0.1:8000"
	require.False(t, cfg.RequiresSecureCookies())
}

func validOIDCProviderConfig() config.OIDCProvider {
	return config.OIDCProvider{
		URL:             "https://idp.example",
		ClientID:        "lakefs",
		ClientSecret:    config.SecureString("secret"),
		CallbackBaseURL: "https://lakefs.example",
	}
}
