package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/stretchr/testify/require"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
	"github.com/treeverse/lakefs/pkg/auth/oidc/principaltags"
	"github.com/treeverse/lakefs/pkg/gateway"
	"github.com/treeverse/lakefs/pkg/gateway/operations"
)

func TestGatewayAuthenticationPrincipalTags(t *testing.T) {
	t.Parallel()
	for _, oidc := range []bool{false, true} {
		t.Run(map[bool]string{false: "independent SigV4", true: "authenticated OIDC"}[oidc], func(t *testing.T) {
			expectedUser := &model.User{Username: "access-key-user"}
			var expectedTags principaltags.Tags
			ctx := t.Context()
			if oidc {
				expectedUser = &model.User{Username: "oidc-user"}
				expectedTags = principaltags.Tags{"clr": "S"}
				ctx = auth.WithUser(ctx, expectedUser)
			}
			ctx = auth.WithPrincipalTags(ctx, principaltags.Tags{"clr": "S"})
			ctx = context.WithValue(ctx, gateway.ContextKeyOperation, &operations.Operation{FQDN: "s3.example.com"})
			req := httptest.NewRequest(http.MethodGet, "https://s3.example.com/", nil).WithContext(ctx)
			service := &principalGatewayAuth{user: expectedUser}
			if !oidc {
				req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
				err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "test-access-key", SecretAccessKey: "test-secret"}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now())
				require.NoError(t, err)
			}
			called := false
			handler := gateway.AuthenticationHandler(service, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				gotUser, err := auth.GetUser(r.Context())
				require.NoError(t, err)
				require.Same(t, expectedUser, gotUser)
				tags, found := auth.PrincipalTagsFromContext(r.Context())
				require.True(t, found)
				require.Equal(t, expectedTags, tags)
				w.WriteHeader(http.StatusNoContent)
			}))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			require.True(t, called)
			require.Equal(t, http.StatusNoContent, recorder.Code)
			require.Equal(t, !oidc, service.credentialsRead)
		})
	}
}

type principalGatewayAuth struct {
	auth.GatewayService
	user            *model.User
	credentialsRead bool
}

func (s *principalGatewayAuth) GetCredentials(_ context.Context, accessKey string) (*model.Credential, error) {
	s.credentialsRead = true
	if accessKey != "test-access-key" {
		return nil, auth.ErrNotFound
	}
	return &model.Credential{Username: s.user.Username, BaseCredential: model.BaseCredential{AccessKeyID: accessKey, SecretAccessKey: "test-secret"}}, nil
}

func (s *principalGatewayAuth) GetUser(_ context.Context, username string) (*model.User, error) {
	if username != s.user.Username {
		return nil, auth.ErrNotFound
	}
	return s.user, nil
}
