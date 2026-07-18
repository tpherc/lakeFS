package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/treeverse/lakefs/pkg/api/apigen"
	"github.com/treeverse/lakefs/pkg/api/apiutil"
	"github.com/treeverse/lakefs/pkg/auth"
	"github.com/treeverse/lakefs/pkg/auth/model"
)

func TestAuthMiddleware(t *testing.T) {
	handler, deps := setupHandler(t)
	server := setupServer(t, handler)
	apiEndpoint := server.URL + apiutil.BaseURL
	clt := setupClientByEndpoint(t, server.URL, "", "")
	cred := createDefaultAdminUser(t, clt)

	t.Run("valid basic auth", func(t *testing.T) {
		ctx := t.Context()
		authClient := setupClientByEndpoint(t, server.URL, cred.AccessKeyID, cred.SecretAccessKey)
		resp, err := authClient.ListRepositoriesWithResponse(ctx, &apigen.ListRepositoriesParams{})
		if err != nil {
			t.Fatal("ListRepositories() should return without error:", err)
		}
		if resp.StatusCode() != http.StatusOK {
			t.Fatalf("unexpected status code %d, expected %d", resp.StatusCode(), http.StatusOK)
		}
	})

	t.Run("invalid basic auth", func(t *testing.T) {
		ctx := t.Context()
		authClient := setupClientByEndpoint(t, server.URL, "foo", "bar")
		resp, err := authClient.ListRepositoriesWithResponse(ctx, &apigen.ListRepositoriesParams{})
		if err != nil {
			t.Fatal("ListRepositories() should return without error:", err)
		}
		if resp.StatusCode() != http.StatusUnauthorized {
			t.Fatal("ListRepositories() should return unauthorized status code, got", resp.StatusCode())
		}
		if resp.JSON401 == nil {
			t.Fatal("ListRepositories() should return unauthorized response, got nil")
		}
	})

	t.Run("valid jwt header", func(t *testing.T) {
		ctx := t.Context()
		apiToken := testGenerateApiToken(ctx, t, clt, cred)
		authProvider, err := securityprovider.NewSecurityProviderApiKey("header", "Authorization", "Bearer "+apiToken)
		if err != nil {
			t.Fatal("basic auth security provider", err)
		}
		authClient, err := apigen.NewClientWithResponses(apiEndpoint, apigen.WithRequestEditorFn(authProvider.Intercept))
		if err != nil {
			t.Fatal("failed to create lakefs api client:", err)
		}
		resp, err := authClient.ListRepositoriesWithResponse(ctx, &apigen.ListRepositoriesParams{})
		if err != nil {
			t.Fatal("ListRepositories() should return without error:", err)
		}
		if resp.StatusCode() != http.StatusOK {
			t.Fatalf("unexpected status code %d, expected %d", resp.StatusCode(), http.StatusOK)
		}
	})

	t.Run("invalid jwt header", func(t *testing.T) {
		ctx := t.Context()
		apiToken := testGenerateBadAPIToken(t, deps.authService)
		authProvider, err := securityprovider.NewSecurityProviderApiKey("header", "Authorization", "Bearer "+apiToken)
		if err != nil {
			t.Fatal("basic auth security provider", err)
		}
		authClient, err := apigen.NewClientWithResponses(apiEndpoint, apigen.WithRequestEditorFn(authProvider.Intercept))
		if err != nil {
			t.Fatal("failed to create lakefs api client:", err)
		}
		resp, err := authClient.ListRepositoriesWithResponse(ctx, &apigen.ListRepositoriesParams{})
		if err != nil {
			t.Fatal("ListRepositories() should return without error:", err)
		}
		if resp.StatusCode() != http.StatusUnauthorized {
			t.Fatal("ListRepositories() should return unauthorized status code, got", resp.StatusCode())
		}
		if resp.JSON401 == nil {
			t.Fatal("ListRepositories() should return unauthorized response, got nil")
		}
	})

	t.Run("valid gorilla session", func(t *testing.T) {
		ctx := t.Context()
		apiToken := testGenerateApiToken(ctx, t, clt, cred)
		values := map[any]any{auth.TokenSessionKeyName: apiToken}
		store := sessions.NewCookieStore([]byte("some secret"))
		encoded, err := securecookie.EncodeMulti(auth.InternalAuthSessionName, values, store.Codecs...)
		if err != nil {
			t.Fatal("Failed to encode cookie value for session: ", err)
		}
		authProvider, err := securityprovider.NewSecurityProviderApiKey("cookie", auth.InternalAuthSessionName, encoded)
		if err != nil {
			t.Fatal("gorilla session security provider", err)
		}
		authClient, err := apigen.NewClientWithResponses(apiEndpoint, apigen.WithRequestEditorFn(authProvider.Intercept))
		if err != nil {
			t.Fatal("failed to create lakefs api client:", err)
		}
		resp, err := authClient.ListRepositoriesWithResponse(ctx, &apigen.ListRepositoriesParams{})
		if err != nil {
			t.Fatal("ListRepositories() should return without error:", err)
		}
		if resp.StatusCode() != http.StatusOK {
			t.Fatalf("unexpected status code %d, expected %d", resp.StatusCode(), http.StatusOK)
		}
		reissuedCookie := responseCookie(t, resp.HTTPResponse, auth.InternalAuthSessionName)
		if reissuedCookie == nil {
			t.Fatal("expected legacy signed session to be reissued")
		}

		authProvider, err = securityprovider.NewSecurityProviderApiKey("cookie", auth.InternalAuthSessionName, reissuedCookie.Value)
		if err != nil {
			t.Fatal("gorilla session security provider", err)
		}
		authClient, err = apigen.NewClientWithResponses(apiEndpoint, apigen.WithRequestEditorFn(authProvider.Intercept))
		if err != nil {
			t.Fatal("failed to create lakefs api client:", err)
		}
		resp, err = authClient.ListRepositoriesWithResponse(ctx, &apigen.ListRepositoriesParams{})
		if err != nil {
			t.Fatal("ListRepositories() should return without error:", err)
		}
		if resp.StatusCode() != http.StatusOK {
			t.Fatalf("unexpected status code %d, expected %d", resp.StatusCode(), http.StatusOK)
		}
		if cookie := responseCookie(t, resp.HTTPResponse, auth.InternalAuthSessionName); cookie != nil {
			t.Fatalf("expected current session not to be reissued, got %q", cookie.String())
		}
	})

	t.Run("password login replaces corrupt cookie and does not reissue on next request", func(t *testing.T) {
		ctx := t.Context()
		resp, err := clt.LoginWithResponse(ctx, apigen.LoginJSONRequestBody{
			AccessKeyId:     cred.AccessKeyID,
			SecretAccessKey: cred.SecretAccessKey,
		}, func(_ context.Context, req *http.Request) error {
			req.AddCookie(&http.Cookie{Name: auth.InternalAuthSessionName, Value: strings.Repeat("x", 32)})
			return nil
		})
		if err != nil {
			t.Fatal("Login:", err)
		}
		if resp.StatusCode() != http.StatusOK {
			t.Fatalf("unexpected status code %d, expected %d", resp.StatusCode(), http.StatusOK)
		}
		loginCookie := responseCookie(t, resp.HTTPResponse, auth.InternalAuthSessionName)
		if loginCookie == nil {
			t.Fatal("expected login to replace corrupt internal auth cookie")
		}

		store, err := auth.NewSessionStore([]byte("some secret"), auth.SessionStoreOptions{MaxAge: 3600})
		if err != nil {
			t.Fatal(err)
		}
		decodeReq := httptest.NewRequest(http.MethodGet, server.URL, nil)
		decodeReq.AddCookie(loginCookie)
		session, err := store.Get(decodeReq, auth.InternalAuthSessionName)
		if err != nil {
			t.Fatal("decode replacement cookie:", err)
		}
		if auth.SessionNeedsEncodingUpgrade(session) {
			t.Fatal("new login cookie should include the current encoding marker")
		}

		authClient := setupClientByEndpoint(t, server.URL, "", "", apigen.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.AddCookie(loginCookie)
			return nil
		}))
		listResp, err := authClient.ListRepositoriesWithResponse(ctx, &apigen.ListRepositoriesParams{})
		if err != nil {
			t.Fatal("ListRepositories() should return without error:", err)
		}
		if listResp.StatusCode() != http.StatusOK {
			t.Fatalf("unexpected status code %d, expected %d", listResp.StatusCode(), http.StatusOK)
		}
		if cookie := responseCookie(t, listResp.HTTPResponse, auth.InternalAuthSessionName); cookie != nil {
			t.Fatalf("expected new password session not to be reissued, got %q", cookie.String())
		}
	})

	t.Run("invalid gorilla cookie", func(t *testing.T) {
		ctx := t.Context()
		apiToken := testGenerateBadAPIToken(t, deps.authService)
		values := map[any]any{auth.TokenSessionKeyName: apiToken}
		store := sessions.NewCookieStore([]byte("some secret"))
		encoded, err := securecookie.EncodeMulti(auth.InternalAuthSessionName, values, store.Codecs...)
		if err != nil {
			t.Fatal("Failed to encode cookie value for session: ", err)
		}
		authProvider, err := securityprovider.NewSecurityProviderApiKey("cookie", auth.InternalAuthSessionName, encoded)
		if err != nil {
			t.Fatal("gorilla session security provider", err)
		}
		authClient, err := apigen.NewClientWithResponses(apiEndpoint, apigen.WithRequestEditorFn(authProvider.Intercept))
		if err != nil {
			t.Fatal("failed to create lakefs api client:", err)
		}
		resp, err := authClient.ListRepositoriesWithResponse(ctx, &apigen.ListRepositoriesParams{})
		if err != nil {
			t.Fatal("ListRepositories() should return without error:", err)
		}
		if resp.StatusCode() != http.StatusUnauthorized {
			t.Fatal("ListRepositories() should return unauthorized status code, got", resp.StatusCode())
		}
		if resp.JSON401 == nil {
			t.Fatal("ListRepositories() should return unauthorized response, got nil")
		}
	})
}

func responseCookie(t testing.TB, response *http.Response, name string) *http.Cookie {
	t.Helper()
	if response == nil {
		t.Fatal("missing HTTP response")
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func testGenerateApiToken(ctx context.Context, t testing.TB, clt apigen.ClientWithResponsesInterface, cred *model.BaseCredential) string {
	t.Helper()
	loginReq := apigen.LoginJSONRequestBody{
		AccessKeyId:     cred.AccessKeyID,
		SecretAccessKey: cred.SecretAccessKey,
	}
	login, err := clt.LoginWithResponse(ctx, loginReq)
	if err != nil {
		t.Fatal("Login:", err)
	}
	if login.JSON200 == nil {
		t.Fatal("Failed to login:", login.Status())
	}
	return login.JSON200.Token
}

func testGenerateBadAPIToken(t testing.TB, authService auth.Service) string {
	secret := authService.SecretStore().SharedSecret()
	now := time.Now()
	expires := now.Add(time.Hour)
	userID := "test_user"
	tokenString, err := auth.GenerateJWTLogin(secret, userID, now, expires)
	if err != nil {
		t.Fatal("Generate (bad) JWT token:", err)
	}
	return tokenString
}
