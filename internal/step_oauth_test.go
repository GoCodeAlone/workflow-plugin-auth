package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOAuthProviderConfig_GoogleAvailable(t *testing.T) {
	step := newOAuthProviderConfigStep("test", googleOAuthTestConfig(nil))

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{"provider": "google"}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["available"] != true {
		t.Fatalf("expected available=true, got %v", result.Output["available"])
	}
	if result.Output["provider"] != "google" {
		t.Fatalf("expected provider=google, got %v", result.Output["provider"])
	}
	if result.Output["client_id"] != "google-client" {
		t.Fatalf("expected client_id output")
	}
	if result.Output["redirect_url"] != "https://app.example.com/auth/google/callback" {
		t.Fatalf("expected redirect_url output")
	}
	if scopes, ok := result.Output["scopes"].([]string); !ok || len(scopes) == 0 {
		t.Fatalf("expected non-empty scopes, got %#v", result.Output["scopes"])
	}
}

func TestOAuthProviderConfig_GoogleIncompleteUnavailable(t *testing.T) {
	step := newOAuthProviderConfigStep("test", map[string]any{
		"google_oauth_client_id": "google-client",
	})

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{"provider": "google"}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["available"] != false {
		t.Fatalf("expected available=false, got %v", result.Output["available"])
	}
	if result.Output["disabled_reason"] == "" {
		t.Fatal("expected disabled_reason for incomplete config")
	}
}

func TestOAuthProviderConfig_DisabledProvidersUnavailable(t *testing.T) {
	for _, provider := range []string{"facebook", "instagram", "x", "bluesky"} {
		t.Run(provider, func(t *testing.T) {
			step := newOAuthProviderConfigStep("test", googleOAuthTestConfig(nil))

			result, err := step.Execute(context.Background(), nil, nil, map[string]any{"provider": provider}, nil, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Output["available"] != false {
				t.Fatalf("expected %s unavailable, got %v", provider, result.Output["available"])
			}
			if result.Output["disabled_reason"] == "" {
				t.Fatalf("expected disabled_reason for %s", provider)
			}
		})
	}
}

func TestOAuthStart_DefaultReturnToAndPKCE(t *testing.T) {
	step := newOAuthStartStep("test", googleOAuthTestConfig(map[string]any{
		"oauth_state_ttl_minutes": 7,
	}))

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider":      "google",
		"pkce_required": true,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["return_to"] != "/auth/callback" {
		t.Fatalf("expected default return_to, got %v", result.Output["return_to"])
	}
	if result.Output["state"] == "" {
		t.Fatal("expected state")
	}
	if result.Output["code_verifier"] == "" {
		t.Fatal("expected code_verifier")
	}
	if result.Output["code_challenge"] == "" {
		t.Fatal("expected code_challenge")
	}
	if result.Output["code_challenge_method"] != "S256" {
		t.Fatalf("expected S256 challenge method, got %v", result.Output["code_challenge_method"])
	}
	if _, err := time.Parse(time.RFC3339, result.Output["expires_at"].(string)); err != nil {
		t.Fatalf("expected RFC3339 expires_at: %v", err)
	}

	authorizationURL := result.Output["authorization_url"].(string)
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("parse authorization_url: %v", err)
	}
	query := parsed.Query()
	if query.Get("client_id") != "google-client" {
		t.Fatalf("expected client_id query, got %q", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != "https://app.example.com/auth/google/callback" {
		t.Fatalf("expected redirect_uri query, got %q", query.Get("redirect_uri"))
	}
	if query.Get("state") != result.Output["state"] {
		t.Fatalf("state query did not match output")
	}
	if query.Get("code_challenge") != result.Output["code_challenge"] {
		t.Fatalf("code_challenge query did not match output")
	}
}

func TestOAuthStart_RejectsExternalReturnTo(t *testing.T) {
	step := newOAuthStartStep("test", googleOAuthTestConfig(nil))

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider":  "google",
		"return_to": "https://evil.example.com/callback",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["started"] != false {
		t.Fatalf("expected started=false, got %v", result.Output["started"])
	}
	if !strings.Contains(result.Output["error"].(string), "return_to") {
		t.Fatalf("expected return_to error, got %v", result.Output["error"])
	}
}

func TestOAuthExchange_PostsTokenRequestWithPKCE(t *testing.T) {
	var form url.Values
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		form = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-123",
			"refresh_token": "refresh-123",
			"id_token":      "id-123",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer tokenServer.Close()

	step := newOAuthExchangeStep("test", googleOAuthTestConfig(map[string]any{
		"google_oauth_token_url":              tokenServer.URL,
		"allow_insecure_test_oauth_endpoints": true,
	}))

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider":      "google",
		"code":          "code-123",
		"code_verifier": "verifier-123",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if form.Get("grant_type") != "authorization_code" {
		t.Fatalf("expected authorization_code grant, got %q", form.Get("grant_type"))
	}
	if form.Get("code") != "code-123" {
		t.Fatalf("expected code in request")
	}
	if form.Get("redirect_uri") != "https://app.example.com/auth/google/callback" {
		t.Fatalf("expected redirect_uri in request")
	}
	if form.Get("client_id") != "google-client" || form.Get("client_secret") != "google-secret" {
		t.Fatalf("expected client credentials in request")
	}
	if form.Get("code_verifier") != "verifier-123" {
		t.Fatalf("expected code_verifier in request")
	}
	if result.Output["access_token"] != "access-123" {
		t.Fatalf("expected access_token output, got %v", result.Output["access_token"])
	}
}

func TestOAuthEndpointOverride_RequiresStrictBooleanTestFlag(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-123"})
	}))
	defer tokenServer.Close()

	step := newOAuthExchangeStep("test", googleOAuthTestConfig(map[string]any{
		"google_oauth_token_url":              tokenServer.URL,
		"allow_insecure_test_oauth_endpoints": "true",
	}))

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider": "google",
		"code":     "code-123",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["exchanged"] != false {
		t.Fatalf("expected string test flag to be rejected, got %#v", result.Output)
	}
	if !strings.Contains(result.Output["error"].(string), "expected Google hostname") {
		t.Fatalf("expected endpoint safety error, got %v", result.Output["error"])
	}
}

func TestAuthMethodsPolicy_DoesNotAdvertiseRejectedOAuthEndpoint(t *testing.T) {
	output := executeMethodsPolicy(t, map[string]any{
		"auth_routes_enabled":        true,
		"google_oauth_client_id":     "client-id",
		"google_oauth_client_secret": "client-secret",
		"google_oauth_redirect_url":  "https://example.com/auth/google/callback",
		"google_oauth_token_url":     "https://evil.example.com/token",
	})
	assertProviders(t, output, nil)
}

func TestAuthMethodsPolicy_AdvertisesTestOAuthEndpointWithStrictFlag(t *testing.T) {
	output := executeMethodsPolicy(t, map[string]any{
		"auth_routes_enabled":                 true,
		"google_oauth_client_id":              "client-id",
		"google_oauth_client_secret":          "client-secret",
		"google_oauth_redirect_url":           "https://example.com/auth/google/callback",
		"google_oauth_token_url":              "http://127.0.0.1/token",
		"allow_insecure_test_oauth_endpoints": true,
	})
	assertProviders(t, output, []string{"google"})
}

func TestOAuthUserinfo_FetchesGoogleClaims(t *testing.T) {
	userinfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-123" {
			t.Fatalf("expected bearer token, got %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":            "google-subject",
			"email":          "user@example.com",
			"email_verified": true,
			"name":           "Example User",
			"picture":        "https://example.com/avatar.png",
			"locale":         "en",
		})
	}))
	defer userinfoServer.Close()

	step := newOAuthUserinfoStep("test", googleOAuthTestConfig(map[string]any{
		"google_oauth_userinfo_url":           userinfoServer.URL,
		"allow_insecure_test_oauth_endpoints": true,
	}))

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider":     "google",
		"access_token": "access-123",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["provider"] != "google" {
		t.Fatalf("expected provider=google")
	}
	if result.Output["provider_subject"] != "google-subject" {
		t.Fatalf("expected provider_subject output")
	}
	if result.Output["provider_user"] != "google-subject" {
		t.Fatalf("expected provider_user compatibility alias")
	}
	if result.Output["email"] != "user@example.com" {
		t.Fatalf("expected email output")
	}
	if result.Output["email_verified"] != true {
		t.Fatalf("expected email_verified output")
	}
	if result.Output["name"] != "Example User" {
		t.Fatalf("expected name output")
	}
	if result.Output["picture"] != "https://example.com/avatar.png" {
		t.Fatalf("expected picture output")
	}
	rawClaims, ok := result.Output["raw_claims"].(map[string]any)
	if !ok {
		t.Fatalf("expected raw_claims map, got %#v", result.Output["raw_claims"])
	}
	if rawClaims["locale"] != "en" {
		t.Fatalf("expected raw locale claim, got %#v", rawClaims)
	}
}

func TestOAuthExchange_Non2xxReturnsError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad token", http.StatusBadRequest)
	}))
	defer tokenServer.Close()

	step := newOAuthExchangeStep("test", googleOAuthTestConfig(map[string]any{
		"google_oauth_token_url":              tokenServer.URL,
		"allow_insecure_test_oauth_endpoints": true,
	}))

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider": "google",
		"code":     "code-123",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["exchanged"] != false {
		t.Fatalf("expected exchanged=false, got %v", result.Output["exchanged"])
	}
	if !strings.Contains(result.Output["error"].(string), "token endpoint") {
		t.Fatalf("expected token endpoint error, got %v", result.Output["error"])
	}
}

func TestOAuthUserinfo_Non2xxReturnsError(t *testing.T) {
	userinfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad userinfo", http.StatusUnauthorized)
	}))
	defer userinfoServer.Close()

	step := newOAuthUserinfoStep("test", googleOAuthTestConfig(map[string]any{
		"google_oauth_userinfo_url":           userinfoServer.URL,
		"allow_insecure_test_oauth_endpoints": true,
	}))

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider":     "google",
		"access_token": "access-123",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["fetched"] != false {
		t.Fatalf("expected fetched=false, got %v", result.Output["fetched"])
	}
	if !strings.Contains(result.Output["error"].(string), "userinfo endpoint") {
		t.Fatalf("expected userinfo endpoint error, got %v", result.Output["error"])
	}
}

func TestOAuthProviderConfig_RejectsProductionEndpointOverrides(t *testing.T) {
	step := newOAuthProviderConfigStep("test", googleOAuthTestConfig(map[string]any{
		"google_oauth_token_url": "https://evil.example.com/token",
	}))

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{"provider": "google"}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["available"] != false {
		t.Fatalf("expected available=false, got %v", result.Output["available"])
	}
	if !strings.Contains(result.Output["disabled_reason"].(string), "expected Google") {
		t.Fatalf("expected Google host validation error, got %v", result.Output["disabled_reason"])
	}
}

func googleOAuthTestConfig(extra map[string]any) map[string]any {
	config := map[string]any{
		"google_oauth_client_id":     "google-client",
		"google_oauth_client_secret": "google-secret",
		"google_oauth_redirect_url":  "https://app.example.com/auth/google/callback",
	}
	for k, v := range extra {
		config[k] = v
	}
	return config
}
