package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-auth/internal/contracts"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/anypb"
)

// TestAuthMethodsPolicyConfig_AcceptsNewBMWFields ensures the typed
// AuthMethodsPolicyConfig accepts every field BMW supplies (closing the gap
// surfaced by BMW local smoke against workflow v0.51.5).
func TestAuthMethodsPolicyConfig_AcceptsNewBMWFields(t *testing.T) {
	cfg := &contracts.AuthMethodsPolicyConfig{
		Environment:                "development",
		JwtSecret:                  "secret",
		SmsAuthEnabled:             protoBool(true),
		FacebookOauthClientId:      "fb-client",
		FacebookOauthClientSecret:  "fb-secret",
		InstagramOauthClientId:     "ig-client",
		InstagramOauthClientSecret: "ig-secret",
		XOauthClientId:             "x-client",
		XOauthClientSecret:         "x-secret",
	}
	packed, err := anypb.New(cfg)
	if err != nil {
		t.Fatalf("pack config: %v", err)
	}
	provider := NewAuthPlugin().(interface {
		CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error)
	})
	if _, err := provider.CreateTypedStep("step.auth_methods_policy", "policy", packed); err != nil {
		t.Fatalf("CreateTypedStep rejected new BMW fields: %v", err)
	}
}

// TestAuthMethodsPolicy_SmsAuthEnabledTogglesSMS verifies the new
// sms_auth_enabled config field reaches the SMS readiness predicate.
func TestAuthMethodsPolicy_SmsAuthEnabledTogglesSMS(t *testing.T) {
	output := executeMethodsPolicy(t, map[string]any{
		"auth_routes_enabled":       true,
		"sms_auth_enabled":          true,
		"twilio_verify_service_sid": "VA123",
		"twilio_account_sid":        "AC123",
		"twilio_auth_token":         "token",
	})
	assertBool(t, output, "sms_code_enabled", true)
}

// TestAuthPolicyGateConfig_AcceptsTenantID ensures BMW's tenant_id config
// supplied to step.auth_policy_gate passes strict-proto validation.
func TestAuthPolicyGateConfig_AcceptsTenantID(t *testing.T) {
	cfg := &contracts.AuthPolicyGateConfig{
		PolicyStep:          "policy",
		RequiredRuntimeKeys: []string{"tenant_id"},
		TenantId:            "tenant-123",
	}
	packed, err := anypb.New(cfg)
	if err != nil {
		t.Fatalf("pack config: %v", err)
	}
	provider := NewAuthPlugin().(interface {
		CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error)
	})
	if _, err := provider.CreateTypedStep("step.auth_policy_gate", "gate", packed); err != nil {
		t.Fatalf("CreateTypedStep rejected tenant_id: %v", err)
	}
}

// TestAuthPolicyGateConfig_AcceptsAllBMWFields ensures every config key BMW
// passes to step.auth_policy_gate (policy_step, signing_secret, tenant_id,
// required_runtime_keys) is accepted under strict-proto validation. Closes the
// round-2 exhaustiveness gap on the v0.2.2 partial fix.
func TestAuthPolicyGateConfig_AcceptsAllBMWFields(t *testing.T) {
	cfg := &contracts.AuthPolicyGateConfig{
		PolicyStep:          "email_policy",
		SigningSecret:       "jwt-secret",
		JwtSecret:           "jwt-secret",
		RequiredRuntimeKeys: []string{"tenant_id"},
		TenantId:            "tenant-123",
	}
	packed, err := anypb.New(cfg)
	if err != nil {
		t.Fatalf("pack config: %v", err)
	}
	provider := NewAuthPlugin().(interface {
		CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error)
	})
	if _, err := provider.CreateTypedStep("step.auth_policy_gate", "gate", packed); err != nil {
		t.Fatalf("CreateTypedStep rejected combined BMW fields: %v", err)
	}
}

// TestAuthChallengeGenerateConfig_AcceptsSigningSecretAndTTL ensures BMW's
// config-supplied signing_secret + ttl_minutes for step.auth_challenge_generate
// pass strict-proto validation under the new AuthChallengeGenerateConfig.
func TestAuthChallengeGenerateConfig_AcceptsSigningSecretAndTTL(t *testing.T) {
	cfg := &contracts.AuthChallengeGenerateConfig{
		SigningSecret: "jwt-secret",
		TtlMinutes:    10,
	}
	packed, err := anypb.New(cfg)
	if err != nil {
		t.Fatalf("pack config: %v", err)
	}
	provider := NewAuthPlugin().(interface {
		CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error)
	})
	if _, err := provider.CreateTypedStep("step.auth_challenge_generate", "generate", packed); err != nil {
		t.Fatalf("CreateTypedStep rejected challenge_generate config: %v", err)
	}
}

// TestChallengeGenerate_FallsBackToConfigSigningSecret ensures signing_secret
// supplied via config (not input) is honored by the handler.
func TestChallengeGenerate_FallsBackToConfigSigningSecret(t *testing.T) {
	gen := newChallengeGenerateStep("generate", map[string]any{
		"signing_secret": "shared-secret",
	})
	genResult, err := gen.Execute(context.Background(), nil, nil, map[string]any{
		"channel":     "email",
		"destination": "user@example.com",
		"tenant_id":   "tenant-123",
		"purpose":     "login",
	}, nil, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if errStr, _ := genResult.Output["error"].(string); errStr != "" {
		t.Fatalf("expected no error when signing_secret supplied via config, got %q", errStr)
	}
	if code, _ := genResult.Output["code"].(string); code == "" {
		t.Fatalf("expected code generation when signing_secret supplied via config, got %#v", genResult.Output)
	}
}

// TestChallengeGenerate_FallsBackToConfigTTL ensures ttl_minutes supplied via
// config (not input) is honored by the handler.
func TestChallengeGenerate_FallsBackToConfigTTL(t *testing.T) {
	gen := newChallengeGenerateStep("generate", map[string]any{
		"signing_secret": "shared-secret",
		"ttl_minutes":    2,
	})
	before := time.Now().UTC()
	genResult, err := gen.Execute(context.Background(), nil, nil, map[string]any{
		"channel":     "email",
		"destination": "user@example.com",
		"tenant_id":   "tenant-123",
		"purpose":     "login",
	}, nil, nil)
	after := time.Now().UTC()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	expiresAtStr, _ := genResult.Output["expires_at"].(string)
	if expiresAtStr == "" {
		t.Fatalf("expected expires_at in output, got %#v", genResult.Output)
	}
	expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	minExpected := before.Add(2 * time.Minute).Add(-1 * time.Second)
	maxExpected := after.Add(2 * time.Minute).Add(1 * time.Second)
	if expiresAt.Before(minExpected) || expiresAt.After(maxExpected) {
		t.Fatalf("expected expires_at ~2 minutes from now (config ttl_minutes=2), got %v (window %v-%v)", expiresAt, minExpected, maxExpected)
	}
}

// TestAuthChallengeVerifyConfig_AcceptsSigningSecret ensures the new
// AuthChallengeVerifyConfig accepts BMW's signing_secret config field.
func TestAuthChallengeVerifyConfig_AcceptsSigningSecret(t *testing.T) {
	cfg := &contracts.AuthChallengeVerifyConfig{SigningSecret: "secret"}
	packed, err := anypb.New(cfg)
	if err != nil {
		t.Fatalf("pack config: %v", err)
	}
	provider := NewAuthPlugin().(interface {
		CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error)
	})
	if _, err := provider.CreateTypedStep("step.auth_challenge_verify", "verify", packed); err != nil {
		t.Fatalf("CreateTypedStep rejected signing_secret config: %v", err)
	}
}

// TestChallengeVerify_FallsBackToConfigSigningSecret ensures signing_secret
// supplied via config (not input) is honored by the handler.
func TestChallengeVerify_FallsBackToConfigSigningSecret(t *testing.T) {
	gen := newChallengeGenerateStep("generate", nil)
	genResult, err := gen.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"destination":    "user@example.com",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "shared-secret",
	}, nil, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	code, _ := genResult.Output["code"].(string)
	codeHash, _ := genResult.Output["code_hash"].(string)

	verify := newChallengeVerifyStep("verify", map[string]any{
		"signing_secret": "shared-secret",
	})
	verifyResult, err := verify.Execute(context.Background(), nil, nil, map[string]any{
		"channel":     "email",
		"destination": "user@example.com",
		"tenant_id":   "tenant-123",
		"purpose":     "login",
		"code":        code,
		"code_hash":   codeHash,
	}, nil, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got, _ := verifyResult.Output["valid"].(bool); !got {
		t.Fatalf("expected valid=true when signing_secret only supplied via config, got %#v", verifyResult.Output)
	}
}

// TestOAuthProviderConfig_AcceptsReturnToAndAccessToken ensures the typed
// OAuthProviderConfig accepts the return_to and access_token fields BMW
// supplies via step.auth_oauth_start.config and step.auth_oauth_userinfo.config
// (round-3 strict-proto gap, v0.2.4).
func TestOAuthProviderConfig_AcceptsReturnToAndAccessToken(t *testing.T) {
	cfg := &contracts.OAuthProviderConfig{
		Provider:                "google",
		GoogleOauthClientId:     "google-client",
		GoogleOauthClientSecret: "google-secret",
		GoogleOauthRedirectUrl:  "https://example.test/cb",
		ReturnTo:                "/auth/callback",
		AccessToken:             "access-token-from-exchange",
	}
	packed, err := anypb.New(cfg)
	if err != nil {
		t.Fatalf("pack config: %v", err)
	}
	provider := NewAuthPlugin().(interface {
		CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error)
	})
	for _, stepType := range []string{
		"step.auth_oauth_start",
		"step.auth_oauth_exchange",
		"step.auth_oauth_userinfo",
		"step.auth_oauth_provider_config",
	} {
		if _, err := provider.CreateTypedStep(stepType, "oauth", packed); err != nil {
			t.Fatalf("CreateTypedStep(%s) rejected return_to/access_token: %v", stepType, err)
		}
	}
}

// TestOAuthStart_UsesReturnToFromConfig verifies start_oauth honors return_to
// when supplied via config (BMW yaml shape), not just via input.
func TestOAuthStart_UsesReturnToFromConfig(t *testing.T) {
	step := newOAuthStartStep("test", googleOAuthTestConfig(map[string]any{
		"return_to": "/wishlists",
	}))
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider": "google",
	}, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if errStr, _ := result.Output["error"].(string); errStr != "" {
		t.Fatalf("expected no error, got %q (output=%#v)", errStr, result.Output)
	}
	if got, _ := result.Output["return_to"].(string); got != "/wishlists" {
		t.Fatalf("expected return_to=/wishlists from config, got %v", result.Output["return_to"])
	}
}

// TestOAuthStart_ConfigReturnToWinsOverCurrent verifies config.return_to wins
// when both config and input supply it (Config-when-non-empty rule).
func TestOAuthStart_ConfigReturnToWinsOverCurrent(t *testing.T) {
	step := newOAuthStartStep("test", googleOAuthTestConfig(map[string]any{
		"return_to": "/from-config",
	}))
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider":  "google",
		"return_to": "/from-input",
	}, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got, _ := result.Output["return_to"].(string); got != "/from-config" {
		t.Fatalf("expected config.return_to to win, got %v", result.Output["return_to"])
	}
}

// TestOAuthStart_FallsBackToCurrentReturnTo verifies start_oauth honors
// return_to from current/input when config does not supply one.
func TestOAuthStart_FallsBackToCurrentReturnTo(t *testing.T) {
	step := newOAuthStartStep("test", googleOAuthTestConfig(nil))
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider":  "google",
		"return_to": "/from-input",
	}, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got, _ := result.Output["return_to"].(string); got != "/from-input" {
		t.Fatalf("expected return_to from input fallback, got %v", result.Output["return_to"])
	}
}

// TestOAuthUserinfo_UsesAccessTokenFromConfig verifies fetch_userinfo honors
// access_token when supplied via config (BMW yaml shape templates the token
// from a preceding exchange_code step into config.access_token).
func TestOAuthUserinfo_UsesAccessTokenFromConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer config-access-token" {
			t.Fatalf("expected bearer from config.access_token, got %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub":   "user-id",
			"email": "user@example.com",
		})
	}))
	defer server.Close()

	step := newOAuthUserinfoStep("test", googleOAuthTestConfig(map[string]any{
		"google_oauth_userinfo_url":           server.URL,
		"allow_insecure_test_oauth_endpoints": true,
		"access_token":                        "config-access-token",
	}))
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider": "google",
	}, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if errStr, _ := result.Output["error"].(string); errStr != "" {
		t.Fatalf("expected no error, got %q (output=%#v)", errStr, result.Output)
	}
	if result.Output["fetched"] != true {
		t.Fatalf("expected fetched=true, got %v", result.Output["fetched"])
	}
}

// TestOAuthUserinfo_ConfigAccessTokenWinsOverCurrent verifies config.access_token
// wins when both config and input supply it.
func TestOAuthUserinfo_ConfigAccessTokenWinsOverCurrent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer config-wins" {
			t.Fatalf("expected config.access_token to win, got %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "x"})
	}))
	defer server.Close()

	step := newOAuthUserinfoStep("test", googleOAuthTestConfig(map[string]any{
		"google_oauth_userinfo_url":           server.URL,
		"allow_insecure_test_oauth_endpoints": true,
		"access_token":                        "config-wins",
	}))
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider":     "google",
		"access_token": "input-loses",
	}, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Output["fetched"] != true {
		t.Fatalf("expected fetched=true, got %#v", result.Output)
	}
}

// TestOAuthUserinfo_FallsBackToCurrentAccessToken verifies fetch_userinfo falls
// back to current/input access_token when config does not supply one.
func TestOAuthUserinfo_FallsBackToCurrentAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer input-access-token" {
			t.Fatalf("expected bearer from input fallback, got %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "user"})
	}))
	defer server.Close()

	step := newOAuthUserinfoStep("test", googleOAuthTestConfig(map[string]any{
		"google_oauth_userinfo_url":           server.URL,
		"allow_insecure_test_oauth_endpoints": true,
	}))
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"provider":     "google",
		"access_token": "input-access-token",
	}, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Output["fetched"] != true {
		t.Fatalf("expected fetched=true via input fallback, got %#v", result.Output)
	}
}
