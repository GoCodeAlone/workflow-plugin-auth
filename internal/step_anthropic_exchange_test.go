package internal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestAnthropicExchange_OptInOffReturnsDisabled verifies the D17 confused-deputy
// gate: when enable_anthropic_oauth is false (the default), the step MUST refuse
// to perform the exchange and MUST NOT issue any HTTP request — the step mints
// long-lived Anthropic API keys, so it is opt-in only (ratchet enables it).
func TestAnthropicExchange_OptInOffReturnsDisabled(t *testing.T) {
	// Sentinel server: if hit, the gate failed and HTTP was issued.
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		hit = true
	}))
	defer srv.Close()

	step := newAnthropicExchangeStep("test", map[string]any{
		// enable_anthropic_oauth intentionally OMITTED (default false).
		"anthropic_oauth_token_url":           srv.URL,
		"allow_insecure_test_oauth_endpoints": true,
	})

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"code":          "code-123",
		"redirect_uri":  "https://app.example.com/callback",
		"code_verifier": "verifier-123",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hit {
		t.Fatalf("opt-in OFF: step issued HTTP request (D17 gate failed)")
	}
	if result == nil || result.Output["success"] != false {
		t.Fatalf("expected success=false, got %#v", result)
	}
	if result.Output["disabled"] != true {
		t.Fatalf("expected disabled=true, got %#v", result)
	}
	if k, present := result.Output["api_key"]; present && k != "" {
		t.Fatalf("expected no api_key when disabled, got %v", result.Output["api_key"])
	}
}

// TestAnthropicExchange_OptInOnStringFlagRejected mirrors the existing oauth
// step convention: allow_insecure_test_oauth_endpoints must be a strict bool,
// not a string, so a YAML coercion cannot silently enable test overrides.
func TestAnthropicExchange_OptInOnStringFlagRejected(t *testing.T) {
	step := newAnthropicExchangeStep("test", map[string]any{
		"enable_anthropic_oauth":              true,
		"allow_insecure_test_oauth_endpoints": "true", // string — must be rejected
	})

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"code":         "code-123",
		"redirect_uri": "https://app.example.com/callback",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Endpoint override rejected -> production constants retained -> step hits
	// the real network and fails (we cannot assert on the real endpoint, but
	// success MUST be false either via disabled-on-error or network failure).
	if result.Output["success"] == true {
		t.Fatalf("expected success=false with string test flag, got %#v", result.Output)
	}
}

// TestAnthropicExchange_TwoStepReturnsAPIKey verifies the full 2-step exchange
// against stub servers mocking both Anthropic endpoints:
//  1. POST token URL (code -> access_token)
//  2. POST create_api_key URL (access_token -> permanent raw_key)
//
// It asserts the PKCE quirk (state == code_verifier) and that the redirect_uri
// comes from RUNTIME input, not config.
func TestAnthropicExchange_TwoStepReturnsAPIKey(t *testing.T) {
	var (
		tokenBody    url.Values
		apiKeyAuthz  string
		apiKeyCalled bool
	)

	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("token: expected POST, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		// Token endpoint expects a JSON body (per the recovered orchestrator
		// source), not form-encoded like the generic oauth providers.
		var raw map[string]any
		_ = json.Unmarshal(body, &raw)
		form := url.Values{}
		for k, v := range raw {
			if s, ok := v.(string); ok {
				form.Set(k, s)
			}
		}
		tokenBody = form
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-xyz",
			"token_type":   "Bearer",
		})
	}))
	defer tokenSrv.Close()

	apiKeySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiKeyCalled = true
		if r.Method != http.MethodPost {
			t.Fatalf("api_key: expected POST, got %s", r.Method)
		}
		apiKeyAuthz = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"raw_key": "sk-ant-permanent-key",
		})
	}))
	defer apiKeySrv.Close()

	step := newAnthropicExchangeStep("test", map[string]any{
		"enable_anthropic_oauth":              true,
		"anthropic_oauth_token_url":           tokenSrv.URL,
		"anthropic_create_api_key_url":        apiKeySrv.URL,
		"allow_insecure_test_oauth_endpoints": true,
	})

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"code":          "code-123",
		"redirect_uri":  "https://spa.example.com/auth/callback",
		"code_verifier": "verifier-456",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !apiKeyCalled {
		t.Fatalf("expected step 2 (create_api_key) to be called")
	}
	if result.Output["success"] != true {
		t.Fatalf("expected success=true, got %#v", result.Output)
	}
	if result.Output["api_key"] != "sk-ant-permanent-key" {
		t.Fatalf("expected api_key=sk-ant-permanent-key, got %v", result.Output["api_key"])
	}
	if result.Output["access_token"] != "access-xyz" {
		t.Fatalf("expected access_token=access-xyz, got %v", result.Output["access_token"])
	}

	// --- Step 1 request assertions ---
	if tokenBody.Get("grant_type") != "authorization_code" {
		t.Fatalf("expected grant_type=authorization_code, got %q", tokenBody.Get("grant_type"))
	}
	if tokenBody.Get("code") != "code-123" {
		t.Fatalf("expected code in token request, got %q", tokenBody.Get("code"))
	}
	if tokenBody.Get("redirect_uri") != "https://spa.example.com/auth/callback" {
		t.Fatalf("expected runtime redirect_uri in token request, got %q", tokenBody.Get("redirect_uri"))
	}
	// Hardcoded public Claude CLI client id.
	if tokenBody.Get("client_id") != "9d1c250a-e61b-44d9-88ed-5944d1962f5e" {
		t.Fatalf("expected hardcoded Claude CLI client_id, got %q", tokenBody.Get("client_id"))
	}
	// PKCE quirk: state == code_verifier.
	if tokenBody.Get("code_verifier") != "verifier-456" {
		t.Fatalf("expected code_verifier=verifier-456, got %q", tokenBody.Get("code_verifier"))
	}
	if tokenBody.Get("state") != "verifier-456" {
		t.Fatalf("PKCE quirk: expected state=verifier-456 (reused as code_verifier), got %q", tokenBody.Get("state"))
	}

	// --- Step 2 request assertions ---
	if apiKeyAuthz != "Bearer access-xyz" {
		t.Fatalf("expected step 2 Authorization=Bearer access-xyz, got %q", apiKeyAuthz)
	}
}

// TestAnthropicExchange_StateAsVerifierAlias verifies the PKCE quirk from the
// other direction: when only `state` is supplied (no explicit code_verifier),
// the step uses state as the verifier for both code_verifier and state params.
func TestAnthropicExchange_StateAsVerifierAlias(t *testing.T) {
	var tokenBody url.Values
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var raw map[string]any
		_ = json.Unmarshal(body, &raw)
		tokenBody = url.Values{}
		for k, v := range raw {
			if s, ok := v.(string); ok {
				tokenBody.Set(k, s)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-xyz"})
	}))
	defer tokenSrv.Close()

	apiKeySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"raw_key": "sk-ant-key"})
	}))
	defer apiKeySrv.Close()

	step := newAnthropicExchangeStep("test", map[string]any{
		"enable_anthropic_oauth":              true,
		"anthropic_oauth_token_url":           tokenSrv.URL,
		"anthropic_create_api_key_url":        apiKeySrv.URL,
		"allow_insecure_test_oauth_endpoints": true,
	})

	_, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"code":         "code-123",
		"redirect_uri": "https://spa.example.com/auth/callback",
		"state":        "state-only-verifier", // no code_verifier field
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if tokenBody.Get("code_verifier") != "state-only-verifier" {
		t.Fatalf("expected state to be used as code_verifier, got %q", tokenBody.Get("code_verifier"))
	}
	if tokenBody.Get("state") != "state-only-verifier" {
		t.Fatalf("expected state echoed, got %q", tokenBody.Get("state"))
	}
}

// TestAnthropicExchange_MissingCodeReturnsError verifies input validation: a
// missing authorization code short-circuits before any HTTP.
func TestAnthropicExchange_MissingCodeReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatalf("expected no HTTP when code missing")
	}))
	defer srv.Close()

	step := newAnthropicExchangeStep("test", map[string]any{
		"enable_anthropic_oauth":              true,
		"anthropic_oauth_token_url":           srv.URL,
		"anthropic_create_api_key_url":        srv.URL,
		"allow_insecure_test_oauth_endpoints": true,
	})

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"redirect_uri":  "https://app.example.com/callback",
		"code_verifier": "verifier",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["success"] != false {
		t.Fatalf("expected success=false for missing code, got %#v", result.Output)
	}
}

// TestAnthropicExchange_TokenEndpointErrorPropagates verifies that a non-2xx
// from step 1 aborts the exchange (step 2 is never reached).
func TestAnthropicExchange_TokenEndpointErrorPropagates(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenSrv.Close()

	apiKeyCalled := false
	apiKeySrv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		apiKeyCalled = true
	}))
	defer apiKeySrv.Close()

	step := newAnthropicExchangeStep("test", map[string]any{
		"enable_anthropic_oauth":              true,
		"anthropic_oauth_token_url":           tokenSrv.URL,
		"anthropic_create_api_key_url":        apiKeySrv.URL,
		"allow_insecure_test_oauth_endpoints": true,
	})

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"code":         "bad-code",
		"redirect_uri": "https://app.example.com/callback",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if apiKeyCalled {
		t.Fatalf("step 2 must NOT be reached when step 1 fails")
	}
	if result.Output["success"] != false {
		t.Fatalf("expected success=false on token error, got %#v", result.Output)
	}
	if k, present := result.Output["api_key"]; present && k != "" {
		t.Fatalf("expected no api_key on token error, got %v", result.Output["api_key"])
	}
}

// TestAnthropicExchange_NoRawKeyReturnsError verifies step 2 response parsing:
// a successful 2xx without raw_key is treated as a failure (no silent empty
// api_key).
func TestAnthropicExchange_NoRawKeyReturnsError(t *testing.T) {
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-xyz"})
	}))
	defer tokenSrv.Close()

	apiKeySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "k_123"}) // no raw_key
	}))
	defer apiKeySrv.Close()

	step := newAnthropicExchangeStep("test", map[string]any{
		"enable_anthropic_oauth":              true,
		"anthropic_oauth_token_url":           tokenSrv.URL,
		"anthropic_create_api_key_url":        apiKeySrv.URL,
		"allow_insecure_test_oauth_endpoints": true,
	})

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"code":         "code-123",
		"redirect_uri": "https://app.example.com/callback",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["success"] != false {
		t.Fatalf("expected success=false when raw_key missing, got %#v", result.Output)
	}
	if k, present := result.Output["api_key"]; present && k != "" {
		t.Fatalf("expected no api_key when raw_key missing, got %v", result.Output["api_key"])
	}
}
