package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// Anthropic OAuth constants (recovered from the orchestrator's deleted
// step_oauth_exchange.go — agent repo commit 6b94458^). The client_id is the
// public Claude CLI identifier; it is NOT a secret and is hardcoded to match
// the CLI's registered redirect.
const (
	anthropicOAuthClientID   = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	anthropicOAuthTokenURL   = "https://console.anthropic.com/v1/oauth/token"
	anthropicCreateAPIKeyURL = "https://api.anthropic.com/api/oauth/claude_cli/create_api_key"
	anthropicHTTPTimeout     = 15 * time.Second
)

// anthropicExchangeStep implements step.auth_anthropic_exchange — Anthropic's
// bespoke 2-step OAuth, DISTINCT from the generic auth_oauth_exchange
// (google/facebook):
//  1. POST console.anthropic.com/v1/oauth/token (code -> access_token)
//  2. POST api.anthropic.com/.../create_api_key (access_token -> permanent key)
//
// The PKCE `state` parameter is reused as the `code_verifier` (Anthropic
// quirk). The redirect_uri is read from RUNTIME input (the SPA's redirect),
// never from config.
//
// D17 confused-deputy gate: enable_anthropic_oauth MUST be explicitly true in
// the step config for the exchange to proceed. The default (false) returns a
// disabled result and performs NO HTTP — the step mints long-lived Anthropic
// API keys, so only opt-in consumers (ratchet) enable it.
type anthropicExchangeStep struct {
	name   string
	config map[string]any
	client *http.Client
}

func newAnthropicExchangeStep(name string, config map[string]any) *anthropicExchangeStep {
	return &anthropicExchangeStep{name: name, config: config, client: &http.Client{Timeout: anthropicHTTPTimeout}}
}

func (s *anthropicExchangeStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	// D17 opt-in gate: default-off. The step mints long-lived Anthropic API
	// keys; only opt-in consumers enable it.
	if !oauthStrictBool(s.config, "enable_anthropic_oauth") {
		return &sdk.StepResult{Output: map[string]any{
			"success":  false,
			"disabled": true,
			"error":    "auth_anthropic_exchange: disabled (enable_anthropic_oauth not set true); this step mints long-lived Anthropic API keys and is opt-in only",
		}}, nil
	}

	code := oauthString(current, "code")
	if code == "" {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   "missing code",
		}}, nil
	}
	redirectURI := oauthString(current, "redirect_uri")
	// PKCE quirk: code_verifier is the verifier; `state` is an alias used by
	// the CLI redirect. Either field satisfies the verifier, and the OAuth
	// `state` param is set to the SAME value (Anthropic reuses state as the
	// code_verifier).
	codeVerifier := oauthString(current, "code_verifier")
	if codeVerifier == "" {
		codeVerifier = oauthString(current, "state")
	}

	tokenURL, apiKeyURL := s.endpoints()

	// Step 1: exchange code for access token (JSON body, per Anthropic — NOT
	// form-encoded like the generic oauth providers).
	tokenReqBody, err := json.Marshal(map[string]any{
		"code":          code,
		"state":         codeVerifier,
		"grant_type":    "authorization_code",
		"client_id":     anthropicOAuthClientID,
		"redirect_uri":  redirectURI,
		"code_verifier": codeVerifier,
	})
	if err != nil {
		return nil, fmt.Errorf("auth_anthropic_exchange: marshal token request: %w", err)
	}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(tokenReqBody))
	if err != nil {
		return nil, fmt.Errorf("auth_anthropic_exchange: create token request: %w", err)
	}
	tokenReq.Header.Set("Content-Type", "application/json")
	tokenReq.Header.Set("Accept", "application/json")

	var tokenResult map[string]any
	if err := oauthDoJSON(s.client, tokenReq, "anthropic token endpoint", &tokenResult); err != nil {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   err.Error(),
		}}, nil
	}
	accessToken := oauthClaimString(tokenResult, "access_token")
	if accessToken == "" {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   "no access_token in token response",
		}}, nil
	}

	// Step 2: create a permanent API key using the access token.
	apiKeyReq, err := http.NewRequestWithContext(ctx, http.MethodPost, apiKeyURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("auth_anthropic_exchange: create api_key request: %w", err)
	}
	apiKeyReq.Header.Set("Authorization", "Bearer "+accessToken)
	apiKeyReq.Header.Set("Content-Type", "application/json")
	apiKeyReq.Header.Set("Accept", "application/json")

	var apiKeyResult map[string]any
	if err := oauthDoJSON(s.client, apiKeyReq, "anthropic api_key endpoint", &apiKeyResult); err != nil {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   err.Error(),
		}}, nil
	}
	rawKey := oauthClaimString(apiKeyResult, "raw_key")
	if rawKey == "" {
		return &sdk.StepResult{Output: map[string]any{
			"success": false,
			"error":   "no raw_key in api_key response",
		}}, nil
	}

	return &sdk.StepResult{Output: map[string]any{
		"success":      true,
		"api_key":      rawKey,
		"access_token": accessToken,
	}}, nil
}

// endpoints returns the token + api_key URLs. Production constants are used
// unless the host sets BOTH the override URL AND the strict-bool
// allow_insecure_test_oauth_endpoints flag (mirrors the generic oauth step's
// convention: a YAML-coerced string "true" is rejected so a config typo cannot
// silently redirect key-minting traffic).
func (s *anthropicExchangeStep) endpoints() (tokenURL, apiKeyURL string) {
	tokenURL = anthropicOAuthTokenURL
	apiKeyURL = anthropicCreateAPIKeyURL
	if oauthStrictBool(s.config, "allow_insecure_test_oauth_endpoints") {
		if override := oauthString(s.config, "anthropic_oauth_token_url"); override != "" {
			tokenURL = override
		}
		if override := oauthString(s.config, "anthropic_create_api_key_url"); override != "" {
			apiKeyURL = override
		}
	}
	return tokenURL, apiKeyURL
}
