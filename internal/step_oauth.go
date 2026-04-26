package internal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

const (
	googleOAuthAuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
	googleOAuthTokenURL         = "https://oauth2.googleapis.com/token"
	googleOAuthUserinfoURL      = "https://openidconnect.googleapis.com/v1/userinfo"
	oauthDefaultReturnTo        = "/auth/callback"
	oauthDefaultStateTTL        = 15 * time.Minute
	oauthJSONBodyLimit          = 1 << 20
)

var googleOAuthScopes = []string{"openid", "email", "profile"}

type oauthProviderConfigStep struct {
	name   string
	config map[string]any
}

func newOAuthProviderConfigStep(name string, config map[string]any) *oauthProviderConfigStep {
	return &oauthProviderConfigStep{name: name, config: config}
}

func (s *oauthProviderConfigStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	provider := oauthProviderFrom(s.config, current)
	cfg, disabledReason := oauthProviderConfig(s.config, provider)
	if disabledReason != "" {
		return &sdk.StepResult{Output: map[string]any{
			"provider":        provider,
			"available":       false,
			"disabled_reason": disabledReason,
		}}, nil
	}
	return &sdk.StepResult{Output: cfg.output()}, nil
}

type oauthStartStep struct {
	name   string
	config map[string]any
}

func newOAuthStartStep(name string, config map[string]any) *oauthStartStep {
	return &oauthStartStep{name: name, config: config}
}

func (s *oauthStartStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	provider := oauthProviderFrom(s.config, current)
	cfg, disabledReason := oauthProviderConfig(s.config, provider)
	if disabledReason != "" {
		return &sdk.StepResult{Output: map[string]any{"started": false, "provider": provider, "error": disabledReason}}, nil
	}

	returnTo, err := normalizeOAuthReturnTo(oauthString(current, "return_to"))
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"started": false, "provider": provider, "error": err.Error()}}, nil
	}

	state, err := oauthRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("generate oauth state: %w", err)
	}

	query := url.Values{}
	query.Set("client_id", cfg.clientID)
	query.Set("redirect_uri", cfg.redirectURL)
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(cfg.scopes, " "))
	query.Set("state", state)
	query.Set("access_type", "offline")
	query.Set("prompt", "consent")

	output := map[string]any{
		"started":           true,
		"provider":          cfg.provider,
		"state":             state,
		"return_to":         returnTo,
		"expires_at":        time.Now().UTC().Add(oauthStateTTL(s.config)).Format(time.RFC3339),
		"redirect_url":      cfg.redirectURL,
		"authorization_url": "",
	}

	if oauthBool(current, "pkce_required") || oauthBool(s.config, "pkce_required") {
		verifier, err := oauthRandomToken(64)
		if err != nil {
			return nil, fmt.Errorf("generate oauth code verifier: %w", err)
		}
		challenge := oauthPKCEChallenge(verifier)
		query.Set("code_challenge", challenge)
		query.Set("code_challenge_method", "S256")
		output["code_verifier"] = verifier
		output["code_challenge"] = challenge
		output["code_challenge_method"] = "S256"
	}

	authURL, err := url.Parse(cfg.authorizationURL)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"started": false, "provider": provider, "error": "invalid authorization_url"}}, nil
	}
	authURL.RawQuery = query.Encode()
	output["authorization_url"] = authURL.String()

	return &sdk.StepResult{Output: output}, nil
}

type oauthExchangeStep struct {
	name   string
	config map[string]any
	client *http.Client
}

func newOAuthExchangeStep(name string, config map[string]any) *oauthExchangeStep {
	return &oauthExchangeStep{name: name, config: config, client: http.DefaultClient}
}

func (s *oauthExchangeStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	provider := oauthProviderFrom(s.config, current)
	cfg, disabledReason := oauthProviderConfig(s.config, provider)
	if disabledReason != "" {
		return &sdk.StepResult{Output: map[string]any{"exchanged": false, "provider": provider, "error": disabledReason}}, nil
	}

	code := oauthString(current, "code")
	if code == "" {
		return &sdk.StepResult{Output: map[string]any{"exchanged": false, "provider": provider, "error": "missing code"}}, nil
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", cfg.redirectURL)
	form.Set("client_id", cfg.clientID)
	form.Set("client_secret", cfg.clientSecret)
	if verifier := oauthString(current, "code_verifier"); verifier != "" {
		form.Set("code_verifier", verifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	var tokenResponse map[string]any
	if err := oauthDoJSON(s.client, req, "token endpoint", &tokenResponse); err != nil {
		return &sdk.StepResult{Output: map[string]any{"exchanged": false, "provider": provider, "error": err.Error()}}, nil
	}

	output := map[string]any{
		"exchanged":  true,
		"provider":   cfg.provider,
		"raw_tokens": tokenResponse,
	}
	for _, key := range []string{"access_token", "refresh_token", "id_token", "token_type", "scope"} {
		if value, ok := tokenResponse[key]; ok {
			output[key] = value
		}
	}
	if value, ok := tokenResponse["expires_in"]; ok {
		output["expires_in"] = value
	}
	return &sdk.StepResult{Output: output}, nil
}

type oauthUserinfoStep struct {
	name   string
	config map[string]any
	client *http.Client
}

func newOAuthUserinfoStep(name string, config map[string]any) *oauthUserinfoStep {
	return &oauthUserinfoStep{name: name, config: config, client: http.DefaultClient}
}

func (s *oauthUserinfoStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	provider := oauthProviderFrom(s.config, current)
	cfg, disabledReason := oauthProviderConfig(s.config, provider)
	if disabledReason != "" {
		return &sdk.StepResult{Output: map[string]any{"fetched": false, "provider": provider, "error": disabledReason}}, nil
	}

	accessToken := oauthString(current, "access_token")
	if accessToken == "" {
		return &sdk.StepResult{Output: map[string]any{"fetched": false, "provider": provider, "error": "missing access_token"}}, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.userinfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create userinfo request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	var claims map[string]any
	if err := oauthDoJSON(s.client, req, "userinfo endpoint", &claims); err != nil {
		return &sdk.StepResult{Output: map[string]any{"fetched": false, "provider": provider, "error": err.Error()}}, nil
	}

	subject := oauthClaimString(claims, "sub")
	output := map[string]any{
		"fetched":          true,
		"provider":         cfg.provider,
		"provider_subject": subject,
		"provider_user":    subject,
		"email":            oauthClaimString(claims, "email"),
		"email_verified":   oauthClaimBool(claims, "email_verified"),
		"name":             oauthClaimString(claims, "name"),
		"picture":          oauthClaimString(claims, "picture"),
		"raw_claims":       claims,
	}
	return &sdk.StepResult{Output: output}, nil
}

type oauthProviderConfigData struct {
	provider         string
	clientID         string
	clientSecret     string
	redirectURL      string
	authorizationURL string
	tokenURL         string
	userinfoURL      string
	scopes           []string
}

func (c oauthProviderConfigData) output() map[string]any {
	return map[string]any{
		"provider":          c.provider,
		"available":         true,
		"client_id":         c.clientID,
		"redirect_url":      c.redirectURL,
		"authorization_url": c.authorizationURL,
		"token_url":         c.tokenURL,
		"userinfo_url":      c.userinfoURL,
		"scopes":            append([]string(nil), c.scopes...),
	}
}

func oauthProviderConfig(config map[string]any, provider string) (oauthProviderConfigData, string) {
	switch provider {
	case "google":
		cfg := oauthProviderConfigData{
			provider:         "google",
			clientID:         oauthString(config, "google_oauth_client_id"),
			clientSecret:     oauthString(config, "google_oauth_client_secret"),
			redirectURL:      oauthString(config, "google_oauth_redirect_url"),
			authorizationURL: googleOAuthAuthorizationURL,
			tokenURL:         googleOAuthTokenURL,
			userinfoURL:      googleOAuthUserinfoURL,
			scopes:           append([]string(nil), googleOAuthScopes...),
		}
		if cfg.clientID == "" || cfg.clientSecret == "" || cfg.redirectURL == "" {
			return cfg, "google oauth is not fully configured"
		}
		if override, ok := oauthEndpointURL(config, "google_oauth_authorization_url", googleOAuthAuthorizationURL, "accounts.google.com"); !ok {
			return cfg, "google authorization_url must use https and the expected Google hostname unless test endpoints are explicitly enabled"
		} else {
			cfg.authorizationURL = override
		}
		if override, ok := oauthEndpointURL(config, "google_oauth_token_url", googleOAuthTokenURL, "oauth2.googleapis.com"); !ok {
			return cfg, "google token_url must use https and the expected Google hostname unless test endpoints are explicitly enabled"
		} else {
			cfg.tokenURL = override
		}
		if override, ok := oauthEndpointURL(config, "google_oauth_userinfo_url", googleOAuthUserinfoURL, "openidconnect.googleapis.com"); !ok {
			return cfg, "google userinfo_url must use https and the expected Google hostname unless test endpoints are explicitly enabled"
		} else {
			cfg.userinfoURL = override
		}
		return cfg, ""
	case "facebook", "instagram", "x", "bluesky":
		return oauthProviderConfigData{provider: provider}, provider + " oauth provider is disabled in this release"
	case "":
		return oauthProviderConfigData{}, "missing oauth provider"
	default:
		return oauthProviderConfigData{provider: provider}, "unsupported oauth provider"
	}
}

func oauthProviderFrom(config, current map[string]any) string {
	if provider := normalizeOAuthProvider(oauthString(current, "provider")); provider != "" {
		return provider
	}
	return normalizeOAuthProvider(oauthString(config, "oauth_provider"))
}

func normalizeOAuthProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "twitter":
		return "x"
	default:
		return provider
	}
}

func oauthEndpointURL(config map[string]any, key, def, expectedHost string) (string, bool) {
	value := strings.TrimSpace(oauthString(config, key))
	if value == "" {
		return def, true
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return "", false
	}
	if oauthBool(config, "allow_insecure_test_oauth_endpoints") {
		return value, true
	}
	if parsed.Scheme == "https" && strings.EqualFold(parsed.Hostname(), expectedHost) {
		return value, true
	}
	return "", false
}

func normalizeOAuthReturnTo(returnTo string) (string, error) {
	returnTo = strings.TrimSpace(returnTo)
	if returnTo == "" {
		return oauthDefaultReturnTo, nil
	}
	parsed, err := url.Parse(returnTo)
	if err != nil {
		return "", fmt.Errorf("invalid return_to")
	}
	if parsed.IsAbs() || parsed.Host != "" || strings.HasPrefix(returnTo, "//") {
		return "", fmt.Errorf("return_to must be a same-site path")
	}
	if !strings.HasPrefix(returnTo, "/") {
		returnTo = "/" + returnTo
	}
	return returnTo, nil
}

func oauthRandomToken(byteCount int) (string, error) {
	data := make([]byte, byteCount)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func oauthPKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func oauthDoJSON(client *http.Client, req *http.Request, label string, target any) error {
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s request failed: %w", label, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, oauthJSONBodyLimit))
	if err != nil {
		return fmt.Errorf("%s response read failed: %w", label, err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("%s returned %d: %s", label, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%s response decode failed: %w", label, err)
	}
	return nil
}

func oauthString(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	switch v := values[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	default:
		return ""
	}
}

func oauthBool(values map[string]any, key string) bool {
	if values == nil {
		return false
	}
	switch v := values[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

func oauthStateTTL(config map[string]any) time.Duration {
	switch v := config["oauth_state_ttl_minutes"].(type) {
	case int:
		if v > 0 {
			return time.Duration(v) * time.Minute
		}
	case int64:
		if v > 0 {
			return time.Duration(v) * time.Minute
		}
	case float64:
		if v > 0 {
			return time.Duration(v) * time.Minute
		}
	}
	return oauthDefaultStateTTL
}

func oauthClaimString(claims map[string]any, key string) string {
	value, _ := claims[key].(string)
	return value
}

func oauthClaimBool(claims map[string]any, key string) bool {
	value, _ := claims[key].(bool)
	return value
}
