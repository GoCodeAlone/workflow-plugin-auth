package internal

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type authMethodsPolicyStep struct {
	name   string
	config map[string]any
}

func newAuthMethodsPolicyStep(name string, config map[string]any) *authMethodsPolicyStep {
	return &authMethodsPolicyStep{name: name, config: config}
}

func (s *authMethodsPolicyStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, runtimeConfig map[string]any) (*sdk.StepResult, error) {
	source := mergePolicyInputs(s.config, runtimeConfig, current)
	policy := buildAuthMethodsPolicy(source)
	return &sdk.StepResult{Output: policy}, nil
}

type authMethodsResponseStep struct {
	name string
}

func newAuthMethodsResponseStep(name string, _ map[string]any) *authMethodsResponseStep {
	return &authMethodsResponseStep{name: name}
}

func (s *authMethodsResponseStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	response := buildAuthMethodsResponse(current)
	return &sdk.StepResult{Output: response}, nil
}

type authPolicyAuditStep struct {
	name   string
	config map[string]any
}

func newAuthPolicyAuditStep(name string, config map[string]any) *authPolicyAuditStep {
	return &authPolicyAuditStep{name: name, config: config}
}

func (s *authPolicyAuditStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, runtimeConfig map[string]any) (*sdk.StepResult, error) {
	source := mergePolicyInputs(s.config, runtimeConfig, current)

	var violations []string
	if isProduction(policyString(source, "environment")) {
		if policyStrictTrue(source, "password_auth_enabled") || policyStrictTrue(source, "password_enabled") {
			violations = append(violations, "password auth cannot be enabled in production")
		}
		if policyInt(source, "password_hash_count") > 0 {
			violations = append(violations, "production contains password hashes")
		}
	}

	return &sdk.StepResult{Output: map[string]any{
		"passed":     len(violations) == 0,
		"violations": violations,
	}}, nil
}

func buildAuthMethodsPolicy(source map[string]any) map[string]any {
	passkeyEnabled := policyPresent(source, "webauthn_rp_id") && policyPresent(source, "webauthn_origin")
	emailCodeEnabled := policyPresent(source, "smtp_host") && policyPresent(source, "smtp_from")
	smsCodeEnabled := smsPolicyReady(source)

	passwordRequested := policyStrictTrue(source, "password_auth_enabled") || policyStrictTrue(source, "password_enabled")
	passwordEnabled := passwordRequested && !isProduction(policyString(source, "environment"))
	totpEnabled := policyStrictTrue(source, "totp_auth_enabled") || policyStrictTrue(source, "totp_enabled")

	oauthProviders := oauthPolicyProviders(source)

	primaryCount := 0
	for _, enabled := range []bool{passkeyEnabled, emailCodeEnabled, smsCodeEnabled, passwordEnabled} {
		if enabled {
			primaryCount++
		}
	}
	primaryCount += len(oauthProviders)

	return map[string]any{
		"passkey_enabled":       passkeyEnabled,
		"email_code_enabled":    emailCodeEnabled,
		"sms_code_enabled":      smsCodeEnabled,
		"password_enabled":      passwordEnabled,
		"password_auth_enabled": passwordEnabled,
		"totp_enabled":          totpEnabled,
		"oauth_providers":       oauthProviders,
		"primary_method_count":  primaryCount,
	}
}

func buildAuthMethodsResponse(current map[string]any) map[string]any {
	response := map[string]any{
		"passkey_enabled":       policyBool(current, "passkey_enabled"),
		"email_code_enabled":    policyBool(current, "email_code_enabled"),
		"sms_code_enabled":      policyBool(current, "sms_code_enabled"),
		"password_enabled":      policyBool(current, "password_enabled"),
		"password_auth_enabled": policyBool(current, "password_auth_enabled"),
		"totp_enabled":          policyBool(current, "totp_enabled"),
		"oauth_providers":       policyStringSlice(current, "oauth_providers"),
		"primary_method_count":  policyInt(current, "primary_method_count"),
	}

	methods := make([]string, 0, 6)
	if response["passkey_enabled"] == true {
		methods = append(methods, "passkey")
	}
	if response["email_code_enabled"] == true {
		methods = append(methods, "email_code")
	}
	if response["sms_code_enabled"] == true {
		methods = append(methods, "sms_code")
	}
	if response["password_enabled"] == true {
		methods = append(methods, "password")
	}
	for _, provider := range response["oauth_providers"].([]string) {
		methods = append(methods, "oauth_"+provider)
	}
	response["methods"] = methods

	return response
}

type authPolicyGateStep struct {
	name   string
	config map[string]any
}

func newAuthPolicyGateStep(name string, config map[string]any) *authPolicyGateStep {
	return &authPolicyGateStep{name: name, config: config}
}

func (s *authPolicyGateStep) Execute(_ context.Context, _ map[string]any, steps map[string]map[string]any, current, _, runtimeConfig map[string]any) (*sdk.StepResult, error) {
	policyStep := policyString(s.config, "policy_step")
	if policyStep == "" {
		policyStep = "policy"
	}

	policy := steps[policyStep]
	output := map[string]any{
		"passkey_enabled":       policyBool(policy, "passkey_enabled"),
		"email_code_enabled":    policyBool(policy, "email_code_enabled"),
		"sms_code_enabled":      policyBool(policy, "sms_code_enabled"),
		"password_enabled":      policyBool(policy, "password_enabled"),
		"password_auth_enabled": policyBool(policy, "password_auth_enabled"),
		"totp_enabled":          policyBool(policy, "totp_enabled"),
		"oauth_providers":       filterPolicyOAuthProviders(policyStringSlice(policy, "oauth_providers"), supportedPolicyOAuthProviders(s.config)),
	}

	secretSource := mergePolicyInputs(s.config, runtimeConfig, current)
	if output["email_code_enabled"] == true && policyString(secretSource, "signing_secret") == "" {
		output["email_code_enabled"] = false
	}
	output["primary_method_count"] = countPrimaryPolicyMethods(output)

	return &sdk.StepResult{Output: output}, nil
}

func supportedPolicyOAuthProviders(config map[string]any) map[string]struct{} {
	providers := policyStringSlice(config, "oauth_supported_providers")
	if len(providers) == 0 {
		providers = []string{"google"}
	}

	supported := make(map[string]struct{}, len(providers))
	for _, provider := range providers {
		provider = strings.ToLower(strings.TrimSpace(provider))
		if provider != "" {
			supported[provider] = struct{}{}
		}
	}
	return supported
}

func filterPolicyOAuthProviders(providers []string, supported map[string]struct{}) []string {
	filtered := make([]string, 0, len(providers))
	for _, provider := range providers {
		provider = strings.ToLower(strings.TrimSpace(provider))
		if _, ok := supported[provider]; ok {
			filtered = append(filtered, provider)
		}
	}
	return filtered
}

func countPrimaryPolicyMethods(output map[string]any) int {
	count := 0
	for _, enabled := range []bool{
		policyBool(output, "passkey_enabled"),
		policyBool(output, "email_code_enabled"),
		policyBool(output, "sms_code_enabled"),
		policyBool(output, "password_enabled"),
	} {
		if enabled {
			count++
		}
	}
	return count + len(policyStringSlice(output, "oauth_providers"))
}

func oauthPolicyProviders(source map[string]any) []string {
	provider := strings.ToLower(policyString(source, "oauth_provider"))
	if provider != "" && provider != "google" {
		return nil
	}
	if !policyAnyStrictTrue(source, "auth_routes_enabled", "routes_enabled", "oauth_routes_enabled") {
		return nil
	}
	if !policyPresent(source, "google_oauth_client_id") ||
		!policyPresent(source, "google_oauth_client_secret") ||
		!policyPresent(source, "google_oauth_redirect_url") {
		return nil
	}
	if _, disabledReason := oauthProviderConfig(source, "google"); disabledReason != "" {
		return nil
	}
	return []string{"google"}
}

func smsPolicyReady(source map[string]any) bool {
	if !policyAnyStrictTrue(source, "auth_routes_enabled", "routes_enabled") ||
		!policyAnyStrictTrue(source, "sms_auth_enabled", "sms_enabled") {
		return false
	}
	if !policyPresent(source, "twilio_verify_service_sid") {
		return false
	}
	if policyPresent(source, "twilio_auth_token") {
		return policyPresent(source, "twilio_account_sid")
	}
	return policyPresent(source, "twilio_api_key_sid") && policyPresent(source, "twilio_api_key_secret")
}

func mergePolicyInputs(inputs ...map[string]any) map[string]any {
	merged := map[string]any{}
	for _, input := range inputs {
		for key, value := range input {
			merged[key] = value
		}
	}
	return merged
}

func policyPresent(source map[string]any, key string) bool {
	return policyString(source, key) != ""
}

func policyString(source map[string]any, key string) string {
	value, ok := source[key]
	if !ok || value == nil {
		return ""
	}

	var text string
	switch v := value.(type) {
	case string:
		text = v
	case fmt.Stringer:
		text = v.String()
	default:
		text = fmt.Sprint(v)
	}

	text = strings.TrimSpace(text)
	if text == "" || strings.Contains(text, "{{") {
		return ""
	}
	return text
}

func policyBool(source map[string]any, key string) bool {
	value, ok := source[key]
	if !ok || value == nil {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(strings.TrimSpace(v), "true")
	default:
		return false
	}
}

func policyStrictTrue(source map[string]any, key string) bool {
	value, ok := source[key]
	if !ok || value == nil {
		return false
	}
	switch v := value.(type) {
	case bool:
		return v
	case string:
		text := strings.TrimSpace(v)
		return text != "" && !strings.Contains(text, "{{") && strings.EqualFold(text, "true")
	default:
		return false
	}
}

func policyAnyStrictTrue(source map[string]any, keys ...string) bool {
	for _, key := range keys {
		if policyStrictTrue(source, key) {
			return true
		}
	}
	return false
}

func policyInt(source map[string]any, key string) int {
	value, ok := source[key]
	if !ok || value == nil {
		return 0
	}
	switch v := value.(type) {
	case int:
		return v
	case int8:
		return int(v)
	case int16:
		return int(v)
	case int32:
		return int(v)
	case int64:
		return int(v)
	case uint:
		return int(v)
	case uint8:
		return int(v)
	case uint16:
		return int(v)
	case uint32:
		return int(v)
	case uint64:
		return int(v)
	case float32:
		return int(v)
	case float64:
		return int(v)
	case string:
		text := policyString(source, key)
		if text == "" {
			return 0
		}
		n, err := strconv.Atoi(text)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

func policyStringSlice(source map[string]any, key string) []string {
	value, ok := source[key]
	if !ok || value == nil {
		return nil
	}
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []any:
		values := make([]string, 0, len(v))
		for _, item := range v {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" && !strings.Contains(text, "{{") {
				values = append(values, text)
			}
		}
		return values
	default:
		return nil
	}
}

func isProduction(environment string) bool {
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "prod", "production":
		return true
	default:
		return false
	}
}
