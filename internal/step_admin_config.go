package internal

import (
	"context"
	"net/url"
	"sort"
	"strings"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type authAdminConfigDescribeStep struct {
	name   string
	config map[string]any
}

func newAuthAdminConfigDescribeStep(name string, config map[string]any) *authAdminConfigDescribeStep {
	return &authAdminConfigDescribeStep{name: name, config: config}
}

func (s *authAdminConfigDescribeStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, runtimeConfig map[string]any) (*sdk.StepResult, error) {
	source := mergePolicyInputs(s.config, runtimeConfig, authAdminNestedConfig(current, "config"), current)
	policy := buildAuthMethodsPolicy(source)

	return &sdk.StepResult{Output: map[string]any{
		"groups":           buildAuthAdminGroups(source),
		"effective_config": sanitizeAuthAdminConfig(source),
		"methods_policy":   policy,
		"warnings":         authAdminWarnings(source, policy),
		"secret_fields":    authAdminSecretFields(source),
	}}, nil
}

type authAdminConfigValidateStep struct {
	name   string
	config map[string]any
}

func newAuthAdminConfigValidateStep(name string, config map[string]any) *authAdminConfigValidateStep {
	return &authAdminConfigValidateStep{name: name, config: config}
}

func (s *authAdminConfigValidateStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, runtimeConfig map[string]any) (*sdk.StepResult, error) {
	desired := authAdminNestedConfig(current, "desired_config")
	source := mergePolicyInputs(s.config, runtimeConfig, desired)
	policy := buildAuthMethodsPolicy(source)

	var errors []map[string]any
	var warnings []map[string]any

	if isProduction(policyString(source, "environment")) &&
		(policyStrictTrue(source, "password_auth_enabled") || policyStrictTrue(source, "password_enabled")) {
		errors = append(errors, authAdminDiagnostic("password_auth_enabled", "error", "password auth cannot be enabled in production"))
	}

	if requirePrimaryMethod(s.config, current) && policyInt(policy, "primary_method_count") == 0 {
		errors = append(errors, authAdminDiagnostic("primary_methods", "error", "at least one primary authentication method must be configured"))
	}

	errors = append(errors, validatePasskeyAdminConfig(source)...)
	errors = append(errors, validateOAuthAdminConfig(source)...)
	warnings = append(warnings, authAdminWarnings(source, policy)...)

	return &sdk.StepResult{Output: map[string]any{
		"valid":           len(errors) == 0,
		"accepted_config": sanitizeAuthAdminConfig(desired),
		"methods_policy":  policy,
		"errors":          errors,
		"warnings":        warnings,
		"secret_fields":   authAdminSecretFields(desired),
	}}, nil
}

func buildAuthAdminGroups(source map[string]any) []map[string]any {
	groups := []map[string]any{
		{
			"key":         "primary_methods",
			"label":       "Primary methods",
			"description": "Login methods that can establish a user session.",
			"controls": []map[string]any{
				authAdminControl(source, "webauthn_rp_id", "Passkey relying party ID", "text", "Domain used by browsers to scope passkey credentials.", "Use the effective application host, for example app.example.com.", true, ""),
				authAdminControl(source, "webauthn_origin", "Passkey origin", "url", "Origin that WebAuthn challenges must be created for.", "Use the full HTTPS origin, for example https://app.example.com.", true, ""),
				authAdminControl(source, "password_auth_enabled", "Password login", "toggle", "Allows users to sign in with a password outside production.", "Production policy blocks password login even when this is enabled.", false, passwordAdminDisabledReason(source)),
			},
		},
		{
			"key":         "delivery_methods",
			"label":       "Delivery methods",
			"description": "Email and SMS configuration used by passwordless login challenges.",
			"controls": []map[string]any{
				authAdminControl(source, "smtp_host", "SMTP host", "text", "SMTP server used for email codes and magic links.", "Set with smtp_from to enable email-code login.", false, ""),
				authAdminControl(source, "smtp_from", "SMTP sender", "text", "From address used for auth emails.", "Use a verified sender address from the configured mail provider.", false, ""),
				authAdminControl(source, "sms_auth_enabled", "SMS login", "toggle", "Allows SMS verification challenges when Twilio is configured.", "Requires auth routes, Twilio Verify service SID, and Twilio credentials.", false, ""),
				authAdminControl(source, "twilio_verify_service_sid", "Twilio Verify service SID", "text", "Verify service that sends SMS challenges.", "Use a VA-prefixed Twilio Verify service SID.", false, ""),
				authAdminControl(source, "twilio_account_sid", "Twilio account SID", "text", "Twilio account used with an auth token.", "Required when using twilio_auth_token instead of API key credentials.", false, ""),
				authAdminControl(source, "twilio_auth_token", "Twilio auth token", "secret", "Secret token for Twilio account authentication.", "Write-only. Leave blank to keep an existing configured value.", false, ""),
				authAdminControl(source, "twilio_api_key_sid", "Twilio API key SID", "text", "Twilio API key identifier.", "Use with twilio_api_key_secret as the preferred SMS credential pair.", false, ""),
				authAdminControl(source, "twilio_api_key_secret", "Twilio API key secret", "secret", "Secret paired with the Twilio API key SID.", "Write-only. Leave blank to keep an existing configured value.", false, ""),
				authAdminControl(source, "jwt_secret", "Challenge signing secret", "secret", "Secret used to sign email and challenge tokens.", "Write-only. Required by policy gates for email-code login.", false, ""),
			},
		},
		{
			"key":         "second_factors",
			"label":       "Second factors",
			"description": "Additional verification methods used after primary login.",
			"controls": []map[string]any{
				authAdminControl(source, "totp_auth_enabled", "Authenticator app codes", "toggle", "Enables TOTP enrollment and verification steps.", "Use recovery codes alongside TOTP for account recovery.", false, ""),
			},
		},
		{
			"key":         "oauth_providers",
			"label":       "OAuth providers",
			"description": "External identity providers available to auth routes.",
			"controls":    buildOAuthAdminControls(source),
		},
	}
	for _, group := range groups {
		groupKey, _ := group["key"].(string)
		controls, _ := group["controls"].([]map[string]any)
		for _, control := range controls {
			control["group_key"] = groupKey
		}
	}
	return groups
}

func buildOAuthAdminControls(source map[string]any) []map[string]any {
	controls := []map[string]any{
		authAdminControl(source, "auth_routes_enabled", "Auth routes", "toggle", "Enables HTTP auth routes used by OAuth callback flows.", "OAuth login requires auth routes before any provider can become login-ready.", false, ""),
	}
	for _, provider := range []struct {
		key   string
		label string
	}{
		{"google", "Google"},
		{"facebook", "Facebook"},
		{"instagram", "Instagram"},
		{"x", "X"},
	} {
		disabledReason := providerDisabledReason(source, provider.key)
		controls = append(controls,
			authAdminControl(source, provider.key+"_oauth_client_id", provider.label+" client ID", "text", "OAuth client identifier issued by "+provider.label+".", "Pair with the matching client secret and redirect URL.", false, disabledReason),
			authAdminControl(source, provider.key+"_oauth_client_secret", provider.label+" client secret", "secret", "OAuth client secret issued by "+provider.label+".", "Write-only. Leave blank to keep an existing configured value.", false, disabledReason),
		)
		if provider.key == "google" || provider.key == "facebook" {
			controls = append(controls, authAdminControl(source, provider.key+"_oauth_redirect_url", provider.label+" redirect URL", "url", "Callback URL registered with "+provider.label+".", "Must be HTTPS and match the provider application settings.", false, disabledReason))
		}
	}
	return controls
}

func authAdminControl(source map[string]any, key, label, inputType, description, helpText string, required bool, disabledReason string) map[string]any {
	return map[string]any{
		"key":             key,
		"group_key":       "",
		"label":           label,
		"description":     description,
		"help_text":       helpText,
		"input_type":      inputType,
		"config_key":      key,
		"secret":          authAdminSecretKey(key),
		"configured":      policyPresent(source, key),
		"required":        required,
		"enabled":         disabledReason == "",
		"disabled_reason": disabledReason,
		"options":         []map[string]any{},
	}
}

func authAdminWarnings(source, policy map[string]any) []map[string]any {
	var warnings []map[string]any
	if isProduction(policyString(source, "environment")) && policyInt(policy, "primary_method_count") == 0 {
		warnings = append(warnings, authAdminDiagnostic("primary_methods", "warning", "production has no enabled primary authentication methods"))
	}
	if policyStrictTrue(source, "password_auth_enabled") && !policyBool(policy, "password_enabled") {
		warnings = append(warnings, authAdminDiagnostic("password_auth_enabled", "warning", "password login was requested but is not available in this environment"))
	}
	return warnings
}

func validatePasskeyAdminConfig(source map[string]any) []map[string]any {
	var errors []map[string]any
	rpID := policyString(source, "webauthn_rp_id")
	origin := policyString(source, "webauthn_origin")
	if rpID == "" && origin == "" {
		return errors
	}
	if rpID == "" {
		errors = append(errors, authAdminDiagnostic("webauthn_rp_id", "error", "passkey login requires a relying party ID"))
	}
	if origin == "" {
		errors = append(errors, authAdminDiagnostic("webauthn_origin", "error", "passkey login requires an origin"))
	} else if !authAdminSecureOrigin(origin) {
		errors = append(errors, authAdminDiagnostic("webauthn_origin", "error", "passkey origin must use https except for localhost development"))
	}
	return errors
}

func validateOAuthAdminConfig(source map[string]any) []map[string]any {
	var errors []map[string]any
	for _, provider := range []string{"google", "facebook", "instagram", "x"} {
		if !authAdminOAuthProviderRequested(source, provider) {
			continue
		}
		if disabled := providerDisabledReason(source, provider); disabled != "" {
			errors = append(errors, authAdminDiagnostic(provider+"_oauth", "error", disabled))
			continue
		}
		if !policyAnyStrictTrue(source, "auth_routes_enabled", "routes_enabled", "oauth_routes_enabled") {
			errors = append(errors, authAdminDiagnostic("auth_routes_enabled", "error", provider+" oauth requires auth routes to be enabled"))
		}
		for _, key := range []string{provider + "_oauth_client_id", provider + "_oauth_client_secret", provider + "_oauth_redirect_url"} {
			if !policyPresent(source, key) {
				errors = append(errors, authAdminDiagnostic(key, "error", provider+" oauth requires "+key))
			}
		}
		if _, disabled := oauthProviderConfig(source, provider); disabled != "" {
			errors = append(errors, authAdminDiagnostic(provider+"_oauth", "error", disabled))
		}
	}
	return errors
}

func authAdminOAuthProviderRequested(source map[string]any, provider string) bool {
	if normalizeOAuthProvider(policyString(source, "oauth_provider")) == provider {
		return true
	}
	clientID := policyPresent(source, provider+"_oauth_client_id")
	clientSecret := policyPresent(source, provider+"_oauth_client_secret")
	redirect := policyPresent(source, provider+"_oauth_redirect_url")
	return clientID || (clientSecret && redirect) || (clientID && clientSecret)
}

func providerDisabledReason(source map[string]any, provider string) string {
	if provider == "instagram" || provider == "x" {
		_, reason := oauthProviderConfig(source, provider)
		return reason
	}
	return ""
}

func passwordAdminDisabledReason(source map[string]any) string {
	if isProduction(policyString(source, "environment")) {
		return "password auth cannot be enabled in production"
	}
	return ""
}

func authAdminNestedConfig(source map[string]any, key string) map[string]any {
	if source == nil {
		return nil
	}
	value, ok := source[key]
	if !ok || value == nil {
		return nil
	}
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[string]string:
		converted := make(map[string]any, len(typed))
		for key, value := range typed {
			converted[key] = value
		}
		return converted
	default:
		return nil
	}
}

func sanitizeAuthAdminConfig(source map[string]any) map[string]any {
	sanitized := make(map[string]any, len(source))
	for key, value := range source {
		if authAdminSecretKey(key) {
			continue
		}
		if key == "desired_config" || key == "config" || key == "require_primary_method" {
			continue
		}
		sanitized[key] = value
	}
	return sanitized
}

func authAdminSecretFields(source map[string]any) []string {
	fields := make([]string, 0)
	for key := range source {
		if authAdminSecretKey(key) && policyPresent(source, key) {
			fields = append(fields, key)
		}
	}
	sort.Strings(fields)
	return fields
}

func authAdminSecretKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(key, "secret") ||
		key == "twilio_auth_token" ||
		key == "smtp_pass" ||
		key == "jwt_secret"
}

func requirePrimaryMethod(config, current map[string]any) bool {
	if policyStrictTrue(current, "require_primary_method") {
		return true
	}
	if value, ok := current["require_primary_method"]; ok && value == false {
		return false
	}
	return policyStrictTrue(config, "require_primary_method")
}

func authAdminDiagnostic(field, severity, message string) map[string]any {
	return map[string]any{
		"field":    field,
		"severity": severity,
		"message":  message,
	}
}

func authAdminSecureOrigin(origin string) bool {
	parsed, err := url.Parse(strings.TrimSpace(origin))
	if err != nil || parsed.Host == "" {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
