package internal

import (
	"context"
	"slices"
	"testing"
)

func TestAuthMethodsPolicy(t *testing.T) {
	t.Run("production disables password auth even when requested", func(t *testing.T) {
		output := executeMethodsPolicy(t, map[string]any{
			"environment":           "production",
			"password_auth_enabled": true,
		})

		assertBool(t, output, "password_enabled", false)
		assertBool(t, output, "password_auth_enabled", false)
	})

	t.Run("development enables password auth when explicitly configured", func(t *testing.T) {
		output := executeMethodsPolicy(t, map[string]any{
			"environment":           "development",
			"password_auth_enabled": true,
		})

		assertBool(t, output, "password_enabled", true)
		assertBool(t, output, "password_auth_enabled", true)
	})

	t.Run("passkey requires relying party id and origin", func(t *testing.T) {
		missingOrigin := executeMethodsPolicy(t, map[string]any{
			"webauthn_rp_id": "example.com",
		})
		assertBool(t, missingOrigin, "passkey_enabled", false)

		ready := executeMethodsPolicy(t, map[string]any{
			"webauthn_rp_id":  "example.com",
			"webauthn_origin": "https://example.com",
		})
		assertBool(t, ready, "passkey_enabled", true)
	})

	t.Run("email code requires smtp host and sender", func(t *testing.T) {
		missingSender := executeMethodsPolicy(t, map[string]any{
			"smtp_host": "smtp.example.com",
		})
		assertBool(t, missingSender, "email_code_enabled", false)

		ready := executeMethodsPolicy(t, map[string]any{
			"smtp_host": "smtp.example.com",
			"smtp_from": "noreply@example.com",
		})
		assertBool(t, ready, "email_code_enabled", true)
	})

	t.Run("sms code requires routes enabled, sms enabled, verify service, and credentials", func(t *testing.T) {
		missingCredentials := executeMethodsPolicy(t, map[string]any{
			"auth_routes_enabled":       true,
			"sms_auth_enabled":          true,
			"twilio_verify_service_sid": "VA123",
		})
		assertBool(t, missingCredentials, "sms_code_enabled", false)

		withAuthToken := executeMethodsPolicy(t, map[string]any{
			"auth_routes_enabled":       true,
			"sms_auth_enabled":          true,
			"twilio_verify_service_sid": "VA123",
			"twilio_auth_token":         "token",
		})
		assertBool(t, withAuthToken, "sms_code_enabled", true)

		withAPIKey := executeMethodsPolicy(t, map[string]any{
			"auth_routes_enabled":       true,
			"sms_auth_enabled":          true,
			"twilio_verify_service_sid": "VA123",
			"twilio_api_key_sid":        "SK123",
			"twilio_api_key_secret":     "secret",
		})
		assertBool(t, withAPIKey, "sms_code_enabled", true)

		withGenericNames := executeMethodsPolicy(t, map[string]any{
			"routes_enabled":            true,
			"sms_enabled":               true,
			"twilio_verify_service_sid": "VA123",
			"twilio_auth_token":         "token",
		})
		assertBool(t, withGenericNames, "sms_code_enabled", true)
	})

	t.Run("totp is enabled only by strict true", func(t *testing.T) {
		defaulted := executeMethodsPolicy(t, map[string]any{})
		assertBool(t, defaulted, "totp_enabled", false)

		looseTruthy := executeMethodsPolicy(t, map[string]any{
			"totp_auth_enabled": "1",
		})
		assertBool(t, looseTruthy, "totp_enabled", false)

		ready := executeMethodsPolicy(t, map[string]any{
			"totp_auth_enabled": "true",
		})
		assertBool(t, ready, "totp_enabled", true)
	})

	t.Run("oauth providers include google only when complete and routes enabled", func(t *testing.T) {
		incomplete := executeMethodsPolicy(t, map[string]any{
			"auth_routes_enabled":         true,
			"google_oauth_client_id":      "client-id",
			"google_oauth_client_secret":  "client-secret",
			"google_oauth_redirect_url":   "",
			"google_oauth_extra_ignored":  "ignored",
			"unsupported_oauth_client_id": "ignored",
		})
		assertProviders(t, incomplete, nil)

		ready := executeMethodsPolicy(t, map[string]any{
			"auth_routes_enabled":        true,
			"google_oauth_client_id":     "client-id",
			"google_oauth_client_secret": "client-secret",
			"google_oauth_redirect_url":  "https://example.com/auth/google/callback",
		})
		assertProviders(t, ready, []string{"google"})
	})

	t.Run("disabled oauth provider metadata is not login ready", func(t *testing.T) {
		output := executeMethodsPolicy(t, map[string]any{
			"oauth_provider":               "facebook",
			"auth_routes_enabled":          true,
			"facebook_oauth_client_id":     "client-id",
			"facebook_oauth_client_secret": "client-secret",
			"facebook_oauth_redirect_url":  "https://example.com/auth/facebook/callback",
		})

		assertProviders(t, output, nil)
	})

	t.Run("templated values are absent", func(t *testing.T) {
		output := executeMethodsPolicy(t, map[string]any{
			"webauthn_rp_id":             "{{ config \"webauthn_rp_id\" }}",
			"webauthn_origin":            "https://example.com",
			"smtp_host":                  "smtp.example.com",
			"smtp_from":                  "{{ config \"smtp_from\" }}",
			"auth_routes_enabled":        true,
			"sms_auth_enabled":           true,
			"twilio_verify_service_sid":  "{{ config \"twilio_verify_service_sid\" }}",
			"twilio_auth_token":          "token",
			"google_oauth_client_id":     "client-id",
			"google_oauth_client_secret": "{{ config \"google_oauth_client_secret\" }}",
			"google_oauth_redirect_url":  "https://example.com/auth/google/callback",
		})

		assertBool(t, output, "passkey_enabled", false)
		assertBool(t, output, "email_code_enabled", false)
		assertBool(t, output, "sms_code_enabled", false)
		assertProviders(t, output, nil)
	})

	t.Run("primary method count tracks enabled primary methods", func(t *testing.T) {
		output := executeMethodsPolicy(t, map[string]any{
			"environment":                "development",
			"password_auth_enabled":      true,
			"webauthn_rp_id":             "example.com",
			"webauthn_origin":            "https://example.com",
			"smtp_host":                  "smtp.example.com",
			"smtp_from":                  "noreply@example.com",
			"auth_routes_enabled":        true,
			"google_oauth_client_id":     "client-id",
			"google_oauth_client_secret": "client-secret",
			"google_oauth_redirect_url":  "https://example.com/auth/google/callback",
			"totp_auth_enabled":          true,
			"sms_auth_enabled":           true,
			"twilio_verify_service_sid":  "VA123",
			"twilio_api_key_sid":         "SK123",
			"twilio_api_key_secret":      "secret",
		})

		if got := output["primary_method_count"]; got != 5 {
			t.Fatalf("primary_method_count = %v, want 5", got)
		}
	})
}

func TestAuthMethodsResponse(t *testing.T) {
	policy := executeMethodsPolicy(t, map[string]any{
		"webauthn_rp_id":             "example.com",
		"webauthn_origin":            "https://example.com",
		"smtp_host":                  "smtp.example.com",
		"smtp_from":                  "noreply@example.com",
		"auth_routes_enabled":        true,
		"google_oauth_client_id":     "client-id",
		"google_oauth_client_secret": "client-secret",
		"google_oauth_redirect_url":  "https://example.com/auth/google/callback",
	})

	step := newAuthMethodsResponseStep("response", nil)
	result, err := step.Execute(context.Background(), nil, nil, policy, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertBool(t, result.Output, "passkey_enabled", true)
	assertBool(t, result.Output, "email_code_enabled", true)
	assertBool(t, result.Output, "password_enabled", false)
	assertProviders(t, result.Output, []string{"google"})

	methods, ok := result.Output["methods"].([]string)
	if !ok {
		t.Fatalf("methods has type %T, want []string", result.Output["methods"])
	}
	if !slices.Equal(methods, []string{"passkey", "email_code", "oauth_google"}) {
		t.Fatalf("methods = %v, want passkey/email_code/oauth_google", methods)
	}
}

func TestAuthPolicyAudit(t *testing.T) {
	t.Run("production password auth request fails", func(t *testing.T) {
		output := executePolicyAudit(t, map[string]any{
			"environment":           "production",
			"password_auth_enabled": true,
		})

		assertBool(t, output, "passed", false)
		assertViolations(t, output, "password auth cannot be enabled in production")
	})

	t.Run("production password hashes fail", func(t *testing.T) {
		output := executePolicyAudit(t, map[string]any{
			"environment":         "production",
			"password_hash_count": 1,
		})

		assertBool(t, output, "passed", false)
		assertViolations(t, output, "production contains password hashes")
	})

	t.Run("development password auth request passes", func(t *testing.T) {
		output := executePolicyAudit(t, map[string]any{
			"environment":           "development",
			"password_auth_enabled": true,
			"password_hash_count":   3,
		})

		assertBool(t, output, "passed", true)
		assertViolations(t, output)
	})
}

func executeMethodsPolicy(t *testing.T, current map[string]any) map[string]any {
	t.Helper()
	step := newAuthMethodsPolicyStep("policy", nil)
	result, err := step.Execute(context.Background(), nil, nil, current, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return result.Output
}

func executePolicyAudit(t *testing.T, current map[string]any) map[string]any {
	t.Helper()
	step := newAuthPolicyAuditStep("audit", nil)
	result, err := step.Execute(context.Background(), nil, nil, current, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return result.Output
}

func assertBool(t *testing.T, output map[string]any, key string, want bool) {
	t.Helper()
	got, ok := output[key].(bool)
	if !ok {
		t.Fatalf("%s has type %T, want bool", key, output[key])
	}
	if got != want {
		t.Fatalf("%s = %v, want %v", key, got, want)
	}
}

func assertProviders(t *testing.T, output map[string]any, want []string) {
	t.Helper()
	got, ok := output["oauth_providers"].([]string)
	if !ok {
		t.Fatalf("oauth_providers has type %T, want []string", output["oauth_providers"])
	}
	if !slices.Equal(got, want) {
		t.Fatalf("oauth_providers = %v, want %v", got, want)
	}
}

func assertViolations(t *testing.T, output map[string]any, want ...string) {
	t.Helper()
	got, ok := output["violations"].([]string)
	if !ok {
		t.Fatalf("violations has type %T, want []string", output["violations"])
	}
	if !slices.Equal(got, want) {
		t.Fatalf("violations = %v, want %v", got, want)
	}
}
