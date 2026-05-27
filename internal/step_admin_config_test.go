package internal

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestAuthAdminConfigDescribeExposesRealConfigControls(t *testing.T) {
	step := newAuthAdminConfigDescribeStep("admin", map[string]any{
		"environment":                  "development",
		"password_auth_enabled":        true,
		"webauthn_rp_id":               "app.example.test",
		"webauthn_origin":              "https://app.example.test",
		"auth_routes_enabled":          true,
		"google_oauth_client_id":       "google-client",
		"google_oauth_client_secret":   "google-secret",
		"google_oauth_redirect_url":    "https://app.example.test/auth/google/callback",
		"facebook_oauth_client_id":     "facebook-client",
		"facebook_oauth_client_secret": "facebook-secret",
		"facebook_oauth_redirect_url":  "https://app.example.test/auth/facebook/callback",
	})

	result, err := step.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("describe admin config: %v", err)
	}

	requireAdminControl(t, result.Output, "webauthn_rp_id", adminControlWant{
		GroupKey:   "primary_methods",
		Label:      "Passkey relying party ID",
		InputType:  "text",
		ConfigKey:  "webauthn_rp_id",
		Secret:     false,
		Configured: true,
		Enabled:    true,
	})
	requireAdminControl(t, result.Output, "webauthn_origin", adminControlWant{
		GroupKey:   "primary_methods",
		Label:      "Passkey origin",
		InputType:  "url",
		ConfigKey:  "webauthn_origin",
		Secret:     false,
		Configured: true,
		Enabled:    true,
	})
	requireAdminControl(t, result.Output, "password_auth_enabled", adminControlWant{
		GroupKey:   "primary_methods",
		Label:      "Password login",
		InputType:  "toggle",
		ConfigKey:  "password_auth_enabled",
		Secret:     false,
		Configured: true,
		Enabled:    true,
	})
	requireAdminControl(t, result.Output, "google_oauth_client_secret", adminControlWant{
		GroupKey:   "oauth_providers",
		Label:      "Google client secret",
		InputType:  "secret",
		ConfigKey:  "google_oauth_client_secret",
		Secret:     true,
		Configured: true,
		Enabled:    true,
	})
	requireAdminControl(t, result.Output, "facebook_oauth_client_secret", adminControlWant{
		GroupKey:   "oauth_providers",
		Label:      "Facebook client secret",
		InputType:  "secret",
		ConfigKey:  "facebook_oauth_client_secret",
		Secret:     true,
		Configured: true,
		Enabled:    true,
	})
	requireAdminControl(t, result.Output, "instagram_oauth_client_secret", adminControlWant{
		GroupKey:          "oauth_providers",
		Label:             "Instagram client secret",
		InputType:         "secret",
		ConfigKey:         "instagram_oauth_client_secret",
		Secret:            true,
		Enabled:           false,
		DisabledReason:    "instagram oauth provider is disabled in this release",
		AllowUnconfigured: true,
	})
	requireAdminControl(t, result.Output, "x_oauth_client_secret", adminControlWant{
		GroupKey:          "oauth_providers",
		Label:             "X client secret",
		InputType:         "secret",
		ConfigKey:         "x_oauth_client_secret",
		Secret:            true,
		Enabled:           false,
		DisabledReason:    "x oauth provider is disabled in this release",
		AllowUnconfigured: true,
	})

	policy, ok := result.Output["methods_policy"].(map[string]any)
	if !ok {
		t.Fatalf("methods_policy has type %T, want map[string]any", result.Output["methods_policy"])
	}
	assertBool(t, policy, "passkey_enabled", true)
	assertBool(t, policy, "password_enabled", true)

	secretFields, ok := result.Output["secret_fields"].([]string)
	if !ok {
		t.Fatalf("secret_fields has type %T, want []string", result.Output["secret_fields"])
	}
	for _, secret := range []string{"google_oauth_client_secret", "facebook_oauth_client_secret"} {
		if !slices.Contains(secretFields, secret) {
			t.Fatalf("secret_fields missing %q: %v", secret, secretFields)
		}
	}
}

func TestAuthAdminConfigValidateRejectsUnsafePasswordProduction(t *testing.T) {
	step := newAuthAdminConfigValidateStep("admin", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"require_primary_method": true,
		"desired_config": map[string]any{
			"environment":           "production",
			"password_auth_enabled": true,
		},
	}, nil, nil)
	if err != nil {
		t.Fatalf("validate admin config: %v", err)
	}

	assertBool(t, result.Output, "valid", false)
	requireAdminDiagnostic(t, result.Output, "password_auth_enabled", "password auth cannot be enabled in production")
}

func TestAuthAdminConfigValidateRejectsZeroPrimaryMethods(t *testing.T) {
	step := newAuthAdminConfigValidateStep("admin", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"require_primary_method": true,
		"desired_config": map[string]any{
			"environment":           "development",
			"password_auth_enabled": false,
			"webauthn_rp_id":        "",
			"webauthn_origin":       "",
		},
	}, nil, nil)
	if err != nil {
		t.Fatalf("validate admin config: %v", err)
	}

	assertBool(t, result.Output, "valid", false)
	requireAdminDiagnostic(t, result.Output, "primary_methods", "at least one primary authentication method must be configured")
}

func TestAuthAdminConfigValidateAcceptsPasskeyPatchAndRedactsSecrets(t *testing.T) {
	step := newAuthAdminConfigValidateStep("admin", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"require_primary_method": true,
		"desired_config": map[string]any{
			"environment":                  "development",
			"webauthn_rp_id":               "app.example.test",
			"webauthn_origin":              "https://app.example.test",
			"auth_routes_enabled":          true,
			"google_oauth_client_id":       "google-client",
			"google_oauth_client_secret":   "google-secret",
			"google_oauth_redirect_url":    "https://app.example.test/auth/google/callback",
			"facebook_oauth_client_secret": "facebook-secret",
		},
	}, nil, nil)
	if err != nil {
		t.Fatalf("validate admin config: %v", err)
	}

	assertBool(t, result.Output, "valid", true)
	accepted, ok := result.Output["accepted_config"].(map[string]any)
	if !ok {
		t.Fatalf("accepted_config has type %T, want map[string]any", result.Output["accepted_config"])
	}
	if accepted["webauthn_rp_id"] != "app.example.test" {
		t.Fatalf("accepted webauthn_rp_id = %v", accepted["webauthn_rp_id"])
	}
	if _, exists := accepted["google_oauth_client_secret"]; exists {
		t.Fatal("accepted_config echoed google_oauth_client_secret")
	}
	if _, exists := accepted["facebook_oauth_client_secret"]; exists {
		t.Fatal("accepted_config echoed facebook_oauth_client_secret")
	}
	secretFields, ok := result.Output["secret_fields"].([]string)
	if !ok {
		t.Fatalf("secret_fields has type %T, want []string", result.Output["secret_fields"])
	}
	for _, secret := range []string{"google_oauth_client_secret", "facebook_oauth_client_secret"} {
		if !slices.Contains(secretFields, secret) {
			t.Fatalf("secret_fields missing %q: %v", secret, secretFields)
		}
	}

	policy, ok := result.Output["methods_policy"].(map[string]any)
	if !ok {
		t.Fatalf("methods_policy has type %T, want map[string]any", result.Output["methods_policy"])
	}
	assertBool(t, policy, "passkey_enabled", true)
}

type adminControlWant struct {
	GroupKey          string
	Label             string
	InputType         string
	ConfigKey         string
	Secret            bool
	Configured        bool
	Enabled           bool
	DisabledReason    string
	AllowUnconfigured bool
}

func requireAdminControl(t *testing.T, output map[string]any, key string, want adminControlWant) {
	t.Helper()
	control := findAdminControl(t, output, key)
	if control["group_key"] != want.GroupKey {
		t.Fatalf("%s group_key = %v, want %s", key, control["group_key"], want.GroupKey)
	}
	if control["label"] != want.Label {
		t.Fatalf("%s label = %v, want %s", key, control["label"], want.Label)
	}
	if control["input_type"] != want.InputType {
		t.Fatalf("%s input_type = %v, want %s", key, control["input_type"], want.InputType)
	}
	if control["config_key"] != want.ConfigKey {
		t.Fatalf("%s config_key = %v, want %s", key, control["config_key"], want.ConfigKey)
	}
	if control["secret"] != want.Secret {
		t.Fatalf("%s secret = %v, want %v", key, control["secret"], want.Secret)
	}
	if !want.AllowUnconfigured && control["configured"] != want.Configured {
		t.Fatalf("%s configured = %v, want %v", key, control["configured"], want.Configured)
	}
	if control["enabled"] != want.Enabled {
		t.Fatalf("%s enabled = %v, want %v", key, control["enabled"], want.Enabled)
	}
	if want.DisabledReason != "" {
		got := control["disabled_reason"]
		if got == nil || !strings.Contains(got.(string), want.DisabledReason) {
			t.Fatalf("%s disabled_reason = %v, want contains %q", key, got, want.DisabledReason)
		}
	}
	if strings.TrimSpace(control["help_text"].(string)) == "" {
		t.Fatalf("%s help_text is empty", key)
	}
}

func findAdminControl(t *testing.T, output map[string]any, key string) map[string]any {
	t.Helper()
	groups, ok := output["groups"].([]map[string]any)
	if !ok {
		t.Fatalf("groups has type %T, want []map[string]any", output["groups"])
	}
	for _, group := range groups {
		controls, ok := group["controls"].([]map[string]any)
		if !ok {
			t.Fatalf("%s controls has type %T, want []map[string]any", group["key"], group["controls"])
		}
		for _, control := range controls {
			if control["key"] == key {
				if control["group_key"] == nil {
					control["group_key"] = group["key"]
				}
				return control
			}
		}
	}
	t.Fatalf("missing admin control %q", key)
	return nil
}

func requireAdminDiagnostic(t *testing.T, output map[string]any, field, contains string) {
	t.Helper()
	diagnostics, ok := output["errors"].([]map[string]any)
	if !ok {
		t.Fatalf("errors has type %T, want []map[string]any", output["errors"])
	}
	for _, diagnostic := range diagnostics {
		if diagnostic["field"] == field && strings.Contains(diagnostic["message"].(string), contains) {
			return
		}
	}
	t.Fatalf("missing diagnostic field=%q contains=%q in %v", field, contains, diagnostics)
}
