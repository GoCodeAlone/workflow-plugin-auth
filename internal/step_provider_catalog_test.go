package internal

import (
	"context"
	"slices"
	"testing"
)

func TestAuthProviderCatalogMergesAndDeduplicatesDescriptors(t *testing.T) {
	step := newAuthProviderCatalogStep("catalog", map[string]any{
		"providers": []any{
			testOAuthProviderDescriptor("auth0", "Auth0", true, "", "auth0_oauth_client_id"),
			testOAuthProviderDescriptor("auth0", "Auth0 duplicate", true, "", "auth0_oauth_client_id"),
			testOAuthProviderDescriptor("entra", "Microsoft Entra ID", true, "", "entra_oauth_client_id"),
		},
	})

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"providers": []any{
			testOAuthProviderDescriptor("okta", "Okta", true, "", "okta_oauth_client_id"),
		},
	}, nil, nil)
	if err != nil {
		t.Fatalf("catalog execute: %v", err)
	}

	providers := authProviderDescriptors(map[string]any{"providers": result.Output["providers"]})
	if got := len(providers); got != 3 {
		t.Fatalf("provider count = %d, want 3: %#v", got, result.Output["providers"])
	}
	if !slices.Contains(providerIDs(providers), "auth0") ||
		!slices.Contains(providerIDs(providers), "entra") ||
		!slices.Contains(providerIDs(providers), "okta") {
		t.Fatalf("provider ids = %v", providerIDs(providers))
	}
	warnings, _ := result.Output["warnings"].([]map[string]any)
	if len(warnings) == 0 {
		t.Fatal("expected duplicate provider warning")
	}
}

func TestAuthAdminConfigDescribeUsesProviderDescriptors(t *testing.T) {
	step := newAuthAdminConfigDescribeStep("admin", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"config": map[string]any{
			"auth_routes_enabled":        true,
			"auth0_oauth_client_id":      "auth0-client",
			"auth0_oauth_client_secret":  "auth0-secret",
			"auth0_oauth_redirect_url":   "https://app.example.test/auth/auth0/callback",
			"entra_oauth_client_id":      "entra-client",
			"entra_oauth_client_secret":  "entra-secret",
			"entra_oauth_redirect_url":   "https://app.example.test/auth/entra/callback",
			"google_oauth_client_id":     "google-client",
			"google_oauth_client_secret": "google-secret",
			"google_oauth_redirect_url":  "https://app.example.test/auth/google/callback",
		},
		"providers": []any{
			testOAuthProviderDescriptor("auth0", "Auth0", true, "", "auth0_oauth_client_id"),
			testOAuthProviderDescriptor("entra", "Microsoft Entra ID", true, "", "entra_oauth_client_id"),
		},
	}, nil, nil)
	if err != nil {
		t.Fatalf("describe: %v", err)
	}

	requireAdminControl(t, result.Output, "auth0_oauth_client_secret", adminControlWant{
		GroupKey:   "oauth_providers",
		Label:      "Auth0 client secret",
		InputType:  "secret",
		ConfigKey:  "auth0_oauth_client_secret",
		Secret:     true,
		Configured: true,
		Enabled:    true,
	})
	requireAdminControl(t, result.Output, "entra_oauth_client_secret", adminControlWant{
		GroupKey:   "oauth_providers",
		Label:      "Microsoft Entra ID client secret",
		InputType:  "secret",
		ConfigKey:  "entra_oauth_client_secret",
		Secret:     true,
		Configured: true,
		Enabled:    true,
	})
	if adminControlExists(t, result.Output, "google_oauth_client_secret") {
		t.Fatal("google fallback control rendered despite descriptor catalog")
	}
}

func TestAuthAdminConfigValidateRejectsDisabledProviderDescriptor(t *testing.T) {
	step := newAuthAdminConfigValidateStep("admin", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"require_primary_method": true,
		"desired_config": map[string]any{
			"environment":                  "development",
			"auth_routes_enabled":          true,
			"auth0_oauth_client_id":        "auth0-client",
			"auth0_oauth_client_secret":    "auth0-secret",
			"auth0_oauth_redirect_url":     "https://app.example.test/auth/auth0/callback",
			"disabled_oauth_client_id":     "disabled-client",
			"disabled_oauth_client_secret": "disabled-secret",
			"disabled_oauth_redirect_url":  "https://app.example.test/auth/disabled/callback",
		},
		"providers": []any{
			testOAuthProviderDescriptor("auth0", "Auth0", true, "", "auth0_oauth_client_id"),
			testOAuthProviderDescriptor("disabled", "Disabled Provider", false, "provider is not enabled", "disabled_oauth_client_id"),
		},
	}, nil, nil)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	assertBool(t, result.Output, "valid", false)
	requireAdminDiagnostic(t, result.Output, "disabled_oauth", "provider is not enabled")
}

func TestAuthAdminConfigValidateDefaultsMissingSupportedToDisabled(t *testing.T) {
	step := newAuthAdminConfigValidateStep("admin", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"require_primary_method": true,
		"desired_config": map[string]any{
			"environment":                 "development",
			"auth_routes_enabled":         true,
			"auth0_oauth_client_id":       "auth0-client",
			"auth0_oauth_client_secret":   "auth0-secret",
			"auth0_oauth_redirect_url":    "https://app.example.test/auth/auth0/callback",
			"missing_oauth_client_id":     "missing-client",
			"missing_oauth_client_secret": "missing-secret",
			"missing_oauth_redirect_url":  "https://app.example.test/auth/missing/callback",
		},
		"providers": []any{
			testOAuthProviderDescriptor("auth0", "Auth0", true, "", "auth0_oauth_client_id"),
			testOAuthProviderDescriptorWithoutSupported("missing", "Missing Supported"),
		},
	}, nil, nil)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}

	assertBool(t, result.Output, "valid", false)
	requireAdminDiagnostic(t, result.Output, "missing_oauth", "provider is not enabled")
}

func testOAuthProviderDescriptor(id, label string, supported bool, disabledReason, firstField string) map[string]any {
	prefix := id + "_oauth_"
	return map[string]any{
		"id":          id,
		"label":       label,
		"categories":  []any{"oauth2_oidc"},
		"description": label + " OIDC provider",
		"capabilities": []any{
			map[string]any{
				"key":             id + "_oidc_login",
				"label":           label + " OIDC login",
				"category":        "oauth2_oidc",
				"supported":       supported,
				"disabled_reason": disabledReason,
				"config_fields": []any{
					map[string]any{"key": firstField, "label": label + " client ID", "input_type": "text", "required": true},
					map[string]any{"key": prefix + "client_secret", "label": label + " client secret", "input_type": "secret", "secret": true, "required": true},
					map[string]any{"key": prefix + "redirect_url", "label": label + " redirect URL", "input_type": "url", "required": true},
				},
			},
		},
	}
}

func testOAuthProviderDescriptorWithoutSupported(id, label string) map[string]any {
	prefix := id + "_oauth_"
	return map[string]any{
		"id":         id,
		"label":      label,
		"categories": []any{"oauth2_oidc"},
		"capabilities": []any{
			map[string]any{
				"key":      id + "_oidc_login",
				"label":    label + " OIDC login",
				"category": "oauth2_oidc",
				"config_fields": []any{
					map[string]any{"key": prefix + "client_id", "label": label + " client ID", "input_type": "text", "required": true},
					map[string]any{"key": prefix + "client_secret", "label": label + " client secret", "input_type": "secret", "secret": true, "required": true},
					map[string]any{"key": prefix + "redirect_url", "label": label + " redirect URL", "input_type": "url", "required": true},
				},
			},
		},
	}
}

func providerIDs(providers []authProviderDescriptor) []string {
	ids := make([]string, 0, len(providers))
	for _, provider := range providers {
		ids = append(ids, provider.ID)
	}
	return ids
}

func adminControlExists(t *testing.T, output map[string]any, key string) bool {
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
				return true
			}
		}
	}
	return false
}
