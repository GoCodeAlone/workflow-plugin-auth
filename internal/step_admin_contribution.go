package internal

import (
	"context"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type authAdminContributionDescribeStep struct {
	name   string
	config map[string]any
}

func newAuthAdminContributionDescribeStep(name string, config map[string]any) *authAdminContributionDescribeStep {
	return &authAdminContributionDescribeStep{name: name, config: config}
}

func (s *authAdminContributionDescribeStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, runtimeConfig map[string]any) (*sdk.StepResult, error) {
	source := mergePolicyInputs(defaultAuthAdminContribution(), s.config, runtimeConfig, authAdminNestedConfig(current, "contribution"), current)
	contribution := map[string]any{
		"id":          contributionString(source, "id", "auth-config"),
		"title":       contributionString(source, "title", "Authentication"),
		"category":    contributionString(source, "category", "security"),
		"path":        contributionString(source, "path", "/admin/auth/"),
		"render_mode": contributionString(source, "render_mode", "iframe"),
		"app_context": contributionString(source, "app_context", "admin"),
		"permissions": contributionPermissions(source["permissions"]),
		"actions":     contributionActions(source["actions"]),
	}
	return &sdk.StepResult{Output: map[string]any{"contribution": contribution}}, nil
}

func defaultAuthAdminContribution() map[string]any {
	return map[string]any{
		"id":          "auth-config",
		"title":       "Authentication",
		"category":    "security",
		"path":        "/admin/auth/",
		"render_mode": "iframe",
		"app_context": "admin",
		"permissions": []map[string]any{
			{"resource": "auth.config", "action": "read", "permission": "admin:auth.config:read"},
			{"resource": "auth.config", "action": "update", "permission": "admin:auth.config:update"},
		},
		"actions": []string{"read", "update"},
	}
}

func contributionString(source map[string]any, key, fallback string) string {
	if value := policyString(source, key); value != "" {
		return value
	}
	return fallback
}

func contributionActions(value any) []string {
	switch actions := value.(type) {
	case []string:
		return append([]string(nil), actions...)
	case []any:
		out := make([]string, 0, len(actions))
		for _, item := range actions {
			if value, ok := item.(string); ok && value != "" {
				out = append(out, value)
			}
		}
		return out
	default:
		return []string{"read", "update"}
	}
}

func contributionPermissions(value any) []map[string]any {
	switch permissions := value.(type) {
	case []map[string]any:
		return cloneContributionPermissions(permissions)
	case []any:
		out := make([]map[string]any, 0, len(permissions))
		for _, item := range permissions {
			if permission, ok := item.(map[string]any); ok {
				out = append(out, map[string]any{
					"resource":   policyString(permission, "resource"),
					"action":     policyString(permission, "action"),
					"permission": policyString(permission, "permission"),
				})
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return cloneContributionPermissions(defaultAuthAdminContribution()["permissions"].([]map[string]any))
}

func cloneContributionPermissions(permissions []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(permissions))
	for _, permission := range permissions {
		out = append(out, map[string]any{
			"resource":   policyString(permission, "resource"),
			"action":     policyString(permission, "action"),
			"permission": policyString(permission, "permission"),
		})
	}
	return out
}
