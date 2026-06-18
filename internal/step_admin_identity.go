package internal

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
	"time"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type authAdminIdentityDescribeStep struct {
	name   string
	config map[string]any
}

func newAuthAdminIdentityDescribeStep(name string, config map[string]any) *authAdminIdentityDescribeStep {
	return &authAdminIdentityDescribeStep{name: name, config: config}
}

func (s *authAdminIdentityDescribeStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, runtimeConfig map[string]any) (*sdk.StepResult, error) {
	source := mergePolicyInputs(defaultAuthAdminIdentityContribution(), s.config, runtimeConfig, authAdminNestedConfig(current, "identity"), authAdminNestedConfig(current, "contribution"), current)
	contribution := map[string]any{
		"id":          contributionString(source, "id", "auth-identity"),
		"title":       contributionString(source, "title", "Identity & Access"),
		"category":    contributionString(source, "category", "security"),
		"path":        contributionString(source, "path", "/api/admin/auth/identity"),
		"render_mode": contributionString(source, "render_mode", "identity-admin"),
		"app_context": contributionString(source, "app_context", "admin"),
		"permissions": contributionPermissionsWithDefault(source["permissions"], defaultAuthAdminIdentityContribution()["permissions"].([]map[string]any)),
		"actions":     contributionActionsWithDefault(source["actions"], defaultAuthAdminIdentityContribution()["actions"].([]string)),
		"metadata":    identityContributionMetadata(source["metadata"]),
	}
	return &sdk.StepResult{Output: map[string]any{"contribution": contribution}}, nil
}

func defaultAuthAdminIdentityContribution() map[string]any {
	return map[string]any{
		"id":          "auth-identity",
		"title":       "Identity & Access",
		"category":    "security",
		"path":        "/api/admin/auth/identity",
		"render_mode": "identity-admin",
		"app_context": "admin",
		"permissions": []map[string]any{
			{"resource": "auth.profile", "action": "read", "permission": "admin:auth.profile:read"},
			{"resource": "auth.profile", "action": "update", "permission": "admin:auth.profile:update"},
			{"resource": "auth.credentials", "action": "read", "permission": "admin:auth.credentials:read"},
			{"resource": "auth.credentials", "action": "update", "permission": "admin:auth.credentials:update"},
			{"resource": "auth.invites", "action": "create", "permission": "admin:auth.invites:create"},
			{"resource": "auth.invites", "action": "revoke", "permission": "admin:auth.invites:revoke"},
		},
		"actions": []string{"read_profile", "update_profile", "list_credentials", "issue_invite", "revoke_invite"},
		"metadata": map[string]any{
			"profile_path":       "/api/admin/auth/profile",
			"credentials_path":   "/api/admin/auth/credentials",
			"invite_issue_path":  "/api/admin/auth/invites",
			"invite_redeem_path": "/api/admin/auth/invites/redeem",
			"invite_revoke_path": "/api/admin/auth/invites/revoke",
			"bootstrap_path":     "/api/admin/auth/bootstrap",
		},
	}
}

func contributionPermissionsWithDefault(value any, fallback []map[string]any) []map[string]any {
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
	return cloneContributionPermissions(fallback)
}

func contributionActionsWithDefault(value any, fallback []string) []string {
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
		if len(out) > 0 {
			return out
		}
	}
	return append([]string(nil), fallback...)
}

func identityContributionMetadata(value any) map[string]any {
	fallback := defaultAuthAdminIdentityContribution()["metadata"].(map[string]any)
	source := fallback
	switch metadata := value.(type) {
	case map[string]any:
		source = metadata
	case map[any]any:
		converted := make(map[string]any, len(metadata))
		for key, item := range metadata {
			if s, ok := key.(string); ok {
				converted[s] = item
			}
		}
		source = converted
	}
	out := make(map[string]any, len(source))
	for key, item := range source {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "secret") || strings.Contains(lower, "token") {
			continue
		}
		out[key] = item
	}
	if len(out) == 0 {
		for key, item := range fallback {
			out[key] = item
		}
	}
	return out
}

type authAdminInviteIssueStep struct {
	name   string
	config map[string]any
}

func newAuthAdminInviteIssueStep(name string, config map[string]any) *authAdminInviteIssueStep {
	return &authAdminInviteIssueStep{name: name, config: config}
}

func (s *authAdminInviteIssueStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	email := normalizeIdentityEmail(policyString(current, "email"))
	role := policyString(current, "role")
	if role == "" {
		role = "tenant_editor"
	}
	tenantIDs := policyStringSlice(current, "tenant_ids")
	out := map[string]any{
		"accepted":   email != "",
		"email":      email,
		"role":       role,
		"tenant_ids": tenantIDs,
		"invited_by": policyString(current, "invited_by"),
		"expires_at": policyString(current, "expires_at"),
	}
	switch {
	case email == "":
		out["error"] = "missing_email"
		out["accepted"] = false
	case !identityValueAllowed(role, policyStringSlice(s.config, "allowed_roles")):
		out["error"] = "invalid_role"
		out["accepted"] = false
	case !identityValuesAllowed(tenantIDs, policyStringSlice(s.config, "allowed_tenant_ids")):
		out["error"] = "invalid_tenant"
		out["accepted"] = false
	}
	return &sdk.StepResult{Output: out}, nil
}

type authAdminInviteRedeemStep struct {
	name   string
	config map[string]any
}

func newAuthAdminInviteRedeemStep(name string, config map[string]any) *authAdminInviteRedeemStep {
	return &authAdminInviteRedeemStep{name: name, config: config}
}

func (s *authAdminInviteRedeemStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	email := normalizeIdentityEmail(policyString(current, "email"))
	targetEmail := normalizeIdentityEmail(policyString(current, "target_email"))
	if targetEmail == "" {
		targetEmail = normalizeIdentityEmail(policyString(current, "invite_email"))
	}
	role := policyString(current, "role")
	tenantIDs := policyStringSlice(current, "tenant_ids")
	reason := authAdminInviteRedeemReason(current, email, targetEmail, role, tenantIDs, s.config)
	accepted := reason == "accepted"
	out := map[string]any{
		"accepted":   accepted,
		"email":      email,
		"role":       role,
		"tenant_ids": tenantIDs,
		"reason":     reason,
	}
	return &sdk.StepResult{Output: out}, nil
}

type authAdminInviteRevokeStep struct {
	name   string
	config map[string]any
}

func newAuthAdminInviteRevokeStep(name string, config map[string]any) *authAdminInviteRevokeStep {
	return &authAdminInviteRevokeStep{name: name, config: config}
}

func (s *authAdminInviteRevokeStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	inviteID := strings.TrimSpace(policyString(current, "invite_id"))
	email := normalizeIdentityEmail(policyString(current, "email"))
	accepted := inviteID != "" || email != ""
	out := map[string]any{
		"accepted":   accepted,
		"invite_id":  inviteID,
		"email":      email,
		"revoked_by": policyString(current, "revoked_by"),
	}
	if !accepted {
		out["reason"] = "missing_invite"
	} else {
		out["reason"] = "accepted"
	}
	return &sdk.StepResult{Output: out}, nil
}

func normalizeIdentityEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func authAdminInviteRedeemReason(current map[string]any, email, targetEmail, role string, tenantIDs []string, config map[string]any) string {
	switch {
	case email == "":
		return "missing_email"
	case targetEmail != "" && email != targetEmail:
		return "wrong_email"
	case policyString(current, "used_at") != "":
		return "already_used"
	case inviteExpired(policyString(current, "expires_at")):
		return "expired"
	case !inviteTokenHashValid(policyString(current, "token"), policyString(current, "token_hash")):
		return "invalid_token"
	case !identityValueAllowed(role, policyStringSlice(config, "allowed_roles")):
		return "invalid_role"
	case !identityValuesAllowed(tenantIDs, policyStringSlice(config, "allowed_tenant_ids")):
		return "invalid_tenant"
	default:
		return "accepted"
	}
}

func inviteExpired(expiresAt string) bool {
	if strings.TrimSpace(expiresAt) == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(expiresAt))
	if err != nil {
		return true
	}
	return time.Now().After(t)
}

func inviteTokenHashValid(token, tokenHash string) bool {
	token = strings.TrimSpace(token)
	tokenHash = strings.TrimSpace(tokenHash)
	if token == "" || tokenHash == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	expected := hex.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(expected), []byte(tokenHash)) == 1
}

func identityValueAllowed(value string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	value = strings.TrimSpace(value)
	for _, candidate := range allowed {
		if strings.TrimSpace(candidate) == value {
			return true
		}
	}
	return false
}

func identityValuesAllowed(values, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, value := range allowed {
		value = strings.TrimSpace(value)
		if value != "" {
			allowedSet[value] = struct{}{}
		}
	}
	for _, value := range values {
		if _, ok := allowedSet[strings.TrimSpace(value)]; !ok {
			return false
		}
	}
	return true
}
