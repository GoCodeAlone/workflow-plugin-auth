package internal

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
)

func TestAuthAdminIdentityDescribeExposesProfileCredentialAndInviteSurface(t *testing.T) {
	step := newAuthAdminIdentityDescribeStep("identity", map[string]any{
		"app_context": "admin",
	})

	result, err := step.Execute(context.Background(), nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatalf("describe admin identity: %v", err)
	}

	contribution, ok := result.Output["contribution"].(map[string]any)
	if !ok {
		t.Fatalf("contribution has type %T, want map[string]any", result.Output["contribution"])
	}
	for key, want := range map[string]any{
		"id":          "auth-identity",
		"title":       "Identity & Access",
		"category":    "security",
		"path":        "/api/admin/auth/identity",
		"render_mode": "identity-admin",
		"app_context": "admin",
	} {
		if got := contribution[key]; got != want {
			t.Fatalf("contribution[%s] = %v, want %v", key, got, want)
		}
	}

	actions, ok := contribution["actions"].([]string)
	if !ok {
		t.Fatalf("actions has type %T, want []string", contribution["actions"])
	}
	for _, action := range []string{"read_profile", "update_profile", "list_credentials", "issue_invite", "revoke_invite"} {
		if !slices.Contains(actions, action) {
			t.Fatalf("actions missing %q: %v", action, actions)
		}
	}

	permissions, ok := contribution["permissions"].([]map[string]any)
	if !ok {
		t.Fatalf("permissions has type %T, want []map[string]any", contribution["permissions"])
	}
	requireContributionPermission(t, permissions, "auth.profile", "read", "admin:auth.profile:read")
	requireContributionPermission(t, permissions, "auth.profile", "update", "admin:auth.profile:update")
	requireContributionPermission(t, permissions, "auth.credentials", "read", "admin:auth.credentials:read")
	requireContributionPermission(t, permissions, "auth.credentials", "update", "admin:auth.credentials:update")
	requireContributionPermission(t, permissions, "auth.invites", "create", "admin:auth.invites:create")
	requireContributionPermission(t, permissions, "auth.invites", "revoke", "admin:auth.invites:revoke")

	metadata, ok := contribution["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata has type %T, want map[string]any", contribution["metadata"])
	}
	for key, want := range map[string]string{
		"profile_path":       "/api/admin/auth/profile",
		"credentials_path":   "/api/admin/auth/credentials",
		"invite_issue_path":  "/api/admin/auth/invites",
		"invite_redeem_path": "/api/admin/auth/invites/redeem",
		"invite_revoke_path": "/api/admin/auth/invites/revoke",
		"bootstrap_path":     "/api/admin/auth/bootstrap",
	} {
		if got := metadata[key]; got != want {
			t.Fatalf("metadata[%s] = %v, want %v", key, got, want)
		}
	}
	for key, value := range metadata {
		if strings.Contains(strings.ToLower(key), "secret") || strings.Contains(strings.ToLower(key), "token") {
			t.Fatalf("metadata leaks secret/token key %q=%v", key, value)
		}
	}
}

func TestAuthAdminIdentityDescribeRedactsInviteTokens(t *testing.T) {
	step := newAuthAdminIdentityDescribeStep("identity", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"invite_token":      "plain-token",
		"invite_token_hash": "hashed-token",
		"identity": map[string]any{
			"invite_token": "nested-token",
		},
	}, nil, nil)
	if err != nil {
		t.Fatalf("describe admin identity: %v", err)
	}
	output := fmt.Sprintf("%#v", result.Output)
	for _, forbidden := range []string{"plain-token", "hashed-token", "nested-token"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("identity output leaked %q: %s", forbidden, output)
		}
	}
}

func TestAuthAdminIdentityContractsRegistered(t *testing.T) {
	plugin := &authPlugin{}
	contractsByKey := map[string]*pb.ContractDescriptor{}
	for _, contract := range plugin.ContractRegistry().Contracts {
		contractsByKey[contractKey(contract)] = contract
	}
	for _, stepType := range []string{
		"step.auth_admin_identity_describe",
		"step.auth_admin_invite_issue",
		"step.auth_admin_invite_redeem",
		"step.auth_admin_invite_revoke",
	} {
		if !slices.Contains(plugin.StepTypes(), stepType) {
			t.Fatalf("StepTypes missing %s", stepType)
		}
		if _, err := plugin.CreateStep(stepType, "test", nil); err != nil {
			t.Fatalf("CreateStep(%s): %v", stepType, err)
		}
		if _, err := plugin.CreateTypedStep(stepType, "typed", nil); err != nil {
			t.Fatalf("CreateTypedStep(%s): %v", stepType, err)
		}
	}
	requireContract(t, contractsByKey, "step:step.auth_admin_identity_describe", "workflow.plugins.auth.v1.AuthAdminIdentityContributionConfig", "workflow.plugins.auth.v1.AuthAdminIdentityDescribeInput", "workflow.plugins.auth.v1.AuthAdminIdentityDescribeOutput")
	requireContract(t, contractsByKey, "step:step.auth_admin_invite_issue", "workflow.plugins.auth.v1.AuthAdminInviteConfig", "workflow.plugins.auth.v1.AuthAdminInviteIssueInput", "workflow.plugins.auth.v1.AuthAdminInviteIssueOutput")
	requireContract(t, contractsByKey, "step:step.auth_admin_invite_redeem", "workflow.plugins.auth.v1.AuthAdminInviteConfig", "workflow.plugins.auth.v1.AuthAdminInviteRedeemInput", "workflow.plugins.auth.v1.AuthAdminInviteRedeemOutput")
	requireContract(t, contractsByKey, "step:step.auth_admin_invite_revoke", "workflow.plugins.auth.v1.AuthAdminInviteConfig", "workflow.plugins.auth.v1.AuthAdminInviteRevokeInput", "workflow.plugins.auth.v1.AuthAdminInviteRevokeOutput")
}
