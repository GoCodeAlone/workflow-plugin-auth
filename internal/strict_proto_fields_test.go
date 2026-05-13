package internal

import (
	"context"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-auth/internal/contracts"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/anypb"
)

// TestAuthMethodsPolicyConfig_AcceptsNewBMWFields ensures the typed
// AuthMethodsPolicyConfig accepts every field BMW supplies (closing the gap
// surfaced by BMW local smoke against workflow v0.51.5).
func TestAuthMethodsPolicyConfig_AcceptsNewBMWFields(t *testing.T) {
	cfg := &contracts.AuthMethodsPolicyConfig{
		Environment:                "development",
		JwtSecret:                  "secret",
		SmsAuthEnabled:             protoBool(true),
		FacebookOauthClientId:      "fb-client",
		FacebookOauthClientSecret:  "fb-secret",
		InstagramOauthClientId:     "ig-client",
		InstagramOauthClientSecret: "ig-secret",
		XOauthClientId:             "x-client",
		XOauthClientSecret:         "x-secret",
	}
	packed, err := anypb.New(cfg)
	if err != nil {
		t.Fatalf("pack config: %v", err)
	}
	provider := NewAuthPlugin().(interface {
		CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error)
	})
	if _, err := provider.CreateTypedStep("step.auth_methods_policy", "policy", packed); err != nil {
		t.Fatalf("CreateTypedStep rejected new BMW fields: %v", err)
	}
}

// TestAuthMethodsPolicy_SmsAuthEnabledTogglesSMS verifies the new
// sms_auth_enabled config field reaches the SMS readiness predicate.
func TestAuthMethodsPolicy_SmsAuthEnabledTogglesSMS(t *testing.T) {
	output := executeMethodsPolicy(t, map[string]any{
		"auth_routes_enabled":       true,
		"sms_auth_enabled":          true,
		"twilio_verify_service_sid": "VA123",
		"twilio_account_sid":        "AC123",
		"twilio_auth_token":         "token",
	})
	assertBool(t, output, "sms_code_enabled", true)
}

// TestAuthPolicyGateConfig_AcceptsTenantID ensures BMW's tenant_id config
// supplied to step.auth_policy_gate passes strict-proto validation.
func TestAuthPolicyGateConfig_AcceptsTenantID(t *testing.T) {
	cfg := &contracts.AuthPolicyGateConfig{
		PolicyStep:          "policy",
		RequiredRuntimeKeys: []string{"tenant_id"},
		TenantId:            "tenant-123",
	}
	packed, err := anypb.New(cfg)
	if err != nil {
		t.Fatalf("pack config: %v", err)
	}
	provider := NewAuthPlugin().(interface {
		CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error)
	})
	if _, err := provider.CreateTypedStep("step.auth_policy_gate", "gate", packed); err != nil {
		t.Fatalf("CreateTypedStep rejected tenant_id: %v", err)
	}
}

// TestAuthChallengeVerifyConfig_AcceptsSigningSecret ensures the new
// AuthChallengeVerifyConfig accepts BMW's signing_secret config field.
func TestAuthChallengeVerifyConfig_AcceptsSigningSecret(t *testing.T) {
	cfg := &contracts.AuthChallengeVerifyConfig{SigningSecret: "secret"}
	packed, err := anypb.New(cfg)
	if err != nil {
		t.Fatalf("pack config: %v", err)
	}
	provider := NewAuthPlugin().(interface {
		CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error)
	})
	if _, err := provider.CreateTypedStep("step.auth_challenge_verify", "verify", packed); err != nil {
		t.Fatalf("CreateTypedStep rejected signing_secret config: %v", err)
	}
}

// TestChallengeVerify_FallsBackToConfigSigningSecret ensures signing_secret
// supplied via config (not input) is honored by the handler.
func TestChallengeVerify_FallsBackToConfigSigningSecret(t *testing.T) {
	gen := newChallengeGenerateStep("generate", nil)
	genResult, err := gen.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"destination":    "user@example.com",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "shared-secret",
	}, nil, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	code, _ := genResult.Output["code"].(string)
	codeHash, _ := genResult.Output["code_hash"].(string)

	verify := newChallengeVerifyStep("verify", map[string]any{
		"signing_secret": "shared-secret",
	})
	verifyResult, err := verify.Execute(context.Background(), nil, nil, map[string]any{
		"channel":     "email",
		"destination": "user@example.com",
		"tenant_id":   "tenant-123",
		"purpose":     "login",
		"code":        code,
		"code_hash":   codeHash,
	}, nil, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got, _ := verifyResult.Output["valid"].(bool); !got {
		t.Fatalf("expected valid=true when signing_secret only supplied via config, got %#v", verifyResult.Output)
	}
}
