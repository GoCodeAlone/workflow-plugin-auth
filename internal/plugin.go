package internal

import (
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// Version is set at build time via -ldflags
// "-X github.com/GoCodeAlone/workflow-plugin-auth/internal.Version=X.Y.Z"
var Version = "dev"

var allStepTypes = []string{
	"step.auth_passkey_begin_register",
	"step.auth_passkey_finish_register",
	"step.auth_passkey_begin_login",
	"step.auth_passkey_finish_login",
	"step.auth_totp_generate_secret",
	"step.auth_totp_verify",
	"step.auth_totp_recovery_codes",
	"step.auth_magic_link_generate",
	"step.auth_magic_link_verify",
	"step.auth_magic_link_send",
	"step.auth_password_hash",
	"step.auth_password_verify",
	"step.auth_challenge_generate",
	"step.auth_challenge_verify",
	"step.auth_normalize_phone",
	"step.auth_methods_policy",
	"step.auth_policy_gate",
	"step.auth_methods_response",
	"step.auth_policy_audit",
	"step.auth_oauth_provider_config",
	"step.auth_oauth_start",
	"step.auth_oauth_exchange",
	"step.auth_oauth_userinfo",
	"step.auth_credential_list",
	"step.auth_credential_revoke",
}

type authPlugin struct{}

func NewAuthPlugin() sdk.PluginProvider {
	return &authPlugin{}
}

func (p *authPlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-auth",
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "Passwordless authentication plugin: WebAuthn/passkeys, TOTP, email magic links",
	}
}

func (p *authPlugin) ModuleTypes() []string {
	return []string{"auth.credential"}
}

func (p *authPlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "auth.credential":
		return newCredentialModule(name, config)
	default:
		return nil, fmt.Errorf("unknown module type: %s", typeName)
	}
}

func (p *authPlugin) StepTypes() []string {
	return allStepTypes
}

func (p *authPlugin) CreateStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.auth_passkey_begin_register":
		return newPasskeyBeginRegisterStep(name, config), nil
	case "step.auth_passkey_finish_register":
		return newPasskeyFinishRegisterStep(name, config), nil
	case "step.auth_passkey_begin_login":
		return newPasskeyBeginLoginStep(name, config), nil
	case "step.auth_passkey_finish_login":
		return newPasskeyFinishLoginStep(name, config), nil
	case "step.auth_totp_generate_secret":
		return newTOTPGenerateSecretStep(name, config), nil
	case "step.auth_totp_verify":
		return newTOTPVerifyStep(name, config), nil
	case "step.auth_totp_recovery_codes":
		return newTOTPRecoveryCodesStep(name, config), nil
	case "step.auth_magic_link_generate":
		return newMagicLinkGenerateStep(name, config), nil
	case "step.auth_magic_link_verify":
		return newMagicLinkVerifyStep(name, config), nil
	case "step.auth_magic_link_send":
		return newMagicLinkSendStep(name, config), nil
	case "step.auth_password_hash":
		return newPasswordHashStep(name, config), nil
	case "step.auth_password_verify":
		return newPasswordVerifyStep(name, config), nil
	case "step.auth_challenge_generate":
		return newChallengeGenerateStep(name, config), nil
	case "step.auth_challenge_verify":
		return newChallengeVerifyStep(name, config), nil
	case "step.auth_normalize_phone":
		return newNormalizePhoneStep(name, config), nil
	case "step.auth_methods_policy":
		return newAuthMethodsPolicyStep(name, config), nil
	case "step.auth_policy_gate":
		return newAuthPolicyGateStep(name, config), nil
	case "step.auth_methods_response":
		return newAuthMethodsResponseStep(name, config), nil
	case "step.auth_policy_audit":
		return newAuthPolicyAuditStep(name, config), nil
	case "step.auth_oauth_provider_config":
		return newOAuthProviderConfigStep(name, config), nil
	case "step.auth_oauth_start":
		return newOAuthStartStep(name, config), nil
	case "step.auth_oauth_exchange":
		return newOAuthExchangeStep(name, config), nil
	case "step.auth_oauth_userinfo":
		return newOAuthUserinfoStep(name, config), nil
	case "step.auth_credential_list":
		return newCredentialListStep(name, config), nil
	case "step.auth_credential_revoke":
		return newCredentialRevokeStep(name, config), nil
	default:
		return nil, fmt.Errorf("unknown step type: %s", typeName)
	}
}
