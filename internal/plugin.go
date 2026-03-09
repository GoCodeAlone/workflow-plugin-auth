package internal

import (
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

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
		Version:     "0.1.0",
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
	case "step.auth_credential_list":
		return newCredentialListStep(name, config), nil
	case "step.auth_credential_revoke":
		return newCredentialRevokeStep(name, config), nil
	default:
		return nil, fmt.Errorf("unknown step type: %s", typeName)
	}
}
