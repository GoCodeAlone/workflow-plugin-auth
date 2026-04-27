package internal

import (
	"fmt"

	"github.com/GoCodeAlone/workflow-plugin-auth/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
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

func (p *authPlugin) TypedModuleTypes() []string {
	return p.ModuleTypes()
}

func (p *authPlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "auth.credential":
		return newCredentialModule(name, config)
	default:
		return nil, fmt.Errorf("unknown module type: %s", typeName)
	}
}

func (p *authPlugin) CreateTypedModule(typeName, name string, config *anypb.Any) (sdk.ModuleInstance, error) {
	if typeName != "auth.credential" {
		return nil, fmt.Errorf("unknown typed module type: %s", typeName)
	}
	factory := sdk.NewTypedModuleFactory(typeName, &contracts.CredentialModuleConfig{}, func(name string, cfg *contracts.CredentialModuleConfig) (sdk.ModuleInstance, error) {
		configMap, err := protoMessageToMap(cfg)
		if err != nil {
			return nil, err
		}
		return newCredentialModule(name, configMap)
	})
	return factory.CreateTypedModule(typeName, name, config)
}

func (p *authPlugin) StepTypes() []string {
	return allStepTypes
}

func (p *authPlugin) TypedStepTypes() []string {
	return p.StepTypes()
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

func (p *authPlugin) CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.auth_passkey_begin_register":
		return sdk.NewTypedStepFactory(typeName, &contracts.PasskeyStepConfig{}, &contracts.PasskeyBeginRegisterInput{}, typedLegacyStep[*contracts.PasskeyStepConfig, *contracts.PasskeyBeginRegisterInput, *contracts.PasskeyBeginRegisterOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newPasskeyBeginRegisterStep(name, config)
		}, &contracts.PasskeyBeginRegisterOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_passkey_finish_register":
		return sdk.NewTypedStepFactory(typeName, &contracts.PasskeyStepConfig{}, &contracts.PasskeyFinishRegisterInput{}, typedLegacyStep[*contracts.PasskeyStepConfig, *contracts.PasskeyFinishRegisterInput, *contracts.PasskeyFinishRegisterOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newPasskeyFinishRegisterStep(name, config)
		}, &contracts.PasskeyFinishRegisterOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_passkey_begin_login":
		return sdk.NewTypedStepFactory(typeName, &contracts.PasskeyStepConfig{}, &contracts.PasskeyBeginLoginInput{}, typedLegacyStep[*contracts.PasskeyStepConfig, *contracts.PasskeyBeginLoginInput, *contracts.PasskeyBeginLoginOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newPasskeyBeginLoginStep(name, config)
		}, &contracts.PasskeyBeginLoginOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_passkey_finish_login":
		return sdk.NewTypedStepFactory(typeName, &contracts.PasskeyStepConfig{}, &contracts.PasskeyFinishLoginInput{}, typedLegacyStep[*contracts.PasskeyStepConfig, *contracts.PasskeyFinishLoginInput, *contracts.PasskeyFinishLoginOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newPasskeyFinishLoginStep(name, config)
		}, &contracts.PasskeyFinishLoginOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_totp_generate_secret":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.TOTPGenerateSecretInput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.TOTPGenerateSecretInput, *contracts.TOTPGenerateSecretOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newTOTPGenerateSecretStep(name, config)
		}, &contracts.TOTPGenerateSecretOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_totp_verify":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.TOTPVerifyInput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.TOTPVerifyInput, *contracts.TOTPVerifyOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newTOTPVerifyStep(name, config)
		}, &contracts.TOTPVerifyOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_totp_recovery_codes":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.TOTPRecoveryCodesInput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.TOTPRecoveryCodesInput, *contracts.TOTPRecoveryCodesOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newTOTPRecoveryCodesStep(name, config)
		}, &contracts.TOTPRecoveryCodesOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_magic_link_generate":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.MagicLinkGenerateInput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.MagicLinkGenerateInput, *contracts.MagicLinkGenerateOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newMagicLinkGenerateStep(name, config)
		}, &contracts.MagicLinkGenerateOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_magic_link_verify":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.MagicLinkVerifyInput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.MagicLinkVerifyInput, *contracts.MagicLinkVerifyOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newMagicLinkVerifyStep(name, config)
		}, &contracts.MagicLinkVerifyOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_magic_link_send":
		return sdk.NewTypedStepFactory(typeName, &contracts.MagicLinkSendConfig{}, &contracts.MagicLinkSendInput{}, typedLegacyStep[*contracts.MagicLinkSendConfig, *contracts.MagicLinkSendInput, *contracts.MagicLinkSendOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newMagicLinkSendStep(name, config)
		}, &contracts.MagicLinkSendOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_password_hash":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.PasswordHashInput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.PasswordHashInput, *contracts.PasswordHashOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newPasswordHashStep(name, config)
		}, &contracts.PasswordHashOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_password_verify":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.PasswordVerifyInput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.PasswordVerifyInput, *contracts.PasswordVerifyOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newPasswordVerifyStep(name, config)
		}, &contracts.PasswordVerifyOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_challenge_generate":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.ChallengeGenerateInput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.ChallengeGenerateInput, *contracts.ChallengeGenerateOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newChallengeGenerateStep(name, config)
		}, &contracts.ChallengeGenerateOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_challenge_verify":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.ChallengeVerifyInput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.ChallengeVerifyInput, *contracts.ChallengeVerifyOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newChallengeVerifyStep(name, config)
		}, &contracts.ChallengeVerifyOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_normalize_phone":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.NormalizePhoneInput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.NormalizePhoneInput, *contracts.NormalizePhoneOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newNormalizePhoneStep(name, config)
		}, &contracts.NormalizePhoneOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_methods_policy":
		return sdk.NewTypedStepFactory(typeName, &contracts.AuthMethodsPolicyConfig{}, &contracts.AuthMethodsPolicyInput{}, typedAuthMethodsPolicy).CreateTypedStep(typeName, name, config)
	case "step.auth_policy_gate":
		return sdk.NewTypedStepFactory(typeName, &contracts.AuthPolicyGateConfig{}, &contracts.AuthPolicyGateInput{}, typedPolicyGate).CreateTypedStep(typeName, name, config)
	case "step.auth_methods_response":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.AuthMethodsPolicyOutput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.AuthMethodsPolicyOutput, *contracts.AuthMethodsResponseOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newAuthMethodsResponseStep(name, config)
		}, &contracts.AuthMethodsResponseOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_policy_audit":
		return sdk.NewTypedStepFactory(typeName, &contracts.AuthMethodsPolicyConfig{}, &contracts.AuthMethodsPolicyInput{}, typedLegacyStep[*contracts.AuthMethodsPolicyConfig, *contracts.AuthMethodsPolicyInput, *contracts.AuthPolicyAuditOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newAuthPolicyAuditStep(name, config)
		}, &contracts.AuthPolicyAuditOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_oauth_provider_config":
		return sdk.NewTypedStepFactory(typeName, &contracts.OAuthProviderConfig{}, &contracts.OAuthProviderInput{}, typedLegacyStep[*contracts.OAuthProviderConfig, *contracts.OAuthProviderInput, *contracts.OAuthProviderConfigOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newOAuthProviderConfigStep(name, config)
		}, &contracts.OAuthProviderConfigOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_oauth_start":
		return sdk.NewTypedStepFactory(typeName, &contracts.OAuthProviderConfig{}, &contracts.OAuthProviderInput{}, typedLegacyStep[*contracts.OAuthProviderConfig, *contracts.OAuthProviderInput, *contracts.OAuthStartOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newOAuthStartStep(name, config)
		}, &contracts.OAuthStartOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_oauth_exchange":
		return sdk.NewTypedStepFactory(typeName, &contracts.OAuthProviderConfig{}, &contracts.OAuthProviderInput{}, typedLegacyStep[*contracts.OAuthProviderConfig, *contracts.OAuthProviderInput, *contracts.OAuthExchangeOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newOAuthExchangeStep(name, config)
		}, &contracts.OAuthExchangeOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_oauth_userinfo":
		return sdk.NewTypedStepFactory(typeName, &contracts.OAuthProviderConfig{}, &contracts.OAuthProviderInput{}, typedLegacyStep[*contracts.OAuthProviderConfig, *contracts.OAuthProviderInput, *contracts.OAuthUserinfoOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newOAuthUserinfoStep(name, config)
		}, &contracts.OAuthUserinfoOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_credential_list":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.CredentialListInput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.CredentialListInput, *contracts.CredentialListOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newCredentialListStep(name, config)
		}, &contracts.CredentialListOutput{})).CreateTypedStep(typeName, name, config)
	case "step.auth_credential_revoke":
		return sdk.NewTypedStepFactory(typeName, &contracts.EmptyConfig{}, &contracts.CredentialRevokeInput{}, typedLegacyStep[*contracts.EmptyConfig, *contracts.CredentialRevokeInput, *contracts.CredentialRevokeOutput](func(name string, config map[string]any) sdk.StepInstance {
			return newCredentialRevokeStep(name, config)
		}, &contracts.CredentialRevokeOutput{})).CreateTypedStep(typeName, name, config)
	default:
		return nil, fmt.Errorf("unknown typed step type: %s", typeName)
	}
}

func (p *authPlugin) ContractRegistry() *pb.ContractRegistry {
	return authContractRegistry
}

var authContractRegistry = &pb.ContractRegistry{
	FileDescriptorSet: &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			protodesc.ToFileDescriptorProto(structpb.File_google_protobuf_struct_proto),
			protodesc.ToFileDescriptorProto(contracts.File_internal_contracts_auth_proto),
		},
	},
	Contracts: []*pb.ContractDescriptor{
		moduleContract("auth.credential", "CredentialModuleConfig"),
		stepContract("step.auth_passkey_begin_register", "PasskeyStepConfig", "PasskeyBeginRegisterInput", "PasskeyBeginRegisterOutput"),
		stepContract("step.auth_passkey_finish_register", "PasskeyStepConfig", "PasskeyFinishRegisterInput", "PasskeyFinishRegisterOutput"),
		stepContract("step.auth_passkey_begin_login", "PasskeyStepConfig", "PasskeyBeginLoginInput", "PasskeyBeginLoginOutput"),
		stepContract("step.auth_passkey_finish_login", "PasskeyStepConfig", "PasskeyFinishLoginInput", "PasskeyFinishLoginOutput"),
		stepContract("step.auth_totp_generate_secret", "EmptyConfig", "TOTPGenerateSecretInput", "TOTPGenerateSecretOutput"),
		stepContract("step.auth_totp_verify", "EmptyConfig", "TOTPVerifyInput", "TOTPVerifyOutput"),
		stepContract("step.auth_totp_recovery_codes", "EmptyConfig", "TOTPRecoveryCodesInput", "TOTPRecoveryCodesOutput"),
		stepContract("step.auth_magic_link_generate", "EmptyConfig", "MagicLinkGenerateInput", "MagicLinkGenerateOutput"),
		stepContract("step.auth_magic_link_verify", "EmptyConfig", "MagicLinkVerifyInput", "MagicLinkVerifyOutput"),
		stepContract("step.auth_magic_link_send", "MagicLinkSendConfig", "MagicLinkSendInput", "MagicLinkSendOutput"),
		stepContract("step.auth_password_hash", "EmptyConfig", "PasswordHashInput", "PasswordHashOutput"),
		stepContract("step.auth_password_verify", "EmptyConfig", "PasswordVerifyInput", "PasswordVerifyOutput"),
		stepContract("step.auth_challenge_generate", "EmptyConfig", "ChallengeGenerateInput", "ChallengeGenerateOutput"),
		stepContract("step.auth_challenge_verify", "EmptyConfig", "ChallengeVerifyInput", "ChallengeVerifyOutput"),
		stepContract("step.auth_normalize_phone", "EmptyConfig", "NormalizePhoneInput", "NormalizePhoneOutput"),
		stepContract("step.auth_methods_policy", "AuthMethodsPolicyConfig", "AuthMethodsPolicyInput", "AuthMethodsPolicyOutput"),
		stepContract("step.auth_policy_gate", "AuthPolicyGateConfig", "AuthPolicyGateInput", "AuthMethodsPolicyOutput"),
		stepContract("step.auth_methods_response", "EmptyConfig", "AuthMethodsPolicyOutput", "AuthMethodsResponseOutput"),
		stepContract("step.auth_policy_audit", "AuthMethodsPolicyConfig", "AuthMethodsPolicyInput", "AuthPolicyAuditOutput"),
		stepContract("step.auth_oauth_provider_config", "OAuthProviderConfig", "OAuthProviderInput", "OAuthProviderConfigOutput"),
		stepContract("step.auth_oauth_start", "OAuthProviderConfig", "OAuthProviderInput", "OAuthStartOutput"),
		stepContract("step.auth_oauth_exchange", "OAuthProviderConfig", "OAuthProviderInput", "OAuthExchangeOutput"),
		stepContract("step.auth_oauth_userinfo", "OAuthProviderConfig", "OAuthProviderInput", "OAuthUserinfoOutput"),
		stepContract("step.auth_credential_list", "EmptyConfig", "CredentialListInput", "CredentialListOutput"),
		stepContract("step.auth_credential_revoke", "EmptyConfig", "CredentialRevokeInput", "CredentialRevokeOutput"),
	},
}

func moduleContract(moduleType, configMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.auth.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_MODULE,
		ModuleType:    moduleType,
		ConfigMessage: pkg + configMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}

func stepContract(stepType, configMessage, inputMessage, outputMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.auth.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_STEP,
		StepType:      stepType,
		ConfigMessage: pkg + configMessage,
		InputMessage:  pkg + inputMessage,
		OutputMessage: pkg + outputMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}
