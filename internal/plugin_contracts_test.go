package internal

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-auth/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestContractRegistryDeclaresStrictContracts(t *testing.T) {
	provider := NewAuthPlugin().(interface {
		ContractRegistry() *pb.ContractRegistry
	})

	registry := provider.ContractRegistry()
	if registry == nil {
		t.Fatal("ContractRegistry returned nil")
	}
	if registry.FileDescriptorSet == nil || len(registry.FileDescriptorSet.File) == 0 {
		t.Fatal("ContractRegistry missing file descriptors")
	}

	runtimeContracts := map[string]*pb.ContractDescriptor{}
	for _, contract := range registry.Contracts {
		if contract.Mode != pb.ContractMode_CONTRACT_MODE_STRICT_PROTO {
			t.Fatalf("contract %v mode = %v, want strict proto", contract, contract.Mode)
		}
		key := contractKey(contract)
		if _, exists := runtimeContracts[key]; exists {
			t.Fatalf("duplicate runtime contract %s", key)
		}
		runtimeContracts[key] = contract
	}

	manifestContracts := readManifestContracts(t)
	for key := range manifestContracts {
		if _, exists := runtimeContracts[key]; !exists {
			t.Fatalf("%s missing from runtime contract registry", key)
		}
	}
	if len(runtimeContracts) != len(manifestContracts) {
		t.Fatalf("runtime contract count = %d, manifest = %d", len(runtimeContracts), len(manifestContracts))
	}

	requireContract(t, runtimeContracts, "module:auth.credential", "workflow.plugins.auth.v1.CredentialModuleConfig", "", "")
	requireContract(t, runtimeContracts, "step:step.auth_challenge_generate", "workflow.plugins.auth.v1.EmptyConfig", "workflow.plugins.auth.v1.ChallengeGenerateInput", "workflow.plugins.auth.v1.ChallengeGenerateOutput")
	requireContract(t, runtimeContracts, "step:step.auth_methods_policy", "workflow.plugins.auth.v1.AuthMethodsPolicyConfig", "workflow.plugins.auth.v1.AuthMethodsPolicyInput", "workflow.plugins.auth.v1.AuthMethodsPolicyOutput")
}

func TestCreateTypedModuleRejectsWrongConfigType(t *testing.T) {
	provider := NewAuthPlugin().(interface {
		CreateTypedModule(typeName, name string, config *anypb.Any) (sdk.ModuleInstance, error)
	})

	wrongConfig, err := anypb.New(&contracts.AuthMethodsPolicyConfig{Environment: "dev"})
	if err != nil {
		t.Fatalf("pack wrong config: %v", err)
	}
	if _, err := provider.CreateTypedModule("auth.credential", "authn", wrongConfig); err == nil {
		t.Fatal("CreateTypedModule accepted wrong typed config")
	}
}

func TestTypedPolicyInputOverridesTypedConfigAtBoundary(t *testing.T) {
	provider := NewAuthPlugin().(interface {
		CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error)
	})

	config, err := anypb.New(&contracts.AuthMethodsPolicyConfig{
		Environment:         "development",
		PasswordAuthEnabled: protoBool(true),
	})
	if err != nil {
		t.Fatalf("pack config: %v", err)
	}
	step, err := provider.CreateTypedStep("step.auth_methods_policy", "policy", config)
	if err != nil {
		t.Fatalf("CreateTypedStep: %v", err)
	}

	typedStep, ok := step.(*sdk.TypedStepInstance[*contracts.AuthMethodsPolicyConfig, *contracts.AuthMethodsPolicyInput, *contracts.AuthMethodsPolicyOutput])
	if !ok {
		t.Fatalf("typed step type = %T", step)
	}
	result, err := typedStepForTest(t, typedStep)(context.Background(), sdk.TypedStepRequest[*contracts.AuthMethodsPolicyConfig, *contracts.AuthMethodsPolicyInput]{
		Config: &contracts.AuthMethodsPolicyConfig{
			Environment:         "development",
			PasswordAuthEnabled: protoBool(true),
		},
		Input: &contracts.AuthMethodsPolicyInput{
			Environment:         "production",
			PasswordAuthEnabled: protoBool(true),
		},
	})
	if err != nil {
		t.Fatalf("typed policy handler: %v", err)
	}
	if result.Output.GetPasswordEnabled() {
		t.Fatal("typed policy let config enable password after production input override")
	}
	if result.Output.GetPasswordAuthEnabled() {
		t.Fatal("typed policy let config enable password_auth after production input override")
	}

	result, err = typedStepForTest(t, typedStep)(context.Background(), sdk.TypedStepRequest[*contracts.AuthMethodsPolicyConfig, *contracts.AuthMethodsPolicyInput]{
		Config: &contracts.AuthMethodsPolicyConfig{
			Environment:         "development",
			PasswordAuthEnabled: protoBool(true),
		},
		Input: &contracts.AuthMethodsPolicyInput{
			PasswordAuthEnabled: protoBool(false),
		},
	})
	if err != nil {
		t.Fatalf("typed policy handler with false override: %v", err)
	}
	if result.Output.GetPasswordEnabled() {
		t.Fatal("typed policy did not let explicit false input override true config")
	}
}

func TestMapToProtoRejectsUnknownOutputFields(t *testing.T) {
	if _, err := mapToProto(map[string]any{"valid": true, "ignored": "drift"}, &contracts.TOTPVerifyOutput{}); err == nil {
		t.Fatal("mapToProto accepted an unknown output field")
	}
}

func TestPasskeyAndTOTPContractsUseRuntimeMapKeys(t *testing.T) {
	requireProtoFields(t, &contracts.PasskeyBeginRegisterInput{}, "user_id", "email", "display_name")
	requireProtoFields(t, &contracts.PasskeyBeginRegisterOutput{}, "options", "session_data", "error")
	requireProtoFields(t, &contracts.PasskeyFinishRegisterInput{}, "user_id", "email", "display_name", "session_data", "attestation")
	requireProtoFields(t, &contracts.PasskeyFinishRegisterOutput{}, "valid", "credential_id", "public_key", "aaguid", "sign_count", "credential", "error")
	requireProtoFields(t, &contracts.PasskeyBeginLoginInput{}, "user_id", "credentials")
	requireProtoFields(t, &contracts.PasskeyBeginLoginOutput{}, "options", "session_data", "error")
	requireProtoFields(t, &contracts.PasskeyFinishLoginInput{}, "user_id", "email", "credentials", "session_data", "assertion")
	requireProtoFields(t, &contracts.PasskeyFinishLoginOutput{}, "valid", "credential_id", "sign_count", "error")

	requireProtoFields(t, &contracts.TOTPGenerateSecretInput{}, "email", "issuer")
	requireProtoFields(t, &contracts.TOTPGenerateSecretOutput{}, "secret", "provisioning_uri", "issuer", "account", "error")
	requireProtoFields(t, &contracts.TOTPRecoveryCodesOutput{}, "codes", "hashes", "error")
}

func TestTypedPasskeyOutputsDecodeRuntimeKeys(t *testing.T) {
	beginRegister, err := mapToProto(map[string]any{
		"options":      `{"publicKey":{}}`,
		"session_data": "session",
	}, &contracts.PasskeyBeginRegisterOutput{})
	if err != nil {
		t.Fatalf("decode begin register output: %v", err)
	}
	if beginRegister.GetOptions() == "" || beginRegister.GetSessionData() != "session" {
		t.Fatalf("begin register output = %+v", beginRegister)
	}

	finishRegister, err := mapToProto(map[string]any{
		"valid":         true,
		"credential_id": "credential-id",
		"public_key":    "public-key",
		"aaguid":        "aaguid",
		"sign_count":    7,
		"credential":    `{"id":"credential-id"}`,
	}, &contracts.PasskeyFinishRegisterOutput{})
	if err != nil {
		t.Fatalf("decode finish register output: %v", err)
	}
	if !finishRegister.GetValid() || finishRegister.GetSignCount() != 7 || finishRegister.GetCredential() == "" {
		t.Fatalf("finish register output = %+v", finishRegister)
	}

	beginLogin, err := mapToProto(map[string]any{
		"options":      `{"publicKey":{}}`,
		"session_data": "login-session",
	}, &contracts.PasskeyBeginLoginOutput{})
	if err != nil {
		t.Fatalf("decode begin login output: %v", err)
	}
	if beginLogin.GetOptions() == "" || beginLogin.GetSessionData() != "login-session" {
		t.Fatalf("begin login output = %+v", beginLogin)
	}

	finishLogin, err := mapToProto(map[string]any{
		"valid":         true,
		"credential_id": "credential-id",
		"sign_count":    8,
	}, &contracts.PasskeyFinishLoginOutput{})
	if err != nil {
		t.Fatalf("decode finish login output: %v", err)
	}
	if !finishLogin.GetValid() || finishLogin.GetSignCount() != 8 {
		t.Fatalf("finish login output = %+v", finishLogin)
	}
}

func TestTypedTOTPStepsDecodeRuntimeOutputs(t *testing.T) {
	generate := typedLegacyStep[*contracts.EmptyConfig, *contracts.TOTPGenerateSecretInput, *contracts.TOTPGenerateSecretOutput](
		func(name string, config map[string]any) sdk.StepInstance {
			return newTOTPGenerateSecretStep(name, config)
		},
		&contracts.TOTPGenerateSecretOutput{},
	)
	generated, err := generate(context.Background(), sdk.TypedStepRequest[*contracts.EmptyConfig, *contracts.TOTPGenerateSecretInput]{
		Config: &contracts.EmptyConfig{},
		Input:  &contracts.TOTPGenerateSecretInput{Email: "alice@example.test", Issuer: "Workflow"},
	})
	if err != nil {
		t.Fatalf("generate TOTP secret: %v", err)
	}
	if generated.Output.GetSecret() == "" || generated.Output.GetProvisioningUri() == "" {
		t.Fatalf("generated TOTP output = %+v", generated.Output)
	}
	if generated.Output.GetIssuer() != "Workflow" || generated.Output.GetAccount() != "alice@example.test" {
		t.Fatalf("generated TOTP issuer/account = %q/%q", generated.Output.GetIssuer(), generated.Output.GetAccount())
	}

	recoveryCodes := typedLegacyStep[*contracts.EmptyConfig, *contracts.TOTPRecoveryCodesInput, *contracts.TOTPRecoveryCodesOutput](
		func(name string, config map[string]any) sdk.StepInstance {
			return newTOTPRecoveryCodesStep(name, config)
		},
		&contracts.TOTPRecoveryCodesOutput{},
	)
	recovery, err := recoveryCodes(context.Background(), sdk.TypedStepRequest[*contracts.EmptyConfig, *contracts.TOTPRecoveryCodesInput]{
		Config: &contracts.EmptyConfig{},
		Input:  &contracts.TOTPRecoveryCodesInput{},
	})
	if err != nil {
		t.Fatalf("generate TOTP recovery codes: %v", err)
	}
	if len(recovery.Output.GetCodes()) != 10 || len(recovery.Output.GetHashes()) != 10 {
		t.Fatalf("recovery output lengths = %d/%d", len(recovery.Output.GetCodes()), len(recovery.Output.GetHashes()))
	}
}

func typedStepForTest[
	C interface {
		*contracts.AuthMethodsPolicyConfig
	},
	I interface {
		*contracts.AuthMethodsPolicyInput
	},
	O interface {
		*contracts.AuthMethodsPolicyOutput
	},
](_ *testing.T, _ *sdk.TypedStepInstance[*contracts.AuthMethodsPolicyConfig, *contracts.AuthMethodsPolicyInput, *contracts.AuthMethodsPolicyOutput]) sdk.TypedStepHandler[*contracts.AuthMethodsPolicyConfig, *contracts.AuthMethodsPolicyInput, *contracts.AuthMethodsPolicyOutput] {
	return typedAuthMethodsPolicy
}

func requireProtoFields(t *testing.T, msg proto.Message, fields ...string) {
	t.Helper()
	descriptor := msg.ProtoReflect().Descriptor()
	for _, field := range fields {
		if descriptor.Fields().ByName(protoreflect.Name(field)) == nil {
			t.Fatalf("%s missing field %q", descriptor.FullName(), field)
		}
	}
}

func contractKey(contract *pb.ContractDescriptor) string {
	switch contract.Kind {
	case pb.ContractKind_CONTRACT_KIND_MODULE:
		return "module:" + contract.ModuleType
	case pb.ContractKind_CONTRACT_KIND_STEP:
		return "step:" + contract.StepType
	default:
		return "unknown:" + contract.String()
	}
}

func requireContract(t *testing.T, contracts map[string]*pb.ContractDescriptor, key, config, input, output string) {
	t.Helper()
	contract, exists := contracts[key]
	if !exists {
		t.Fatalf("missing contract %s", key)
	}
	if contract.GetConfigMessage() != config {
		t.Fatalf("%s config = %q, want %q", key, contract.GetConfigMessage(), config)
	}
	if contract.GetInputMessage() != input {
		t.Fatalf("%s input = %q, want %q", key, contract.GetInputMessage(), input)
	}
	if contract.GetOutputMessage() != output {
		t.Fatalf("%s output = %q, want %q", key, contract.GetOutputMessage(), output)
	}
}

func readManifestContracts(t *testing.T) map[string]struct{} {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "plugin.contracts.json"))
	if err != nil {
		t.Fatalf("read plugin.contracts.json: %v", err)
	}
	var manifest struct {
		Version   string `json:"version"`
		Contracts []struct {
			Kind string `json:"kind"`
			Type string `json:"type"`
		} `json:"contracts"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse plugin.contracts.json: %v", err)
	}
	if manifest.Version != "v1" {
		t.Fatalf("plugin.contracts.json version = %q, want v1", manifest.Version)
	}
	contracts := make(map[string]struct{}, len(manifest.Contracts))
	for _, contract := range manifest.Contracts {
		contracts[strings.TrimSpace(contract.Kind)+":"+strings.TrimSpace(contract.Type)] = struct{}{}
	}
	return contracts
}

func protoBool(value bool) *bool {
	return &value
}
