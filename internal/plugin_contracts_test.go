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
