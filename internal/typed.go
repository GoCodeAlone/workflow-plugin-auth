package internal

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/GoCodeAlone/workflow-plugin-auth/internal/contracts"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var typedAuthMethodsPolicy = typedLegacyStep[*contracts.AuthMethodsPolicyConfig, *contracts.AuthMethodsPolicyInput, *contracts.AuthMethodsPolicyOutput](
	func(name string, config map[string]any) sdk.StepInstance {
		return newAuthMethodsPolicyStep(name, config)
	},
	&contracts.AuthMethodsPolicyOutput{},
)

func typedPolicyGate(ctx context.Context, req sdk.TypedStepRequest[*contracts.AuthPolicyGateConfig, *contracts.AuthPolicyGateInput]) (*sdk.TypedStepResult[*contracts.AuthMethodsPolicyOutput], error) {
	config, err := protoMessageToMap(req.Config)
	if err != nil {
		return nil, err
	}
	input, err := protoMessageToMap(req.Input)
	if err != nil {
		return nil, err
	}
	stepName := policyString(config, "policy_step")
	if stepName == "" {
		stepName = "policy"
	}
	stepOutputs := map[string]map[string]any{}
	for name, output := range req.StepOutputs {
		stepOutputs[name] = output
	}
	stepOutputs[stepName] = input
	runtimeConfig := runtimeConfigFromMetadata(req.Metadata)
	step := newAuthPolicyGateStep("typed", config)
	result, err := step.Execute(ctx, req.TriggerData, stepOutputs, mergeMaps(req.Current, input), req.Metadata, runtimeConfig)
	if err != nil {
		return nil, err
	}
	output, err := mapToProto(result.Output, &contracts.AuthMethodsPolicyOutput{})
	if err != nil {
		return nil, err
	}
	return &sdk.TypedStepResult[*contracts.AuthMethodsPolicyOutput]{Output: output, StopPipeline: result.StopPipeline}, nil
}

func typedLegacyStep[C proto.Message, I proto.Message, O proto.Message](
	create func(name string, config map[string]any) sdk.StepInstance,
	output O,
) sdk.TypedStepHandler[C, I, O] {
	return func(ctx context.Context, req sdk.TypedStepRequest[C, I]) (*sdk.TypedStepResult[O], error) {
		config, err := protoMessageToMap(req.Config)
		if err != nil {
			return nil, err
		}
		input, err := protoMessageToMap(req.Input)
		if err != nil {
			return nil, err
		}
		step := create("typed", config)
		result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, mergeMaps(req.Current, input), req.Metadata, runtimeConfigFromMetadata(req.Metadata))
		if err != nil {
			return nil, err
		}
		typedOutput, err := mapToProto(result.Output, output)
		if err != nil {
			return nil, err
		}
		return &sdk.TypedStepResult[O]{Output: typedOutput, StopPipeline: result.StopPipeline}, nil
	}
}

func protoMessageToMap(msg proto.Message) (map[string]any, error) {
	if msg == nil {
		return map[string]any{}, nil
	}
	data, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal typed protobuf: %w", err)
	}
	values := map[string]any{}
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, fmt.Errorf("decode typed protobuf: %w", err)
	}
	return values, nil
}

func mapToProto[O proto.Message](values map[string]any, target O) (O, error) {
	typed := proto.Clone(target).(O)
	data, err := json.Marshal(values)
	if err != nil {
		return typed, fmt.Errorf("marshal step output map: %w", err)
	}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(data, typed); err != nil {
		return typed, fmt.Errorf("decode typed protobuf output: %w", err)
	}
	return typed, nil
}

func runtimeConfigFromMetadata(metadata map[string]any) map[string]any {
	for _, key := range []string{"runtime_config", "runtimeConfig"} {
		values, ok := metadata[key]
		if !ok {
			continue
		}
		switch typed := values.(type) {
		case map[string]any:
			return typed
		case map[string]string:
			converted := make(map[string]any, len(typed))
			for key, value := range typed {
				converted[key] = value
			}
			return converted
		}
	}
	return nil
}

func mergeMaps(sources ...map[string]any) map[string]any {
	merged := map[string]any{}
	for _, source := range sources {
		for key, value := range source {
			merged[key] = value
		}
	}
	return merged
}
