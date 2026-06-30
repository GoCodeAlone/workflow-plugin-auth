// Package workflowpluginauth provides the auth workflow plugin.
package workflowpluginauth

import (
	"context"
	"fmt"

	"github.com/GoCodeAlone/modular"
	"github.com/GoCodeAlone/workflow-plugin-auth/internal"
	"github.com/GoCodeAlone/workflow/module"
	"github.com/GoCodeAlone/workflow/plugin"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// AuthEnginePlugin is the in-process EnginePlugin entry for auth. It is the
// dual-shape complement (ADR 0056) to the existing sdk/gRPC entry (NewAuthPlugin):
// it exposes auth's existing sdk steps for in-process consumption (e.g., by
// ratchet, a modular app) via a reverse bridge, WITHOUT spawning a gRPC
// subprocess. The gRPC path + the 35 sdk steps remain unchanged and authoritative.
type AuthEnginePlugin struct {
	plugin.BaseEnginePlugin
}

// NewAuthEnginePlugin returns an in-process plugin.EnginePlugin that wraps
// auth's existing sdk steps for in-process consumption.
func NewAuthEnginePlugin() plugin.EnginePlugin {
	return &AuthEnginePlugin{
		BaseEnginePlugin: plugin.BaseEnginePlugin{
			BaseNativePlugin: plugin.BaseNativePlugin{
				PluginName:        "workflow-plugin-auth",
				PluginVersion:     internal.Version,
				PluginDescription: "Passwordless authentication plugin: WebAuthn/passkeys, TOTP, email magic links",
			},
			Manifest: plugin.PluginManifest{
				Name:        "workflow-plugin-auth",
				Version:     internal.Version,
				Author:      "GoCodeAlone",
				Description: "Passwordless authentication plugin: WebAuthn/passkeys, TOTP, email magic links",
				ModuleTypes: []string{"auth.credential"},
				StepTypes:   []string{"step.auth_password_hash", "step.auth_password_verify"},
			},
		},
	}
}

// StepFactories returns the in-process step factories, wrapping auth's existing
// sdk steps via the reverse sdk→in-process bridge.
func (p *AuthEnginePlugin) StepFactories() map[string]plugin.StepFactory {
	provider := internal.NewAuthPlugin()
	stepProvider, ok := provider.(sdk.StepProvider)
	if !ok {
		// authPlugin always implements sdk.StepProvider; this is a defensive
		// guard against a future refactor that drops the interface.
		panic("workflow-plugin-auth: sdk provider does not implement sdk.StepProvider")
	}
	return map[string]plugin.StepFactory{
		"step.auth_password_hash":   wrapSDKStep(stepProvider, "step.auth_password_hash"),
		"step.auth_password_verify": wrapSDKStep(stepProvider, "step.auth_password_verify"),
	}
}

// wrapSDKStep returns a plugin.StepFactory that constructs the named sdk step
// via the auth sdk provider and wraps it for in-process execution. It is the
// REVERSE of the agent plugin's legacyStepInstance (typed_contracts.go:206-241):
// legacyStepInstance wraps an in-process step (Execute(ctx,*module.PipelineContext))
// FOR sdk serving; sdkStepToInProcess wraps an sdk step (Execute→*sdk.StepResult)
// for IN-PROCESS consumption, reusing the same PipelineContext↔maps mapping
// logic and the StepResult field mapping (Output, StopPipeline↔Stop).
func wrapSDKStep(provider sdk.StepProvider, stepType string) plugin.StepFactory {
	return func(name string, config map[string]any, _ /* app */ modular.Application) (any, error) {
		step, err := provider.CreateStep(stepType, name, config)
		if err != nil {
			return nil, fmt.Errorf("auth engine plugin: create step %s: %w", stepType, err)
		}
		return &sdkStepToInProcess{step: step}, nil
	}
}

// sdkStepToInProcess adapts an sdk.StepInstance (Execute with the sdk signature
// returning *sdk.StepResult) to module.PipelineStep (Execute(ctx,*module.PipelineContext)
// returning *module.StepResult). It is the reverse of legacyStepInstance.
type sdkStepToInProcess struct {
	step sdk.StepInstance
}

func (s *sdkStepToInProcess) Name() string { return "auth-inprocess" }

// Execute delegates to the wrapped sdk step, unpacking the PipelineContext
// fields into the sdk Execute signature (triggerData, stepOutputs, current,
// metadata, config) and mapping the sdk StepResult back to the in-process
// StepResult (Output, StopPipeline→Stop).
func (s *sdkStepToInProcess) Execute(ctx context.Context, pc *module.PipelineContext) (*module.StepResult, error) {
	var current map[string]any
	if pc != nil {
		current = pc.Current
	}
	res, err := s.step.Execute(ctx, pc.TriggerData, pc.StepOutputs, current, pc.Metadata, nil)
	if err != nil {
		return nil, err
	}
	if res == nil {
		return &module.StepResult{}, nil
	}
	return &module.StepResult{
		Output: res.Output,
		Stop:   res.StopPipeline,
	}, nil
}
