package internal

import (
	"context"
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- BEGIN REGISTER ---

type passkeyBeginRegisterStep struct{ name, module string }

func newPasskeyBeginRegisterStep(name string, config map[string]any) *passkeyBeginRegisterStep {
	module, _ := config["module"].(string)
	return &passkeyBeginRegisterStep{name: name, module: module}
}

func (s *passkeyBeginRegisterStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	return nil, fmt.Errorf("step %s: not yet implemented", s.name)
}

// --- FINISH REGISTER ---

type passkeyFinishRegisterStep struct{ name, module string }

func newPasskeyFinishRegisterStep(name string, config map[string]any) *passkeyFinishRegisterStep {
	module, _ := config["module"].(string)
	return &passkeyFinishRegisterStep{name: name, module: module}
}

func (s *passkeyFinishRegisterStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	return nil, fmt.Errorf("step %s: not yet implemented", s.name)
}

// --- BEGIN LOGIN ---

type passkeyBeginLoginStep struct{ name, module string }

func newPasskeyBeginLoginStep(name string, config map[string]any) *passkeyBeginLoginStep {
	module, _ := config["module"].(string)
	return &passkeyBeginLoginStep{name: name, module: module}
}

func (s *passkeyBeginLoginStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	return nil, fmt.Errorf("step %s: not yet implemented", s.name)
}

// --- FINISH LOGIN ---

type passkeyFinishLoginStep struct{ name, module string }

func newPasskeyFinishLoginStep(name string, config map[string]any) *passkeyFinishLoginStep {
	module, _ := config["module"].(string)
	return &passkeyFinishLoginStep{name: name, module: module}
}

func (s *passkeyFinishLoginStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	return nil, fmt.Errorf("step %s: not yet implemented", s.name)
}
