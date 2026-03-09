package internal

import (
	"context"
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- GENERATE SECRET ---

type totpGenerateSecretStep struct{ name string }

func newTOTPGenerateSecretStep(name string, _ map[string]any) *totpGenerateSecretStep {
	return &totpGenerateSecretStep{name: name}
}

func (s *totpGenerateSecretStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	return nil, fmt.Errorf("step %s: not yet implemented", s.name)
}

// --- VERIFY ---

type totpVerifyStep struct{ name string }

func newTOTPVerifyStep(name string, _ map[string]any) *totpVerifyStep {
	return &totpVerifyStep{name: name}
}

func (s *totpVerifyStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	return nil, fmt.Errorf("step %s: not yet implemented", s.name)
}

// --- RECOVERY CODES ---

type totpRecoveryCodesStep struct{ name string }

func newTOTPRecoveryCodesStep(name string, _ map[string]any) *totpRecoveryCodesStep {
	return &totpRecoveryCodesStep{name: name}
}

func (s *totpRecoveryCodesStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	return nil, fmt.Errorf("step %s: not yet implemented", s.name)
}
