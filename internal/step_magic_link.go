package internal

import (
	"context"
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- GENERATE ---

type magicLinkGenerateStep struct{ name string }

func newMagicLinkGenerateStep(name string, _ map[string]any) *magicLinkGenerateStep {
	return &magicLinkGenerateStep{name: name}
}

func (s *magicLinkGenerateStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	return nil, fmt.Errorf("step %s: not yet implemented", s.name)
}

// --- VERIFY ---

type magicLinkVerifyStep struct{ name string }

func newMagicLinkVerifyStep(name string, _ map[string]any) *magicLinkVerifyStep {
	return &magicLinkVerifyStep{name: name}
}

func (s *magicLinkVerifyStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	return nil, fmt.Errorf("step %s: not yet implemented", s.name)
}

// --- SEND ---

type magicLinkSendStep struct{ name string }

func newMagicLinkSendStep(name string, _ map[string]any) *magicLinkSendStep {
	return &magicLinkSendStep{name: name}
}

func (s *magicLinkSendStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	return nil, fmt.Errorf("step %s: not yet implemented", s.name)
}
