package internal

import (
	"context"
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- LIST ---

type credentialListStep struct{ name string }

func newCredentialListStep(name string, _ map[string]any) *credentialListStep {
	return &credentialListStep{name: name}
}

func (s *credentialListStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	return nil, fmt.Errorf("step %s: not yet implemented", s.name)
}

// --- REVOKE ---

type credentialRevokeStep struct{ name string }

func newCredentialRevokeStep(name string, _ map[string]any) *credentialRevokeStep {
	return &credentialRevokeStep{name: name}
}

func (s *credentialRevokeStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	return nil, fmt.Errorf("step %s: not yet implemented", s.name)
}
