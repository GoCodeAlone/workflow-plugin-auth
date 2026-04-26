package internal

import (
	"context"
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"golang.org/x/crypto/bcrypt"
)

type passwordHashStep struct{ name string }

func newPasswordHashStep(name string, _ map[string]any) *passwordHashStep {
	return &passwordHashStep{name: name}
}

func (s *passwordHashStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	password, _ := current["password"].(string)
	if password == "" {
		return &sdk.StepResult{Output: map[string]any{"error": "missing password"}}, nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	return &sdk.StepResult{Output: map[string]any{"hash": string(hash)}}, nil
}

type passwordVerifyStep struct{ name string }

func newPasswordVerifyStep(name string, _ map[string]any) *passwordVerifyStep {
	return &passwordVerifyStep{name: name}
}

func (s *passwordVerifyStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	password, _ := current["password"].(string)
	hash, _ := current["hash"].(string)
	if password == "" || hash == "" {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "missing password or hash"}}, nil
	}

	valid := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	return &sdk.StepResult{Output: map[string]any{"valid": valid}}, nil
}
