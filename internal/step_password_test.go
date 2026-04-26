package internal

import (
	"context"
	"testing"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"golang.org/x/crypto/bcrypt"
)

func TestPasswordHash_EmitsHashWithoutPassword(t *testing.T) {
	step := mustCreatePasswordStep(t, "step.auth_password_hash")

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"password": "correct horse battery staple",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hash, ok := result.Output["hash"].(string)
	if !ok || hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if _, ok := result.Output["password"]; ok {
		t.Fatal("did not expect password in output")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("correct horse battery staple")); err != nil {
		t.Fatalf("expected hash to match password: %v", err)
	}
}

func TestPasswordVerify_ReturnsTrueForMatchingPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash fixture: %v", err)
	}
	step := mustCreatePasswordStep(t, "step.auth_password_verify")

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"password": "secret-password",
		"hash":     string(hash),
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["valid"] != true {
		t.Fatal("expected valid=true for matching password")
	}
}

func TestPasswordVerify_ReturnsFalseForWrongPassword(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret-password"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash fixture: %v", err)
	}
	step := mustCreatePasswordStep(t, "step.auth_password_verify")

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"password": "wrong-password",
		"hash":     string(hash),
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["valid"] != false {
		t.Fatal("expected valid=false for wrong password")
	}
}

func TestPasswordVerify_ReturnsFalseAndErrorForMissingInput(t *testing.T) {
	step := mustCreatePasswordStep(t, "step.auth_password_verify")

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["valid"] != false {
		t.Fatal("expected valid=false for missing input")
	}
	if _, ok := result.Output["error"].(string); !ok {
		t.Fatal("expected error string for missing input")
	}
}

func mustCreatePasswordStep(t *testing.T, stepType string) sdk.StepInstance {
	t.Helper()
	provider := NewAuthPlugin().(sdk.StepProvider)
	step, err := provider.CreateStep(stepType, "test", map[string]any{})
	if err != nil {
		t.Fatalf("CreateStep(%q): %v", stepType, err)
	}
	return step
}
