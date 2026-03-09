package internal

import (
	"context"
	"testing"
)

func TestPasskeyBeginRegisterStep_MissingModule(t *testing.T) {
	step := newPasskeyBeginRegisterStep("test", map[string]any{"module": "nonexistent"})
	_, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"user_id": "test-user",
		"email":   "test@example.com",
	}, nil, nil)
	if err == nil {
		t.Fatal("expected error for missing module")
	}
}

func TestPasskeyFinishRegisterStep_MissingModule(t *testing.T) {
	step := newPasskeyFinishRegisterStep("test", map[string]any{"module": "nonexistent"})
	_, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err == nil {
		t.Fatal("expected error for missing module")
	}
}

func TestPasskeyBeginLoginStep_MissingModule(t *testing.T) {
	step := newPasskeyBeginLoginStep("test", map[string]any{"module": "nonexistent"})
	_, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err == nil {
		t.Fatal("expected error for missing module")
	}
}

func TestPasskeyFinishLoginStep_MissingModule(t *testing.T) {
	step := newPasskeyFinishLoginStep("test", map[string]any{"module": "nonexistent"})
	_, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err == nil {
		t.Fatal("expected error for missing module")
	}
}

func TestPasskeyFinishRegisterStep_MissingData(t *testing.T) {
	// Register a module so we can test the data validation path
	mod := &credentialModule{name: "test-mod"}
	registerModule("test-mod", mod)
	defer unregisterModule("test-mod")

	step := newPasskeyFinishRegisterStep("test", map[string]any{"module": "test-mod"})
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	valid, _ := result.Output["valid"].(bool)
	if valid {
		t.Fatal("expected valid=false for missing data")
	}
}

func TestPasskeyFinishLoginStep_MissingData(t *testing.T) {
	mod := &credentialModule{name: "test-mod"}
	registerModule("test-mod", mod)
	defer unregisterModule("test-mod")

	step := newPasskeyFinishLoginStep("test", map[string]any{"module": "test-mod"})
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	valid, _ := result.Output["valid"].(bool)
	if valid {
		t.Fatal("expected valid=false for missing data")
	}
}
