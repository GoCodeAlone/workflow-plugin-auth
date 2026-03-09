package internal

import (
	"context"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestTOTPGenerateSecret(t *testing.T) {
	step := newTOTPGenerateSecretStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"email": "test@example.com",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secret, ok := result.Output["secret"].(string)
	if !ok || secret == "" {
		t.Fatal("expected non-empty secret")
	}
	uri, ok := result.Output["provisioning_uri"].(string)
	if !ok || uri == "" {
		t.Fatal("expected non-empty provisioning URI")
	}
}

func TestTOTPVerify(t *testing.T) {
	genStep := newTOTPGenerateSecretStep("gen", nil)
	genResult, _ := genStep.Execute(context.Background(), nil, nil, map[string]any{
		"email": "test@example.com",
	}, nil, nil)
	secret := genResult.Output["secret"].(string)

	code, _ := totp.GenerateCode(secret, time.Now())

	verifyStep := newTOTPVerifyStep("verify", nil)
	result, err := verifyStep.Execute(context.Background(), nil, nil, map[string]any{
		"code":   code,
		"secret": secret,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["valid"] != true {
		t.Fatal("expected valid=true for correct TOTP code")
	}
}

func TestTOTPVerify_InvalidCode(t *testing.T) {
	step := newTOTPVerifyStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"code":   "000000",
		"secret": "JBSWY3DPEHPK3PXP",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["valid"] != false {
		t.Fatal("expected valid=false for wrong code")
	}
}

func TestTOTPVerify_MissingData(t *testing.T) {
	step := newTOTPVerifyStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["valid"] != false {
		t.Fatal("expected valid=false for missing data")
	}
}

func TestTOTPRecoveryCodes(t *testing.T) {
	step := newTOTPRecoveryCodesStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	codes, ok := result.Output["codes"].([]string)
	if !ok || len(codes) != 10 {
		t.Fatalf("expected 10 codes, got %d", len(codes))
	}
	hashes, ok := result.Output["hashes"].([]string)
	if !ok || len(hashes) != 10 {
		t.Fatalf("expected 10 hashes, got %d", len(hashes))
	}
}
