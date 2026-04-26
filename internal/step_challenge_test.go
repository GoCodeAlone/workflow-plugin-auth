package internal

import (
	"context"
	"regexp"
	"testing"
	"time"
)

func TestChallengeGenerate_EmitsCodeHashDestinationAndExpiry(t *testing.T) {
	step := newChallengeGenerateStep("test", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"destination":    " User@Example.COM ",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "test-secret",
		"ttl_minutes":    5,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	code, ok := result.Output["code"].(string)
	if !ok || !regexp.MustCompile(`^\d{6}$`).MatchString(code) {
		t.Fatalf("expected six-digit code, got %#v", result.Output["code"])
	}
	if codeHash, ok := result.Output["code_hash"].(string); !ok || codeHash == "" {
		t.Fatal("expected non-empty code_hash")
	}
	if result.Output["destination"] != "user@example.com" {
		t.Fatalf("expected normalized email destination, got %#v", result.Output["destination"])
	}
	if result.Output["channel"] != "email" {
		t.Fatalf("expected channel in output, got %#v", result.Output["channel"])
	}
	expiresAt, ok := result.Output["expires_at"].(string)
	if !ok || expiresAt == "" {
		t.Fatal("expected expires_at")
	}
	parsed, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		t.Fatalf("expected RFC3339 expires_at: %v", err)
	}
	if time.Until(parsed) <= 0 {
		t.Fatal("expected expires_at in the future")
	}
}

func TestChallengeGenerate_TrimsPhoneDestinationWithoutChangingPunctuation(t *testing.T) {
	step := newChallengeGenerateStep("test", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "sms",
		"destination":    " +15551234567 ",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "test-secret",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["destination"] != "+15551234567" {
		t.Fatalf("expected trimmed phone destination, got %#v", result.Output["destination"])
	}
}

func TestChallengeGenerate_RequiresSigningSecret(t *testing.T) {
	step := newChallengeGenerateStep("test", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"channel":     "email",
		"destination": "user@example.com",
		"tenant_id":   "tenant-123",
		"purpose":     "login",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := result.Output["code_hash"]; ok {
		t.Fatal("did not expect code_hash without signing_secret")
	}
	if _, ok := result.Output["error"].(string); !ok {
		t.Fatal("expected error string without signing_secret")
	}
}

func TestChallengeVerify_ReturnsTrueForGeneratedCodeHash(t *testing.T) {
	genStep := newChallengeGenerateStep("generate", nil)
	genResult, err := genStep.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"destination":    "User@Example.COM",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "test-secret",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected generate error: %v", err)
	}

	verifyStep := newChallengeVerifyStep("verify", nil)
	result, err := verifyStep.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"code":           genResult.Output["code"],
		"code_hash":      genResult.Output["code_hash"],
		"destination":    " user@example.com ",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "test-secret",
		"expires_at":     genResult.Output["expires_at"],
		"attempts":       0,
		"max_attempts":   3,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}

	if result.Output["valid"] != true {
		t.Fatal("expected valid=true for generated challenge")
	}
}

func TestChallengeVerify_DefaultsMaxAttemptsWhenOmitted(t *testing.T) {
	genStep := newChallengeGenerateStep("generate", nil)
	genResult, err := genStep.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"destination":    "user@example.com",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "test-secret",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected generate error: %v", err)
	}

	verifyStep := newChallengeVerifyStep("verify", nil)
	result, err := verifyStep.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"code":           genResult.Output["code"],
		"code_hash":      genResult.Output["code_hash"],
		"destination":    "user@example.com",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "test-secret",
		"expires_at":     genResult.Output["expires_at"],
		"attempts":       4,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}

	if result.Output["valid"] != true {
		t.Fatal("expected valid=true below default max_attempts")
	}
}

func TestChallengeVerify_BindsChannelTenantAndPurpose(t *testing.T) {
	genStep := newChallengeGenerateStep("generate", nil)
	genResult, err := genStep.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"destination":    "user@example.com",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "test-secret",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected generate error: %v", err)
	}

	verifyStep := newChallengeVerifyStep("verify", nil)
	result, err := verifyStep.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "sms",
		"code":           genResult.Output["code"],
		"code_hash":      genResult.Output["code_hash"],
		"destination":    "user@example.com",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "test-secret",
		"expires_at":     genResult.Output["expires_at"],
		"attempts":       0,
		"max_attempts":   3,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if result.Output["valid"] != false {
		t.Fatal("expected valid=false when channel differs")
	}

	result, err = verifyStep.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"code":           genResult.Output["code"],
		"code_hash":      genResult.Output["code_hash"],
		"destination":    "user@example.com",
		"tenant_id":      "tenant-999",
		"purpose":        "login",
		"signing_secret": "test-secret",
		"expires_at":     genResult.Output["expires_at"],
		"attempts":       0,
		"max_attempts":   3,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if result.Output["valid"] != false {
		t.Fatal("expected valid=false when tenant_id differs")
	}

	result, err = verifyStep.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"code":           genResult.Output["code"],
		"code_hash":      genResult.Output["code_hash"],
		"destination":    "user@example.com",
		"tenant_id":      "tenant-123",
		"purpose":        "signup",
		"signing_secret": "test-secret",
		"expires_at":     genResult.Output["expires_at"],
		"attempts":       0,
		"max_attempts":   3,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}
	if result.Output["valid"] != false {
		t.Fatal("expected valid=false when purpose differs")
	}
}

func TestChallengeVerify_ReturnsFalseForWrongCode(t *testing.T) {
	genStep := newChallengeGenerateStep("generate", nil)
	genResult, err := genStep.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"destination":    "user@example.com",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "test-secret",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected generate error: %v", err)
	}

	verifyStep := newChallengeVerifyStep("verify", nil)
	result, err := verifyStep.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"code":           "000000",
		"code_hash":      genResult.Output["code_hash"],
		"destination":    "user@example.com",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "test-secret",
		"expires_at":     genResult.Output["expires_at"],
		"attempts":       0,
		"max_attempts":   3,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected verify error: %v", err)
	}

	if result.Output["valid"] != false {
		t.Fatal("expected valid=false for wrong code")
	}
}

func TestChallengeVerify_ReturnsFalseForExpiredChallenge(t *testing.T) {
	codeHash := hashChallengeCode("email", "user@example.com", "tenant-123", "login", "123456", "test-secret")
	step := newChallengeVerifyStep("verify", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"code":           "123456",
		"code_hash":      codeHash,
		"destination":    "user@example.com",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "test-secret",
		"expires_at":     time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339),
		"attempts":       0,
		"max_attempts":   3,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["valid"] != false {
		t.Fatal("expected valid=false for expired challenge")
	}
}

func TestChallengeVerify_ReturnsFalseWhenAttemptsExhausted(t *testing.T) {
	codeHash := hashChallengeCode("email", "user@example.com", "tenant-123", "login", "123456", "test-secret")
	step := newChallengeVerifyStep("verify", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"channel":        "email",
		"code":           "123456",
		"code_hash":      codeHash,
		"destination":    "user@example.com",
		"tenant_id":      "tenant-123",
		"purpose":        "login",
		"signing_secret": "test-secret",
		"expires_at":     time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339),
		"attempts":       3,
		"max_attempts":   3,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["valid"] != false {
		t.Fatal("expected valid=false when attempts are exhausted")
	}
	if _, ok := result.Output["error"].(string); !ok {
		t.Fatal("expected error string when attempts are exhausted")
	}
}
