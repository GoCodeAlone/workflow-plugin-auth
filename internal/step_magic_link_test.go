package internal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestMagicLinkGenerate(t *testing.T) {
	step := newMagicLinkGenerateStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"email":          "test@example.com",
		"signing_secret": "test-secret-key",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	token, ok := result.Output["token"].(string)
	if !ok || token == "" {
		t.Fatal("expected non-empty token")
	}
	tokenHash, ok := result.Output["token_hash"].(string)
	if !ok || tokenHash == "" {
		t.Fatal("expected non-empty token_hash")
	}
	sig, ok := result.Output["signature"].(string)
	if !ok || sig == "" {
		t.Fatal("expected non-empty signature")
	}
	// Verify token_hash matches sha256(token)
	h := sha256.Sum256([]byte(token))
	expected := hex.EncodeToString(h[:])
	if tokenHash != expected {
		t.Fatalf("token_hash mismatch: got %s, want %s", tokenHash, expected)
	}
}

func TestMagicLinkGenerate_MissingData(t *testing.T) {
	step := newMagicLinkGenerateStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := result.Output["error"]; !ok {
		t.Fatal("expected error in output for missing data")
	}
}

func TestMagicLinkVerify_Valid(t *testing.T) {
	// Generate a token and hash
	token := "test-token-12345"
	h := sha256.Sum256([]byte(token))
	storedHash := hex.EncodeToString(h[:])
	expiresAt := time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339)

	step := newMagicLinkVerifyStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"token":       token,
		"stored_hash": storedHash,
		"expires_at":  expiresAt,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["valid"] != true {
		t.Fatal("expected valid=true for matching token")
	}
}

func TestMagicLinkVerify_Expired(t *testing.T) {
	token := "test-token-12345"
	h := sha256.Sum256([]byte(token))
	storedHash := hex.EncodeToString(h[:])
	expiresAt := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)

	step := newMagicLinkVerifyStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"token":       token,
		"stored_hash": storedHash,
		"expires_at":  expiresAt,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["valid"] != false {
		t.Fatal("expected valid=false for expired token")
	}
}

func TestMagicLinkVerify_WrongToken(t *testing.T) {
	h := sha256.Sum256([]byte("correct-token"))
	storedHash := hex.EncodeToString(h[:])

	step := newMagicLinkVerifyStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"token":       "wrong-token",
		"stored_hash": storedHash,
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["valid"] != false {
		t.Fatal("expected valid=false for wrong token")
	}
}

func TestMagicLinkVerify_MissingData(t *testing.T) {
	step := newMagicLinkVerifyStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["valid"] != false {
		t.Fatal("expected valid=false for missing data")
	}
}

func TestMagicLinkSend_DevMode(t *testing.T) {
	// No SMTP configured = dev mode
	step := newMagicLinkSendStep("test", map[string]any{})
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"to":             "test@example.com",
		"magic_link_url": "https://example.com/auth?token=abc",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["dev_mode"] != true {
		t.Fatal("expected dev_mode=true when no SMTP configured")
	}
}

func TestMagicLinkSend_MissingData(t *testing.T) {
	step := newMagicLinkSendStep("test", map[string]any{})
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["sent"] != false {
		t.Fatal("expected sent=false for missing data")
	}
}
