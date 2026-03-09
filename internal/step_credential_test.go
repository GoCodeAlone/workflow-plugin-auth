package internal

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCredentialList_Empty(t *testing.T) {
	step := newCredentialListStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count, _ := result.Output["count"].(int)
	if count != 0 {
		t.Fatalf("expected 0 credentials, got %d", count)
	}
}

func TestCredentialList_SanitizesFields(t *testing.T) {
	creds := []map[string]any{
		{
			"id":           "cred-1",
			"type":         "passkey",
			"device_name":  "My Phone",
			"created_at":   "2026-01-01T00:00:00Z",
			"last_used_at": "2026-03-01T00:00:00Z",
			"public_key":   "SENSITIVE_KEY_DATA",
			"totp_secret":  "SENSITIVE_SECRET",
		},
	}
	credJSON, _ := json.Marshal(creds)

	step := newCredentialListStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"credentials_json": string(credJSON),
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	count, _ := result.Output["count"].(int)
	if count != 1 {
		t.Fatalf("expected 1 credential, got %d", count)
	}
	sanitized := result.Output["credentials"].([]map[string]any)
	if _, exists := sanitized[0]["public_key"]; exists {
		t.Fatal("expected public_key to be stripped")
	}
	if _, exists := sanitized[0]["totp_secret"]; exists {
		t.Fatal("expected totp_secret to be stripped")
	}
}

func TestCredentialRevoke_Authorized(t *testing.T) {
	step := newCredentialRevokeStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"credential_id": "cred-1",
		"owner_user_id": "user-123",
		"user_id":       "user-123",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["authorized"] != true {
		t.Fatal("expected authorized=true")
	}
}

func TestCredentialRevoke_Unauthorized(t *testing.T) {
	step := newCredentialRevokeStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"credential_id": "cred-1",
		"owner_user_id": "user-123",
		"user_id":       "user-456",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["authorized"] != false {
		t.Fatal("expected authorized=false for different user")
	}
}

func TestCredentialRevoke_MissingID(t *testing.T) {
	step := newCredentialRevokeStep("test", nil)
	result, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Output["authorized"] != false {
		t.Fatal("expected authorized=false for missing credential_id")
	}
}
