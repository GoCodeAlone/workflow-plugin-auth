package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
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

func TestParsePasskeyCredentials_AcceptsBase64URLCredentialID(t *testing.T) {
	credentialID := []byte{0xfb, 0xff, 0xee, 0x01, 0x02}
	credentialsJSON := `[{` +
		`"id":"` + base64.RawURLEncoding.EncodeToString(credentialID) + `",` +
		`"publicKey":"` + base64.StdEncoding.EncodeToString([]byte("public-key")) + `",` +
		`"authenticator":{` +
		`"AAGUID":"` + base64.StdEncoding.EncodeToString([]byte("authenticator-id")) + `",` +
		`"signCount":42,` +
		`"cloneWarning":true` +
		`}}]`

	credentials, err := parsePasskeyCredentials(credentialsJSON)
	if err != nil {
		t.Fatalf("parsePasskeyCredentials returned error: %v", err)
	}
	if len(credentials) != 1 {
		t.Fatalf("len(credentials) = %d, want 1", len(credentials))
	}
	if !bytes.Equal(credentials[0].ID, credentialID) {
		t.Fatalf("credential ID = %x, want %x", credentials[0].ID, credentialID)
	}
	if got, want := credentials[0].Authenticator.SignCount, uint32(42); got != want {
		t.Fatalf("sign count = %d, want %d", got, want)
	}
	if !credentials[0].Authenticator.CloneWarning {
		t.Fatal("clone warning = false, want true")
	}
}

func TestParsePasskeyCredentials_AcceptsStandardBase64CredentialID(t *testing.T) {
	credentialID := []byte{0xfb, 0xff, 0xee, 0x01, 0x02}
	credentialsJSON := `[{` +
		`"id":"` + base64.StdEncoding.EncodeToString(credentialID) + `",` +
		`"publicKey":"` + base64.StdEncoding.EncodeToString([]byte("public-key")) + `",` +
		`"authenticator":{"signCount":7}` +
		`}]`

	credentials, err := parsePasskeyCredentials(credentialsJSON)
	if err != nil {
		t.Fatalf("parsePasskeyCredentials returned error: %v", err)
	}
	if len(credentials) != 1 {
		t.Fatalf("len(credentials) = %d, want 1", len(credentials))
	}
	if !bytes.Equal(credentials[0].ID, credentialID) {
		t.Fatalf("credential ID = %x, want %x", credentials[0].ID, credentialID)
	}
}

func TestParsePasskeyCredentials_RejectsInvalidCredentialID(t *testing.T) {
	_, err := parsePasskeyCredentials(`[{"id":"not valid base64","publicKey":"` + base64.StdEncoding.EncodeToString([]byte("public-key")) + `"}]`)
	if err == nil {
		t.Fatal("expected invalid credential ID error")
	}
	if !strings.Contains(err.Error(), "credential 0 id") {
		t.Fatalf("error = %q, want credential id context", err.Error())
	}
}
