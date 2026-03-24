package internal_test

import (
	"testing"

	"github.com/GoCodeAlone/workflow/wftest"
)

func TestWFTest_TOTPRecoveryCodesPipeline(t *testing.T) {
	rec := wftest.RecordStep("step.auth_totp_recovery_codes")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  totp-recovery:
    steps:
      - name: gen_codes
        type: step.auth_totp_recovery_codes
        config:
          module: auth
`),
		rec.WithOutput(map[string]any{
			"codes": []any{"abc12", "def34", "ghi56", "jkl78", "mno90", "pqr12", "stu34", "uvw56"},
			"count": 8,
		}),
	)

	result := h.ExecutePipeline("totp-recovery", map[string]any{"user_id": "user-abc"})
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if rec.CallCount() != 1 {
		t.Errorf("expected auth_totp_recovery_codes called once, got %d", rec.CallCount())
	}
	if result.StepResults["gen_codes"]["count"] != 8 {
		t.Errorf("expected count=8, got %v", result.StepResults["gen_codes"]["count"])
	}
}

func TestWFTest_MagicLinkVerifyPipeline(t *testing.T) {
	rec := wftest.RecordStep("step.auth_magic_link_verify")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  magic-link-verify:
    steps:
      - name: verify
        type: step.auth_magic_link_verify
        config:
          module: auth
`),
		rec.WithOutput(map[string]any{
			"valid":  true,
			"email":  "user@example.com",
			"claims": map[string]any{"sub": "user-123"},
		}),
	)

	result := h.ExecutePipeline("magic-link-verify", map[string]any{"token": "tok_abc123"})
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if rec.CallCount() != 1 {
		t.Errorf("expected auth_magic_link_verify called once, got %d", rec.CallCount())
	}
	if result.StepResults["verify"]["valid"] != true {
		t.Errorf("expected valid=true, got %v", result.StepResults["verify"]["valid"])
	}
}

func TestWFTest_CredentialRevokePipeline(t *testing.T) {
	rec := wftest.RecordStep("step.auth_credential_revoke")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  credential-revoke:
    steps:
      - name: revoke
        type: step.auth_credential_revoke
        config:
          module: auth
`),
		rec.WithOutput(map[string]any{"revoked": true}),
	)

	result := h.ExecutePipeline("credential-revoke", map[string]any{
		"user_id":       "user-xyz",
		"credential_id": "cred-1",
	})
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if rec.CallCount() != 1 {
		t.Errorf("expected auth_credential_revoke called once, got %d", rec.CallCount())
	}
	if result.StepResults["revoke"]["revoked"] != true {
		t.Errorf("expected revoked=true, got %v", result.StepResults["revoke"]["revoked"])
	}
}

func TestWFTest_PasskeyRegisterFlowPipeline(t *testing.T) {
	beginRec := wftest.RecordStep("step.auth_passkey_begin_register")
	finishRec := wftest.RecordStep("step.auth_passkey_finish_register")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  passkey-register:
    steps:
      - name: begin
        type: step.auth_passkey_begin_register
        config:
          module: auth
      - name: finish
        type: step.auth_passkey_finish_register
        config:
          module: auth
`),
		beginRec.WithOutput(map[string]any{
			"options":  map[string]any{"challenge": "abc123"},
			"session":  "session-data",
			"complete": false,
		}),
		finishRec.WithOutput(map[string]any{
			"credential_id": "cred-new-1",
			"registered":    true,
		}),
	)

	result := h.ExecutePipeline("passkey-register", map[string]any{
		"user_id":      "user-123",
		"email":        "user@example.com",
		"display_name": "Test User",
	})
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if beginRec.CallCount() != 1 {
		t.Errorf("expected passkey_begin_register called once, got %d", beginRec.CallCount())
	}
	if finishRec.CallCount() != 1 {
		t.Errorf("expected passkey_finish_register called once, got %d", finishRec.CallCount())
	}
	if result.StepResults["finish"]["registered"] != true {
		t.Errorf("expected registered=true, got %v", result.StepResults["finish"]["registered"])
	}
}

func TestWFTest_PasskeyLoginFlowPipeline(t *testing.T) {
	beginRec := wftest.RecordStep("step.auth_passkey_begin_login")
	finishRec := wftest.RecordStep("step.auth_passkey_finish_login")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  passkey-login:
    steps:
      - name: begin
        type: step.auth_passkey_begin_login
        config:
          module: auth
      - name: finish
        type: step.auth_passkey_finish_login
        config:
          module: auth
`),
		beginRec.WithOutput(map[string]any{
			"options": map[string]any{"challenge": "xyz789"},
			"session": "session-data-login",
		}),
		finishRec.WithOutput(map[string]any{
			"user_id":       "user-123",
			"credential_id": "cred-1",
			"authenticated": true,
		}),
	)

	result := h.ExecutePipeline("passkey-login", map[string]any{
		"user_id": "user-123",
	})
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if beginRec.CallCount() != 1 {
		t.Errorf("expected passkey_begin_login called once, got %d", beginRec.CallCount())
	}
	if finishRec.CallCount() != 1 {
		t.Errorf("expected passkey_finish_login called once, got %d", finishRec.CallCount())
	}
	if result.StepResults["finish"]["authenticated"] != true {
		t.Errorf("expected authenticated=true, got %v", result.StepResults["finish"]["authenticated"])
	}
}
