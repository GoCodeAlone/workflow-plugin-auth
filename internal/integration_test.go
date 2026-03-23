package internal_test

import (
	"testing"

	authplugin "github.com/GoCodeAlone/workflow-plugin-auth/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"github.com/GoCodeAlone/workflow/wftest"
)

func TestIntegration_TOTPGenerateAndVerifyPipeline(t *testing.T) {
	genRec := wftest.RecordStep("step.auth_totp_generate_secret")
	verRec := wftest.RecordStep("step.auth_totp_verify")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  totp-flow:
    steps:
      - name: generate
        type: step.auth_totp_generate_secret
        config:
          module: auth
          user_id_key: user_id
      - name: verify
        type: step.auth_totp_verify
        config:
          module: auth
          user_id_key: user_id
          code_key: totp_code
`),
		genRec.WithOutput(map[string]any{
			"totp_secret":    "JBSWY3DPEHPK3PXP",
			"qr_uri":         "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP",
			"setup_complete": false,
		}),
		verRec.WithOutput(map[string]any{"verified": true}),
	)

	result := h.ExecutePipeline("totp-flow", map[string]any{
		"user_id":   "user-abc",
		"totp_code": "123456",
	})
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if genRec.CallCount() != 1 {
		t.Errorf("expected generate called once, got %d", genRec.CallCount())
	}
	if verRec.CallCount() != 1 {
		t.Errorf("expected verify called once, got %d", verRec.CallCount())
	}
	if result.StepResults["verify"]["verified"] != true {
		t.Errorf("expected verified=true, got %v", result.StepResults["verify"]["verified"])
	}
}

func TestIntegration_MagicLinkPipeline(t *testing.T) {
	genRec := wftest.RecordStep("step.auth_magic_link_generate")
	sendRec := wftest.RecordStep("step.auth_magic_link_send")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  magic-link:
    steps:
      - name: generate
        type: step.auth_magic_link_generate
        config:
          module: auth
          email_key: email
      - name: send
        type: step.auth_magic_link_send
        config:
          module: auth
          email_key: email
`),
		genRec.WithOutput(map[string]any{"token": "tok_abc123", "expires_at": "2026-04-01T00:00:00Z"}),
		sendRec.WithOutput(map[string]any{"sent": true}),
	)

	result := h.ExecutePipeline("magic-link", map[string]any{"email": "user@example.com"})
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if genRec.CallCount() != 1 {
		t.Errorf("expected generate called once, got %d", genRec.CallCount())
	}
	if result.StepResults["generate"]["token"] != "tok_abc123" {
		t.Errorf("expected token=tok_abc123, got %v", result.StepResults["generate"]["token"])
	}
}

func TestIntegration_CredentialListPipeline(t *testing.T) {
	rec := wftest.RecordStep("step.auth_credential_list")
	h := wftest.New(t,
		wftest.WithYAML(`
pipelines:
  list-creds:
    steps:
      - name: list
        type: step.auth_credential_list
        config:
          module: auth
          user_id_key: user_id
`),
		rec.WithOutput(map[string]any{
			"credentials": []any{
				map[string]any{"id": "cred-1", "type": "passkey"},
				map[string]any{"id": "cred-2", "type": "totp"},
			},
			"count": 2,
		}),
	)

	result := h.ExecutePipeline("list-creds", map[string]any{"user_id": "user-xyz"})
	if result.Error != nil {
		t.Fatalf("pipeline error: %v", result.Error)
	}
	if result.StepResults["list"]["count"] != 2 {
		t.Errorf("expected count=2, got %v", result.StepResults["list"]["count"])
	}
}

func TestIntegration_PluginManifestAndStepTypes(t *testing.T) {
	p := authplugin.NewAuthPlugin()
	m := p.Manifest()
	if m.Name != "workflow-plugin-auth" {
		t.Errorf("unexpected plugin name: %s", m.Name)
	}

	sp, ok := p.(sdk.StepProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.StepProvider")
	}

	if len(sp.StepTypes()) == 0 {
		t.Error("expected at least one step type")
	}

	// Verify each step type can be instantiated.
	for _, st := range sp.StepTypes() {
		if _, err := sp.CreateStep(st, "test", map[string]any{}); err != nil {
			t.Errorf("CreateStep(%q) failed: %v", st, err)
		}
	}
}
