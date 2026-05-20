package internal

import (
	"context"
	"testing"
)

// TestPasswordSteps_DisableViaCredentialModule verifies that a
// credentialModule with `disable_password_auth: true` short-circuits
// both password steps. Mirrors gocodealone-multisite SPEC V17 / T-AUTH-1.
func TestPasswordSteps_DisableViaCredentialModule(t *testing.T) {
	// Register a credential module with disable_password_auth = true.
	// Note: bypassing newCredentialModule's Init() (which requires
	// rpID/origin) — we only need disable flag set + module in registry.
	m := &credentialModule{name: "test", disablePasswordAuth: true}
	registerModule(m.name, m)
	t.Cleanup(func() { unregisterModule(m.name) })

	if !passwordAuthDisabled() {
		t.Fatal("passwordAuthDisabled should return true after register")
	}

	// hash step short-circuits.
	hash := newPasswordHashStep("hash", nil)
	res, err := hash.Execute(context.Background(), nil, nil, map[string]any{"password": "secret"}, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if disabled, _ := res.Output["disabled"].(bool); !disabled {
		t.Errorf("expected disabled=true, got %v", res.Output)
	}
	if _, ok := res.Output["hash"]; ok {
		t.Errorf("hash output should NOT include `hash` when disabled")
	}

	// verify step short-circuits.
	verify := newPasswordVerifyStep("verify", nil)
	res, err = verify.Execute(context.Background(), nil, nil, map[string]any{"password": "x", "hash": "y"}, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if disabled, _ := res.Output["disabled"].(bool); !disabled {
		t.Errorf("verify: expected disabled=true, got %v", res.Output)
	}
	if valid, _ := res.Output["valid"].(bool); valid {
		t.Error("verify: should not report valid=true when disabled")
	}
}

func TestPasswordSteps_EnabledByDefault(t *testing.T) {
	// No modules registered with disable → password steps work normally.
	// Ensure clean registry state.
	if passwordAuthDisabled() {
		t.Skip("registry has a disabled module from prior test ordering")
	}

	hash := newPasswordHashStep("hash", nil)
	res, err := hash.Execute(context.Background(), nil, nil, map[string]any{"password": "secret"}, nil, nil)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if _, ok := res.Output["hash"]; !ok {
		t.Errorf("expected hash output, got %v", res.Output)
	}
}

func TestNewCredentialModule_DisableFlagParsed(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]any
		want bool
	}{
		{"absent", map[string]any{}, false},
		{"bool true", map[string]any{"disable_password_auth": true}, true},
		{"bool false", map[string]any{"disable_password_auth": false}, false},
		{"string true", map[string]any{"disable_password_auth": "true"}, true},
		{"string false", map[string]any{"disable_password_auth": "false"}, false},
		{"string TRUE mixed case", map[string]any{"disable_password_auth": "TRUE"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := newCredentialModule("test", tc.cfg)
			if err != nil {
				t.Fatalf("newCredentialModule: %v", err)
			}
			if m.disablePasswordAuth != tc.want {
				t.Errorf("disablePasswordAuth: got %v want %v", m.disablePasswordAuth, tc.want)
			}
		})
	}
}

func TestPasswordAuthDisabled_AnyModuleSetsFlag(t *testing.T) {
	// Two modules, one with disable, one without → disabled=true overall.
	m1 := &credentialModule{name: "a", disablePasswordAuth: false}
	m2 := &credentialModule{name: "b", disablePasswordAuth: true}
	registerModule(m1.name, m1)
	registerModule(m2.name, m2)
	t.Cleanup(func() {
		unregisterModule(m1.name)
		unregisterModule(m2.name)
	})

	if !passwordAuthDisabled() {
		t.Error("expected disabled=true when ANY module has flag set")
	}
}
