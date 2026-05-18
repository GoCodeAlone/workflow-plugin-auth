package internal

import "testing"

func TestCredentialModuleInitMissingConfigStrictByDefault(t *testing.T) {
	mod, err := newCredentialModule("missing-strict", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if err := mod.Init(); err == nil {
		t.Fatal("expected missing rpID/origin config to fail by default")
	}
	if getModule("missing-strict") != nil {
		t.Fatal("expected missing strict module not to register")
	}
}

func TestCredentialModuleInitOptionalMissingConfigDoesNotRegister(t *testing.T) {
	mod, err := newCredentialModule("missing-optional", map[string]any{
		"optional": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mod.Init(); err != nil {
		t.Fatalf("expected optional missing config to initialize, got %v", err)
	}
	if getModule("missing-optional") != nil {
		t.Fatal("expected optional missing module not to register")
	}
}

func TestCredentialModuleInitWithOriginRegisters(t *testing.T) {
	mod, err := newCredentialModule("configured-origin", map[string]any{
		"origin": "https://example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mod.Init(); err != nil {
		t.Fatalf("expected origin-only config to initialize, got %v", err)
	}
	if getModule("configured-origin") == nil {
		t.Fatal("expected configured module to register")
	}
	unregisterModule("configured-origin")
}

func TestCredentialModuleInitTypedSnakeCaseConfigRegisters(t *testing.T) {
	mod, err := newCredentialModule("configured-typed", map[string]any{
		"optional":        true,
		"rp_display_name": "Typed App",
		"rp_id":           "example.com",
		"origin":          "https://example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mod.Init(); err != nil {
		t.Fatalf("expected typed snake_case config to initialize, got %v", err)
	}
	if getModule("configured-typed") == nil {
		t.Fatal("expected typed configured module to register")
	}
	unregisterModule("configured-typed")
}

func TestCredentialModuleInitOptionalOriginOnlyDerivesRPID(t *testing.T) {
	mod, err := newCredentialModule("configured-optional-origin", map[string]any{
		"optional": true,
		"origin":   "https://example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mod.Init(); err != nil {
		t.Fatalf("expected optional origin-only config to initialize, got %v", err)
	}
	if getModule("configured-optional-origin") == nil {
		t.Fatal("expected optional origin-only module to register")
	}
	unregisterModule("configured-optional-origin")
}
