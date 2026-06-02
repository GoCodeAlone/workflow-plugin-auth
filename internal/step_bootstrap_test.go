package internal

import (
	"context"
	"testing"
)

func TestBootstrapRedeem_OpenAndValid(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "super-secret-bootstrap-code-001")
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "admin@example.com"})
	current := map[string]any{"code": "super-secret-bootstrap-code-001", "existing_admin_count": float64(0)}
	res, err := s.Execute(context.Background(), nil, nil, current, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := res.Output
	if out["redeemed"] != true {
		t.Fatalf("want redeemed=true, got %v (reason=%v)", out["redeemed"], out["reason"])
	}
	if out["email"] != "admin@example.com" || out["role"] != "super_admin" {
		t.Fatalf("bad principal: %v / %v", out["email"], out["role"])
	}
}

func TestBootstrapRedeem_ClosedWhenCredentialsExist(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "super-secret-bootstrap-code-001")
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "admin@example.com"})
	// count > 0 → closed, even with the correct code
	current := map[string]any{"code": "super-secret-bootstrap-code-001", "existing_admin_count": float64(1)}
	res, err := s.Execute(context.Background(), nil, nil, current, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := res.Output
	if out["redeemed"] != false || out["reason"] != "bootstrap_closed" {
		t.Fatalf("want closed, got redeemed=%v reason=%v", out["redeemed"], out["reason"])
	}
}

func TestBootstrapRedeem_DefaultDenyMissingCount(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "super-secret-bootstrap-code-001")
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "admin@example.com"})
	current := map[string]any{"code": "super-secret-bootstrap-code-001"} // no count
	res, err := s.Execute(context.Background(), nil, nil, current, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := res.Output
	if out["redeemed"] != false || out["reason"] != "bootstrap_closed" {
		t.Fatalf("want default-deny closed, got %v / %v", out["redeemed"], out["reason"])
	}
}

func TestBootstrapRedeem_InvalidCode(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "super-secret-bootstrap-code-001")
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "admin@example.com"})
	current := map[string]any{"code": "wrong", "existing_admin_count": float64(0)}
	res, err := s.Execute(context.Background(), nil, nil, current, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := res.Output
	if out["redeemed"] != false || out["reason"] != "invalid_code" {
		t.Fatalf("want invalid_code, got %v / %v", out["redeemed"], out["reason"])
	}
}

func TestBootstrapRedeem_NotConfiguredShortCode(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "short") // < 16
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "admin@example.com"})
	current := map[string]any{"code": "short", "existing_admin_count": float64(0)}
	res, err := s.Execute(context.Background(), nil, nil, current, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	out := res.Output
	if out["redeemed"] != false || out["reason"] != "not_configured" {
		t.Fatalf("want not_configured, got %v / %v", out["redeemed"], out["reason"])
	}
}

func TestBootstrapRedeem_CountCoercion(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "super-secret-bootstrap-code-001")
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "a@b.com"})
	for _, c := range []any{0, int64(0), float64(0), "0"} {
		current := map[string]any{"code": "super-secret-bootstrap-code-001", "existing_admin_count": c}
		res, err := s.Execute(context.Background(), nil, nil, current, nil, nil)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		out := res.Output
		if out["redeemed"] != true {
			t.Fatalf("count %T(%v) should coerce to 0 → open; got reason=%v", c, c, out["reason"])
		}
	}
}

// Non-zero / fractional / uncoercible counts must NEVER open bootstrap (V-B1 "exactly 0").
func TestBootstrapRedeem_CountClosedOrDenied(t *testing.T) {
	t.Setenv("AUTH_BOOTSTRAP_CODE", "super-secret-bootstrap-code-001")
	s := newBootstrapRedeemStep("t", map[string]any{"super_admin_email": "a@b.com"})
	for _, c := range []any{1, int64(2), float64(1), float64(0.9), float64(-0.5), int(-1), "1", "notanumber", nil, []any{}} {
		current := map[string]any{"code": "super-secret-bootstrap-code-001", "existing_admin_count": c}
		res, err := s.Execute(context.Background(), nil, nil, current, nil, nil)
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		out := res.Output
		if out["redeemed"] != false || out["reason"] != "bootstrap_closed" {
			t.Fatalf("count %T(%v) must NOT open bootstrap; got redeemed=%v reason=%v", c, c, out["redeemed"], out["reason"])
		}
	}
}
