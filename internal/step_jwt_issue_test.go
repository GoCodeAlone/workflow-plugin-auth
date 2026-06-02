package internal

import (
	"context"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"google.golang.org/protobuf/types/known/structpb"
)

func mustExecJWT(t *testing.T, s *jwtIssueStep, current map[string]any) map[string]any {
	t.Helper()
	res, err := s.Execute(context.Background(), nil, nil, current, nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	return res.Output
}

func TestJWTIssue_SignsAndStandardClaimsWin(t *testing.T) {
	secret := "this-is-a-32-byte-minimum-secret-xx" // >=32
	t.Setenv("AUTH_JWT_SECRET", secret)
	s := newJWTIssueStep("t", map[string]any{"issuer": "wf-test", "ttl_seconds": int64(60)})
	out := mustExecJWT(t, s, map[string]any{
		"subject": "admin@example.com",
		"claims":  map[string]any{"roles": []any{"super_admin"}, "sub": "evil", "iss": "evil"},
	})
	tokStr, _ := out["token"].(string)
	if tokStr == "" {
		t.Fatalf("no token; error=%v", out["error"])
	}
	tok, err := jwt.Parse(tokStr, func(*jwt.Token) (any, error) { return []byte(secret), nil })
	if err != nil || !tok.Valid {
		t.Fatalf("token did not validate with shared secret: %v", err)
	}
	c := tok.Claims.(jwt.MapClaims)
	if c["sub"] != "admin@example.com" {
		t.Fatalf("caller overrode sub: %v (V-B8 violated)", c["sub"])
	}
	if c["iss"] != "wf-test" {
		t.Fatalf("caller overrode iss: %v", c["iss"])
	}
}

func TestJWTIssue_RejectsShortSecret(t *testing.T) {
	t.Setenv("AUTH_JWT_SECRET", "tooshort")
	s := newJWTIssueStep("t", nil)
	out := mustExecJWT(t, s, map[string]any{"subject": "x"})
	if out["token"] != "" && out["token"] != nil {
		t.Fatalf("expected no token for short secret")
	}
	if out["error"] == "" || out["error"] == nil {
		t.Fatalf("expected error for short secret")
	}
}

func TestJWTIssue_RejectsEmptySubject(t *testing.T) {
	t.Setenv("AUTH_JWT_SECRET", "this-is-a-32-byte-minimum-secret-xx")
	s := newJWTIssueStep("t", nil)
	for _, subj := range []any{"", "   ", nil} {
		out := mustExecJWT(t, s, map[string]any{"subject": subj})
		if tok, _ := out["token"].(string); tok != "" {
			t.Fatalf("subject %q minted a token; want none (no anonymous sub)", subj)
		}
		if out["error"] == "" || out["error"] == nil {
			t.Fatalf("subject %q: expected error, got none", subj)
		}
	}
}

func TestJWTIssue_CarriesCallerClaims(t *testing.T) {
	secret := "this-is-a-32-byte-minimum-secret-xx"
	t.Setenv("AUTH_JWT_SECRET", secret)
	s := newJWTIssueStep("t", map[string]any{"issuer": "wf-test", "ttl_seconds": int64(3600)})
	out := mustExecJWT(t, s, map[string]any{
		"subject": "user@example.com",
		"claims":  map[string]any{"roles": []any{"super_admin"}, "email": "user@example.com"},
	})
	tokStr, _ := out["token"].(string)
	if tokStr == "" {
		t.Fatalf("no token; error=%v", out["error"])
	}
	tok, err := jwt.Parse(tokStr, func(*jwt.Token) (any, error) { return []byte(secret), nil })
	if err != nil || !tok.Valid {
		t.Fatalf("token invalid: %v", err)
	}
	c := tok.Claims.(jwt.MapClaims)
	if c["jti"] == "" || c["jti"] == nil {
		t.Fatalf("jti missing from token claims")
	}
	if c["email"] != "user@example.com" {
		t.Fatalf("caller claim email missing: %v", c["email"])
	}
}

func TestJWTIssue_StructpbClaimsShape(t *testing.T) {
	secret := "this-is-a-32-byte-minimum-secret-xx"
	t.Setenv("AUTH_JWT_SECRET", secret)
	s := newJWTIssueStep("t", map[string]any{"issuer": "wf-test", "ttl_seconds": int64(3600)})

	// Build a structpb.Struct to simulate the typed-step path
	pb, err := structpb.NewStruct(map[string]any{"roles": []any{"admin"}, "sub": "evil"})
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}
	out := mustExecJWT(t, s, map[string]any{
		"subject": "struct-user@example.com",
		"claims":  pb,
	})
	tokStr, _ := out["token"].(string)
	if tokStr == "" {
		t.Fatalf("no token for structpb claims; error=%v", out["error"])
	}
	tok, err := jwt.Parse(tokStr, func(*jwt.Token) (any, error) { return []byte(secret), nil })
	if err != nil || !tok.Valid {
		t.Fatalf("token invalid: %v", err)
	}
	c := tok.Claims.(jwt.MapClaims)
	// sub must be overwritten to the subject, not "evil"
	if c["sub"] != "struct-user@example.com" {
		t.Fatalf("V-B8: structpb caller overrode sub: %v", c["sub"])
	}
}
