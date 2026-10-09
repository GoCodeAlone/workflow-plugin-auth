package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-auth/agentidentity"
)

const syntheticLeak = "postgres://synthetic-secret@example.invalid/db Bearer synthetic-token -----BEGIN PRIVATE KEY-----"

var driverOpens atomic.Int64
var driverCalls atomic.Int64

type failingDriver struct{}
type failingConn struct{}

func (failingDriver) Open(string) (driver.Conn, error) {
	driverOpens.Add(1)
	return failingConn{}, nil
}
func (failingConn) Prepare(string) (driver.Stmt, error) {
	driverCalls.Add(1)
	return nil, errors.New(syntheticLeak)
}
func (failingConn) Close() error { return nil }
func (failingConn) Begin() (driver.Tx, error) {
	driverCalls.Add(1)
	return nil, errors.New(syntheticLeak)
}
func (failingConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	driverCalls.Add(1)
	return nil, errors.New(syntheticLeak)
}

func init() { sql.Register("agentidentity-postgres-redaction-fixture", failingDriver{}) }

func fixtureGrant(t *testing.T, id string, tenant int64) agentidentity.Grant {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("synthetic public-key fixture failed")
	}
	now := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Second)
	return agentidentity.Grant{
		ID: id, Subject: "synthetic-agent", AssertionIssuer: "https://agent.example.test",
		KeyID: "synthetic-kid", PublicKey: &key.PublicKey, Version: 1, TenantID: tenant,
		ApprovedBy: "synthetic-owner", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		APIAudience:   "https://cms.example.test",
		Scopes:        []string{agentidentity.PagesRead, agentidentity.HistoryRead, agentidentity.PagesUpdate, agentidentity.PreviewRead},
		UpdatePageIDs: []string{"10"},
		Preview:       &agentidentity.PreviewGrant{Audience: "https://preview.example.test/audience", Origin: "https://preview.example.test", Paths: []string{"/", "/teaching"}},
	}
}

func fixtureHash(label string) string {
	h := sha256.Sum256([]byte("synthetic-fixture:" + label))
	return hex.EncodeToString(h[:])
}

func TestConstructorHasNoIOAndValidatesNamespace(t *testing.T) {
	db, err := sql.Open("agentidentity-postgres-redaction-fixture", "synthetic-unused")
	if err != nil {
		t.Fatal("driver fixture unavailable")
	}
	defer db.Close()
	before := driverOpens.Load()
	for _, schema := range []string{"agent_identity", "a", strings.Repeat("a", 63)} {
		store, err := New(db, schema)
		if err != nil || store.schema != schema {
			t.Fatal("valid namespace refused")
		}
	}
	for _, schema := range []string{"", "public;drop schema public", "a.b", `a"b`, "MixedCase", "1first", strings.Repeat("a", 64), "a\n"} {
		if _, err := New(db, schema); err != agentidentity.ErrUnavailable {
			t.Fatal("unsafe namespace accepted")
		}
	}
	if _, err := New(nil, "agent_identity"); err != agentidentity.ErrUnavailable {
		t.Fatal("nil database accepted")
	}
	if driverOpens.Load() != before {
		t.Fatal("constructor performed database I/O")
	}
}

func TestDatabaseFailuresReturnOnlyFixedPublicErrors(t *testing.T) {
	db, err := sql.Open("agentidentity-postgres-redaction-fixture", "synthetic-unused")
	if err != nil {
		t.Fatal("driver fixture unavailable")
	}
	defer db.Close()
	s, err := New(db, "agent_fixture")
	if err != nil {
		t.Fatal("constructor failed")
	}
	ctx := context.Background()
	g := fixtureGrant(t, "fixture-grant", 501)
	now := time.Now().UTC()
	checks := []struct {
		name string
		run  func() error
	}{
		{"get", func() error { _, err := s.GetGrant(ctx, g.ID); return err }},
		{"list", func() error { _, err := s.ListGrants(ctx, agentidentity.Owner{ID: "owner"}); return err }},
		{"create", func() error { return s.CreateGrant(ctx, g) }},
		{"revoke", func() error { return s.RevokeGrant(ctx, g.ID, 1, "owner", now) }},
		{"consume", func() error {
			_, err := s.ConsumeAssertion(ctx, agentidentity.AssertionUse{GrantID: g.ID, GrantVersion: 1, JTIHash: fixtureHash("assertion"), Now: now, ExpiresAt: now.Add(30 * time.Second)})
			return err
		}},
		{"read-revocation", func() error { _, err := s.IsTokenRevoked(ctx, fixtureHash("token")); return err }},
		{"revoke-token", func() error { return s.RevokeToken(ctx, fixtureHash("token"), "owner", now, now.Add(time.Minute)) }},
		{"audit", func() error {
			return s.Record(ctx, agentidentity.Audit{At: now, Operation: "access", Decision: "deny", Reason: "denied"})
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); err != agentidentity.ErrUnavailable || strings.Contains(err.Error(), syntheticLeak) {
				t.Fatal("database error was not redacted to fixed unavailable")
			}
		})
	}
}

func TestInvalidInputsAndUnboundedAuditNeverReachDatabase(t *testing.T) {
	db, err := sql.Open("agentidentity-postgres-redaction-fixture", "synthetic-unused")
	if err != nil {
		t.Fatal("driver fixture unavailable")
	}
	defer db.Close()
	s, _ := New(db, "agent_fixture")
	ctx := context.Background()
	before := driverCalls.Load()
	g := fixtureGrant(t, "fixture-grant", 501)
	g.Version = 2
	if s.CreateGrant(ctx, g) != agentidentity.ErrDenied {
		t.Fatal("create did not enforce initial version")
	}
	g.Version, g.Revoked = 1, true
	if s.CreateGrant(ctx, g) != agentidentity.ErrDenied {
		t.Fatal("revoked create accepted")
	}
	if _, err := s.GetGrant(ctx, "bad/id"); err != agentidentity.ErrDenied {
		t.Fatal("invalid grant ID accepted")
	}
	if _, err := s.ListGrants(ctx, agentidentity.Owner{}); err != agentidentity.ErrDenied {
		t.Fatal("missing owner accepted")
	}
	if s.RevokeGrant(ctx, "fixture-grant", 0, "owner", time.Now()) != agentidentity.ErrDenied {
		t.Fatal("missing expected version accepted")
	}
	if _, err := s.IsTokenRevoked(ctx, syntheticLeak); err != agentidentity.ErrDenied {
		t.Fatal("raw token accepted as a hash")
	}
	if s.RevokeToken(ctx, fixtureHash("token"), "owner", time.Now(), time.Now().Add(time.Hour)) != agentidentity.ErrDenied {
		t.Fatal("overlong token lifetime accepted")
	}
	base := agentidentity.Audit{At: time.Now(), Operation: "access", Decision: "deny", Reason: "denied"}
	for _, mutate := range []func(*agentidentity.Audit){
		func(a *agentidentity.Audit) { a.Reason = syntheticLeak },
		func(a *agentidentity.Audit) { a.Operation = syntheticLeak },
		func(a *agentidentity.Audit) { a.Subject = syntheticLeak },
		func(a *agentidentity.Audit) { a.OwnerID = "owner@example.test" },
		func(a *agentidentity.Audit) { a.Scope = "admin:*" },
		func(a *agentidentity.Audit) { a.JTIHash = syntheticLeak },
		func(a *agentidentity.Audit) { a.PageID = "18446744073709551616" },
		func(a *agentidentity.Audit) { a.PageID = "01" },
	} {
		a := base
		mutate(&a)
		if s.Record(ctx, a) != agentidentity.ErrDenied {
			t.Fatal("unbounded audit metadata accepted")
		}
	}
	if driverCalls.Load() != before {
		t.Fatal("invalid input reached database")
	}
}
