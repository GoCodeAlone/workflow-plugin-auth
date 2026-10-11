// Package postgres persists agentidentity service grants in a host-owned SQL
// schema. It never provisions a database, schema, issuer key or human identity.
package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-auth/agentidentity"
)

var namespace = regexp.MustCompile("^[a-z_][a-z0-9_]{0,62}$")
var identifier = regexp.MustCompile("^[A-Za-z0-9_.:-]{1,128}$")
var hash = regexp.MustCompile("^[0-9a-f]{64}$")

const maxList = 4096

// Store uses one shared schema for ALL tenant grants and replay identities.
// The caller owns connection security/pool lifecycle, migration and current
// human/tenant authorization. Schema is copied/validated; no search_path is used.
type Store struct {
	db     *sql.DB
	schema string
}

// New validates configuration only. It performs no I/O, Ping or DDL.
func New(db *sql.DB, schema string) (*Store, error) {
	if db == nil || !namespace.MatchString(schema) {
		return nil, agentidentity.ErrUnavailable
	}
	return &Store{db: db, schema: schema}, nil
}

func (s *Store) table(name string) string { return `"` + s.schema + `"."` + name + `"` }

const grantColumns = "id,subject,assertion_issuer,key_id,public_key_der,version,tenant_id,approved_by,created_at,expires_at,revoked,api_audience,scopes,update_page_ids,preview"

type scanner interface{ Scan(...any) error }

func scanGrant(row scanner) (agentidentity.Grant, error) {
	var g agentidentity.Grant
	var key, scopes, pages, preview []byte
	dest := []any{&g.ID, &g.Subject, &g.AssertionIssuer, &g.KeyID, &key, &g.Version, &g.TenantID, &g.ApprovedBy, &g.CreatedAt, &g.ExpiresAt, &g.Revoked, &g.APIAudience, &scopes, &pages, &preview}
	if err := row.Scan(dest...); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return g, agentidentity.ErrDenied
		}
		return g, agentidentity.ErrUnavailable
	}
	if len(key) > 512 || len(scopes) > 4096 || len(pages) > 4096 || len(preview) > 16384 {
		return agentidentity.Grant{}, agentidentity.ErrUnavailable
	}
	pk, err := x509.ParsePKIXPublicKey(key)
	if err != nil {
		return agentidentity.Grant{}, agentidentity.ErrUnavailable
	}
	public, ok := pk.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() {
		return agentidentity.Grant{}, agentidentity.ErrUnavailable
	}
	g.PublicKey = public
	if json.Unmarshal(scopes, &g.Scopes) != nil || json.Unmarshal(pages, &g.UpdatePageIDs) != nil {
		return agentidentity.Grant{}, agentidentity.ErrUnavailable
	}
	if len(preview) != 0 {
		if json.Unmarshal(preview, &g.Preview) != nil || g.Preview == nil {
			return agentidentity.Grant{}, agentidentity.ErrUnavailable
		}
	}
	g.CreatedAt, g.ExpiresAt = g.CreatedAt.UTC(), g.ExpiresAt.UTC()
	if agentidentity.ValidateGrantForStorage(g) != nil || len(g.UpdatePageIDs) > 128 || (g.Revoked && g.Version < 2) {
		return agentidentity.Grant{}, agentidentity.ErrUnavailable
	}
	return g, nil
}

func (s *Store) GetGrant(ctx context.Context, id string) (agentidentity.Grant, error) {
	if !identifier.MatchString(id) {
		return agentidentity.Grant{}, agentidentity.ErrDenied
	}
	return scanGrant(s.db.QueryRowContext(ctx, "SELECT "+grantColumns+" FROM "+s.table("agent_grants")+" WHERE id=$1", id))
}

// ListGrants is internal persistence, not an owner-authorized endpoint. The
// reusable management handler filters each row using CURRENT OwnerPolicy.
// Original ApprovedBy must not be used to infer today's tenant authority.
func (s *Store) ListGrants(ctx context.Context, owner agentidentity.Owner) ([]agentidentity.Grant, error) {
	if !identifier.MatchString(owner.ID) {
		return nil, agentidentity.ErrDenied
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+grantColumns+" FROM "+s.table("agent_grants")+" ORDER BY id LIMIT $1", maxList+1)
	if err != nil {
		return nil, agentidentity.ErrUnavailable
	}
	defer rows.Close()
	out := []agentidentity.Grant{}
	for rows.Next() {
		if len(out) == maxList {
			return nil, agentidentity.ErrUnavailable
		}
		g, err := scanGrant(rows)
		if err != nil {
			return nil, agentidentity.ErrUnavailable
		}
		out = append(out, g)
	}
	if rows.Err() != nil {
		return nil, agentidentity.ErrUnavailable
	}
	return out, nil
}

func sqlConflict(err error) bool {
	var e interface{ SQLState() string }
	return errors.As(err, &e) && e.SQLState() == "23505"
}

func (s *Store) CreateGrant(ctx context.Context, g agentidentity.Grant) error {
	if g.Version != 1 || g.Revoked || agentidentity.ValidateGrantForStorage(g) != nil || len(g.UpdatePageIDs) > 128 {
		return agentidentity.ErrDenied
	}
	key, err := x509.MarshalPKIXPublicKey(g.PublicKey)
	if err != nil {
		return agentidentity.ErrDenied
	}
	scopes, err := json.Marshal(g.Scopes)
	if err != nil {
		return agentidentity.ErrDenied
	}
	pages := g.UpdatePageIDs
	if pages == nil {
		pages = []string{}
	}
	pageJSON, err := json.Marshal(pages)
	if err != nil {
		return agentidentity.ErrDenied
	}
	var preview any
	if g.Preview != nil {
		b, err := json.Marshal(g.Preview)
		if err != nil || len(b) > 16384 {
			return agentidentity.ErrDenied
		}
		preview = b
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return agentidentity.ErrUnavailable
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "INSERT INTO "+s.table("agent_grants")+" ("+grantColumns+") SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15 WHERE $9::timestamptz<=clock_timestamp() AND $10::timestamptz>clock_timestamp()", g.ID, g.Subject, g.AssertionIssuer, g.KeyID, key, g.Version, g.TenantID, g.ApprovedBy, g.CreatedAt.UTC(), g.ExpiresAt.UTC(), false, g.APIAudience, scopes, pageJSON, preview)
	if err != nil {
		if sqlConflict(err) {
			return agentidentity.ErrConflict
		}
		return agentidentity.ErrUnavailable
	}
	n, err := result.RowsAffected()
	if err != nil {
		return agentidentity.ErrUnavailable
	}
	if n != 1 {
		return agentidentity.ErrDenied
	}
	event := agentidentity.Audit{At: g.CreatedAt.UTC(), Operation: "grant-create-committed", Decision: "allow", Reason: "committed", Subject: g.Subject, GrantID: g.ID, GrantVersion: g.Version, TenantID: g.TenantID, OwnerID: g.ApprovedBy}
	if s.appendAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		return agentidentity.ErrUnavailable
	}
	return nil
}

func (s *Store) RevokeGrant(ctx context.Context, id string, expectedVersion int64, actor string, at time.Time) error {
	if !identifier.MatchString(id) || !identifier.MatchString(actor) || expectedVersion <= 0 || expectedVersion == math.MaxInt64 || at.IsZero() {
		return agentidentity.ErrDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return agentidentity.ErrUnavailable
	}
	defer tx.Rollback()
	g, err := scanGrant(tx.QueryRowContext(ctx, "SELECT "+grantColumns+" FROM "+s.table("agent_grants")+" WHERE id=$1 FOR UPDATE", id))
	if errors.Is(err, agentidentity.ErrDenied) {
		return agentidentity.ErrConflict
	}
	if err != nil {
		return agentidentity.ErrUnavailable
	}
	if g.Revoked || g.Version != expectedVersion {
		return agentidentity.ErrConflict
	}
	if at.Before(g.CreatedAt) {
		return agentidentity.ErrDenied
	}
	result, err := tx.ExecContext(ctx, "UPDATE "+s.table("agent_grants")+" SET revoked=true,version=version+1,revoked_by=$3,revoked_at=$4 WHERE id=$1 AND version=$2 AND NOT revoked", id, expectedVersion, actor, at.UTC())
	if err != nil {
		return agentidentity.ErrUnavailable
	}
	n, err := result.RowsAffected()
	if err != nil {
		return agentidentity.ErrUnavailable
	}
	if n != 1 {
		return agentidentity.ErrConflict
	}
	event := agentidentity.Audit{At: at.UTC(), Operation: "grant-revoke-committed", Decision: "allow", Reason: "committed", Subject: g.Subject, GrantID: g.ID, GrantVersion: g.Version + 1, TenantID: g.TenantID, OwnerID: actor}
	if s.appendAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		return agentidentity.ErrUnavailable
	}
	return nil
}

// ConsumeAssertion serializes with grant revoke and atomically rechecks the
// current row. The DB clock also refuses expired state if a caller clock lags.
// One bound JTIHash is consumed globally, never by grant/version partition.
func (s *Store) ConsumeAssertion(ctx context.Context, use agentidentity.AssertionUse) (bool, error) {
	if !identifier.MatchString(use.GrantID) || use.GrantVersion <= 0 || !hash.MatchString(use.JTIHash) || use.Now.IsZero() || !use.ExpiresAt.After(use.Now) || use.ExpiresAt.Sub(use.Now) > agentidentity.MaxAssertionLifetime {
		return false, agentidentity.ErrDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, agentidentity.ErrUnavailable
	}
	defer tx.Rollback()
	g, err := scanGrant(tx.QueryRowContext(ctx, "SELECT "+grantColumns+" FROM "+s.table("agent_grants")+" WHERE id=$1 FOR UPDATE", use.GrantID))
	if errors.Is(err, agentidentity.ErrDenied) {
		return false, nil
	}
	if err != nil {
		return false, agentidentity.ErrUnavailable
	}
	if g.Revoked || g.Version != use.GrantVersion || g.CreatedAt.After(use.Now) || !g.ExpiresAt.After(use.Now) {
		return false, nil
	}
	result, err := tx.ExecContext(ctx, "INSERT INTO "+s.table("agent_assertion_uses")+" (jti_hash,grant_id,grant_version,consumed_at,expires_at) SELECT $1,id,version,$4,$5 FROM "+s.table("agent_grants")+" WHERE id=$2 AND version=$3 AND NOT revoked AND created_at<=clock_timestamp() AND expires_at>clock_timestamp() AND $5::timestamptz>clock_timestamp() ON CONFLICT (jti_hash) DO NOTHING", use.JTIHash, g.ID, g.Version, use.Now.UTC(), use.ExpiresAt.UTC())
	if err != nil {
		return false, agentidentity.ErrUnavailable
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, agentidentity.ErrUnavailable
	}
	if n != 1 {
		return false, nil
	}
	event := agentidentity.Audit{At: use.Now.UTC(), Operation: "assertion-consume", Decision: "allow", Reason: "consumed", Subject: g.Subject, GrantID: g.ID, GrantVersion: g.Version, TenantID: g.TenantID, OwnerID: g.ApprovedBy, JTIHash: use.JTIHash}
	if s.appendAudit(ctx, tx, event) != nil || tx.Commit() != nil {
		return false, agentidentity.ErrUnavailable
	}
	return true, nil
}

func (s *Store) IsTokenRevoked(ctx context.Context, jtiHash string) (bool, error) {
	if !hash.MatchString(jtiHash) {
		return false, agentidentity.ErrDenied
	}
	var revoked bool
	if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+s.table("agent_token_revocations")+" WHERE jti_hash=$1)", jtiHash).Scan(&revoked); err != nil {
		return false, agentidentity.ErrUnavailable
	}
	return revoked, nil
}

// RevokeToken records only an already-approved token identity hash. A caller
// must authorize the actor/target separately; this typed adapter grants no role.
func (s *Store) RevokeToken(ctx context.Context, jtiHash, actor string, at, expiresAt time.Time) error {
	if !hash.MatchString(jtiHash) || !identifier.MatchString(actor) || at.IsZero() || !expiresAt.After(at) || expiresAt.Sub(at) > agentidentity.MaxTokenLifetime {
		return agentidentity.ErrDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return agentidentity.ErrUnavailable
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "INSERT INTO "+s.table("agent_token_revocations")+" (jti_hash,revoked_by,revoked_at,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT (jti_hash) DO NOTHING", jtiHash, actor, at.UTC(), expiresAt.UTC())
	if err != nil {
		return agentidentity.ErrUnavailable
	}
	n, err := result.RowsAffected()
	if err != nil {
		return agentidentity.ErrUnavailable
	}
	if n == 1 {
		event := agentidentity.Audit{At: at.UTC(), Operation: "token-revoke", Decision: "allow", Reason: "revoked", OwnerID: actor, JTIHash: jtiHash}
		if s.appendAudit(ctx, tx, event) != nil {
			return agentidentity.ErrUnavailable
		}
	}
	if tx.Commit() != nil {
		return agentidentity.ErrUnavailable
	}
	return nil
}

var _ agentidentity.Store = (*Store)(nil)
var _ agentidentity.GrantManager = (*Store)(nil)
var _ agentidentity.Auditor = (*Store)(nil)
