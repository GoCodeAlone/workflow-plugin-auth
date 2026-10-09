package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"

	"github.com/GoCodeAlone/workflow-plugin-auth/agentidentity"
)

var operations = map[string]bool{
	"exchange": true, "access": true, "grant-page": true, "grant-list": true,
	"grant-create": true, "grant-revoke": true, "grant-create-committed": true,
	"grant-revoke-committed": true, "assertion-consume": true, "token-revoke": true,
}
var reasons = map[string]bool{
	"issued": true, "authorized": true, "approved": true, "denied": true,
	"unavailable": true, "committed": true, "consumed": true, "revoked": true,
}

func validAudit(e agentidentity.Audit) bool {
	if e.At.IsZero() || !operations[e.Operation] || !reasons[e.Reason] || (e.Decision != "allow" && e.Decision != "deny") || e.GrantVersion < 0 || e.TenantID < 0 {
		return false
	}
	for _, id := range []string{e.Subject, e.GrantID, e.OwnerID} {
		if id != "" && !identifier.MatchString(id) {
			return false
		}
	}
	if e.PageID != "" {
		id, err := strconv.ParseUint(e.PageID, 10, 64)
		if err != nil || id == 0 || strconv.FormatUint(id, 10) != e.PageID {
			return false
		}
	}
	if e.JTIHash != "" && !hash.MatchString(e.JTIHash) {
		return false
	}
	if e.Scope != "" && e.Scope != agentidentity.PagesRead && e.Scope != agentidentity.HistoryRead && e.Scope != agentidentity.PagesUpdate && e.Scope != agentidentity.PreviewRead {
		return false
	}
	return true
}

func (s *Store) appendAudit(ctx context.Context, tx *sql.Tx, e agentidentity.Audit) error {
	if !validAudit(e) {
		return agentidentity.ErrDenied
	}
	e.At = e.At.UTC()
	payload, err := json.Marshal(e)
	if err != nil {
		return agentidentity.ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO "+s.table("agent_management_audit")+" (event) VALUES($1)", payload); err != nil {
		return agentidentity.ErrUnavailable
	}
	return nil
}

// Record retains fixed-code service/management metadata. Create/Revoke also
// append their distinct committed event in the SAME mutation transaction.
func (s *Store) Record(ctx context.Context, e agentidentity.Audit) error {
	if !validAudit(e) {
		return agentidentity.ErrDenied
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return agentidentity.ErrUnavailable
	}
	defer tx.Rollback()
	if s.appendAudit(ctx, tx, e) != nil || tx.Commit() != nil {
		return agentidentity.ErrUnavailable
	}
	return nil
}
