package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-auth/agentidentity"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

//go:embed schema.sql
var fixtureSchemaSQL string

// The integration fixture is explicit and loopback-only. It creates and drops
// only a random schema inside the dedicated synthetic CI/test database.
func fixtureURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.User == nil || u.Path != "/agentidentity_test" || u.RawPath != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, agentidentity.ErrDenied
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if ip == nil || !ip.IsLoopback() || err != nil || port == 0 || !identifier.MatchString(u.User.Username()) {
		return nil, agentidentity.ErrDenied
	}
	if password, ok := u.User.Password(); !ok || password == "" {
		return nil, agentidentity.ErrDenied
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q) != 1 || len(q["sslmode"]) != 1 || q.Get("sslmode") != "disable" {
		return nil, agentidentity.ErrDenied
	}
	return u, nil
}

func TestIntegrationURLRequiresExplicitSyntheticLoopbackDatabase(t *testing.T) {
	good := "postgres://agentidentity_test:isolated-test-only@127.0.0.1:5432/agentidentity_test?sslmode=disable"
	if _, err := fixtureURL(good); err != nil {
		t.Fatal("isolated CI URI refused")
	}
	for _, bad := range []string{
		"", "host=127.0.0.1 dbname=agentidentity_test",
		"postgres://fixture:synthetic@database.example.test:5432/agentidentity_test?sslmode=disable",
		"postgres://fixture:synthetic@127.0.0.1:5432/production?sslmode=disable",
		"postgres://fixture@127.0.0.1:5432/agentidentity_test?sslmode=disable",
		"postgres://fixture:synthetic@127.0.0.1/agentidentity_test?sslmode=disable",
		good + "&service=personal", good + "&passfile=/personal/pgpass", good + "&host=remote.example.test",
		good + "&sslmode=disable", good + "#fragment",
	} {
		if _, err := fixtureURL(bad); err != agentidentity.ErrDenied {
			t.Fatal("unsafe integration URI accepted")
		}
	}
}

type pgFixture struct {
	db     *sql.DB
	store  *Store
	config *pgx.ConnConfig
}

func newPGFixture(t *testing.T) *pgFixture {
	t.Helper()
	raw := os.Getenv("AGENTIDENTITY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("explicit AGENTIDENTITY_TEST_DATABASE_URL not provided; no database/profile action")
	}
	u, err := fixtureURL(raw)
	if err != nil {
		t.Fatal("integration database must be explicit synthetic loopback URI")
	}
	// Prevent inherited personal service, passfile, SSL or runtime profiles.
	// These tests do not run in parallel because Setenv is process-scoped.
	for _, name := range []string{"PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE", "PGAPPNAME", "PGCONNECT_TIMEOUT", "PGSSLMODE", "PGSSLKEY", "PGSSLCERT", "PGSSLSNI", "PGSSLROOTCERT", "PGSSLPASSWORD", "PGSSLNEGOTIATION", "PGTARGETSESSIONATTRS", "PGSERVICE", "PGSERVICEFILE", "PGTZ", "PGOPTIONS", "PGMINPROTOCOLVERSION", "PGMAXPROTOCOLVERSION"} {
		t.Setenv(name, "")
	}
	q := u.Query()
	q.Set("passfile", filepath.Join(t.TempDir(), "nonexistent-synthetic-passfile"))
	q.Set("connect_timeout", "5")
	u.RawQuery = q.Encode()
	config, err := pgx.ParseConfig(u.String())
	if err != nil {
		t.Fatal("synthetic connection configuration failed")
	}
	db := stdlib.OpenDB(*config)
	db.SetMaxOpenConns(8)
	t.Cleanup(func() { db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if db.PingContext(ctx) != nil {
		t.Fatal("explicit synthetic PostgreSQL fixture unavailable")
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("schema nonce failed")
	}
	schema := "agent_fixture_" + hex.EncodeToString(nonce[:])
	if _, err := db.ExecContext(ctx, `CREATE SCHEMA "`+schema+`"`); err != nil {
		t.Fatal("owned synthetic schema create failed")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, err := db.ExecContext(ctx, `DROP SCHEMA "`+schema+`" CASCADE`); err != nil {
			t.Error("owned synthetic schema cleanup failed")
		}
	})
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("fixture transaction failed")
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL search_path TO "`+schema+`"`); err != nil {
		t.Fatal("owned schema search path failed")
	}
	if _, err := tx.ExecContext(ctx, fixtureSchemaSQL); err != nil {
		t.Fatal("explicit fixture-only SQL adoption failed")
	}
	if tx.Commit() != nil {
		t.Fatal("fixture migration commit failed")
	}
	s, err := New(db, schema)
	if err != nil {
		t.Fatal("fixture store failed")
	}
	return &pgFixture{db: db, store: s, config: config}
}

func (f *pgFixture) reconnect(t *testing.T) *Store {
	t.Helper()
	db := stdlib.OpenDB(*f.config)
	db.SetMaxOpenConns(8)
	t.Cleanup(func() { db.Close() })
	s, err := New(db, f.store.schema)
	if err != nil {
		t.Fatal("reconnected fixture store failed")
	}
	return s
}

func (f *pgFixture) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := f.db.QueryRow("SELECT count(*) FROM " + f.store.table(table)).Scan(&n); err != nil {
		t.Fatal("fixture row count failed")
	}
	return n
}

func assertionUse(g agentidentity.Grant, label string) agentidentity.AssertionUse {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return agentidentity.AssertionUse{GrantID: g.ID, GrantVersion: g.Version, JTIHash: fixtureHash(label), Now: now, ExpiresAt: now.Add(45 * time.Second)}
}

func TestPostgresGrantReplayRevokeSurviveNewConnectionPool(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	g := fixtureGrant(t, "fixture-one", 501)
	if err := f.store.CreateGrant(ctx, g); err != nil {
		t.Fatal("valid grant create failed")
	}
	if f.store.CreateGrant(ctx, g) != agentidentity.ErrConflict {
		t.Fatal("duplicate create was not a CAS conflict")
	}
	loaded, err := f.reconnect(t).GetGrant(ctx, g.ID)
	if err != nil || loaded.PublicKey.X.Cmp(g.PublicKey.X) != 0 || loaded.PublicKey.Y.Cmp(g.PublicKey.Y) != 0 || loaded.Preview.Origin != g.Preview.Origin || loaded.TenantID != g.TenantID || loaded.ApprovedBy != g.ApprovedBy || loaded.Version != 1 {
		t.Fatal("grant/public key/content did not persist across connection pools")
	}
	use := assertionUse(g, "reconnect-assertion")
	if ok, err := f.store.ConsumeAssertion(ctx, use); err != nil || !ok {
		t.Fatal("first assertion consume failed")
	}
	if ok, err := f.reconnect(t).ConsumeAssertion(ctx, use); err != nil || ok {
		t.Fatal("replay survived reconnect")
	}
	if f.store.RevokeGrant(ctx, g.ID, 2, "current-owner", time.Now()) != agentidentity.ErrConflict {
		t.Fatal("stale expected version did not conflict")
	}
	if f.store.RevokeGrant(ctx, g.ID, 1, "current-owner", time.Now()) != nil {
		t.Fatal("matching revoke failed")
	}
	if f.store.RevokeGrant(ctx, g.ID, 1, "current-owner", time.Now()) != agentidentity.ErrConflict {
		t.Fatal("repeat revoke did not conflict")
	}
	loaded, err = f.reconnect(t).GetGrant(ctx, g.ID)
	if err != nil || !loaded.Revoked || loaded.Version != 2 {
		t.Fatal("revoke/version bump did not persist")
	}
	for _, version := range []int64{1, 2} {
		use = assertionUse(g, "revoked-assertion")
		use.GrantVersion = version
		if ok, err := f.reconnect(t).ConsumeAssertion(ctx, use); err != nil || ok {
			t.Fatal("revoked grant assertion was admitted")
		}
	}
	now := time.Now().UTC()
	if err := f.store.RevokeToken(ctx, fixtureHash("token-one"), "current-owner", now, now.Add(time.Minute)); err != nil {
		t.Fatal("token revoke failed")
	}
	before := f.count(t, "agent_management_audit")
	if err := f.store.RevokeToken(ctx, fixtureHash("token-one"), "current-owner", now, now.Add(time.Minute)); err != nil || f.count(t, "agent_management_audit") != before {
		t.Fatal("idempotent token revoke duplicated committed outbox event")
	}
	if revoked, err := f.reconnect(t).IsTokenRevoked(ctx, fixtureHash("token-one")); err != nil || !revoked {
		t.Fatal("token revocation did not persist")
	}
	if revoked, err := f.store.IsTokenRevoked(ctx, fixtureHash("different-token")); err != nil || revoked {
		t.Fatal("unrelated token hash was revoked")
	}
	if f.count(t, "agent_management_audit") != 4 {
		t.Fatal("committed create/consume/revoke/token events were not retained exactly once")
	}
}

func TestPostgresGlobalReplayConcurrentTenantsAndVersions(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	one, two := fixtureGrant(t, "fixture-one", 501), fixtureGrant(t, "fixture-two", 502)
	two.PublicKey = one.PublicKey // One workload identity, independent tenant grants.
	for _, g := range []agentidentity.Grant{one, two} {
		if err := f.store.CreateGrant(ctx, g); err != nil {
			t.Fatal("tenant grant create failed")
		}
		if ok, err := f.store.ConsumeAssertion(ctx, assertionUse(g, g.ID+"-positive")); err != nil || !ok {
			t.Fatal("independent tenant positive consume failed")
		}
	}
	start := make(chan struct{})
	type outcome struct {
		ok  bool
		err error
	}
	results := make(chan outcome, 24)
	var workers sync.WaitGroup
	for i := 0; i < 24; i++ {
		g := one
		if i%2 != 0 {
			g = two
		}
		use := assertionUse(g, "same-issuer-subject-kid-jti")
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			ok, err := f.store.ConsumeAssertion(ctx, use)
			results <- outcome{ok, err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	winners := 0
	for result := range results {
		if result.err != nil {
			t.Fatal("concurrent fixture consume failed")
		}
		if result.ok {
			winners++
		}
	}
	if winners != 1 || f.count(t, "agent_assertion_uses") != 3 {
		t.Fatal("global replay identity had multiple winners across grants")
	}
	// Fixture-only permission-edit version bump proves uniqueness is not
	// partitioned by grant version. No production edit API is introduced.
	if _, err := f.db.Exec("UPDATE "+f.store.table("agent_grants")+" SET version=2 WHERE id=$1", one.ID); err != nil {
		t.Fatal("fixture version bump failed")
	}
	one.Version = 2
	if ok, err := f.reconnect(t).ConsumeAssertion(ctx, assertionUse(one, "same-issuer-subject-kid-jti")); err != nil || ok {
		t.Fatal("version bump reopened globally consumed assertion")
	}
	if ok, err := f.store.ConsumeAssertion(ctx, assertionUse(one, "new-version-positive")); err != nil || !ok {
		t.Fatal("fresh assertion at current version failed")
	}
	stale := assertionUse(one, "stale-version")
	stale.GrantVersion = 1
	if ok, err := f.store.ConsumeAssertion(ctx, stale); err != nil || ok {
		t.Fatal("stale grant version admitted")
	}
}

func TestPostgresExpiryUsesDatabaseClockAndRevokeSerialization(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	g := fixtureGrant(t, "fixture-expiry", 501)
	g.CreatedAt = time.Now().UTC().Add(-2 * time.Hour)
	g.ExpiresAt = time.Now().UTC().Add(time.Hour)
	if f.store.CreateGrant(ctx, g) != nil {
		t.Fatal("expiry fixture create failed")
	}
	use := assertionUse(g, "expired-assertion")
	use.Now, use.ExpiresAt = time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(-30*time.Second)
	if ok, err := f.store.ConsumeAssertion(ctx, use); err != nil || ok {
		t.Fatal("lagging caller clock admitted expired assertion")
	}
	if _, err := f.db.Exec("UPDATE "+f.store.table("agent_grants")+" SET expires_at=$2 WHERE id=$1", g.ID, time.Now().UTC().Add(-time.Second)); err != nil {
		t.Fatal("owned expiry fixture update failed")
	}
	use = assertionUse(g, "expired-grant")
	use.Now = time.Now().UTC().Add(-30 * time.Second)
	use.ExpiresAt = use.Now.Add(time.Minute)
	if ok, err := f.store.ConsumeAssertion(ctx, use); err != nil || ok {
		t.Fatal("lagging caller clock admitted expired grant")
	}
	expired := fixtureGrant(t, "expired-create", 502)
	expired.CreatedAt, expired.ExpiresAt = g.CreatedAt, time.Now().UTC().Add(-time.Second)
	if f.store.CreateGrant(ctx, expired) != agentidentity.ErrDenied {
		t.Fatal("expired create accepted")
	}
	live := fixtureGrant(t, "fixture-lock", 502)
	if f.store.CreateGrant(ctx, live) != nil {
		t.Fatal("lock fixture create failed")
	}
	tx, err := f.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("lock transaction failed")
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE "+f.store.table("agent_grants")+" SET revoked=true,version=2,revoked_by='fixture-owner',revoked_at=clock_timestamp() WHERE id=$1", live.ID); err != nil {
		t.Fatal("owned concurrent revoke update failed")
	}
	result := make(chan bool, 1)
	errResult := make(chan error, 1)
	go func() {
		ok, err := f.store.ConsumeAssertion(ctx, assertionUse(live, "locked-revoke"))
		result <- ok
		errResult <- err
	}()
	if tx.Commit() != nil {
		t.Fatal("owned concurrent revoke commit failed")
	}
	if <-result || <-errResult != nil {
		t.Fatal("consumer did not observe current revoked row after lock")
	}
}

func TestPostgresAuditFailureRollsBackEveryMutation(t *testing.T) {
	f := newPGFixture(t)
	ctx := context.Background()
	g := fixtureGrant(t, "fixture-rollback", 501)
	if f.store.CreateGrant(ctx, g) != nil {
		t.Fatal("rollback fixture create failed")
	}
	before := f.count(t, "agent_management_audit")
	function := f.store.table("fixture_reject_audit")
	if _, err := f.db.Exec("CREATE FUNCTION " + function + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic-secret-token-PEM-DSN'; END; $$"); err != nil {
		t.Fatal("owned audit failure fixture failed")
	}
	if _, err := f.db.Exec("CREATE TRIGGER fixture_audit_failure BEFORE INSERT ON " + f.store.table("agent_management_audit") + " FOR EACH ROW EXECUTE FUNCTION " + function + "()"); err != nil {
		t.Fatal("owned audit failure trigger failed")
	}
	newGrant := fixtureGrant(t, "fixture-rollback-new", 502)
	use := assertionUse(g, "rollback-assertion")
	now := time.Now().UTC()
	if f.store.CreateGrant(ctx, newGrant) != agentidentity.ErrUnavailable || f.store.RevokeGrant(ctx, g.ID, 1, "current-owner", now) != agentidentity.ErrUnavailable {
		t.Fatal("audit failure did not fail grant mutations closed")
	}
	if ok, err := f.store.ConsumeAssertion(ctx, use); err != agentidentity.ErrUnavailable || ok {
		t.Fatal("audit failure did not roll back assertion consume")
	}
	if f.store.RevokeToken(ctx, fixtureHash("rollback-token"), "current-owner", now, now.Add(time.Minute)) != agentidentity.ErrUnavailable {
		t.Fatal("audit failure did not fail token revoke closed")
	}
	if f.store.Record(ctx, agentidentity.Audit{At: now, Operation: "access", Decision: "deny", Reason: "denied"}) != agentidentity.ErrUnavailable {
		t.Fatal("audit raw database failure escaped redaction")
	}
	loaded, err := f.reconnect(t).GetGrant(ctx, g.ID)
	if err != nil || loaded.Revoked || loaded.Version != 1 || f.count(t, "agent_grants") != 1 || f.count(t, "agent_assertion_uses") != 0 || f.count(t, "agent_token_revocations") != 0 || f.count(t, "agent_management_audit") != before {
		t.Fatal("failed transaction left partial durable changes")
	}
	if _, err := f.db.Exec("DROP TRIGGER fixture_audit_failure ON " + f.store.table("agent_management_audit")); err != nil {
		t.Fatal("owned audit failure trigger removal failed")
	}
	if ok, err := f.store.ConsumeAssertion(ctx, use); err != nil || !ok {
		t.Fatal("rolled-back assertion was incorrectly consumed")
	}
}

func TestPostgresSQLConstraintsAndRetainedRows(t *testing.T) {
	f := newPGFixture(t)
	g := fixtureGrant(t, "fixture-constraints", 501)
	ctx := context.Background()
	if f.store.CreateGrant(ctx, g) != nil {
		t.Fatal("constraint fixture create failed")
	}
	for _, clause := range []string{"tenant_id=0", "version=0", "expires_at=created_at+interval '721 hours'", "expires_at=created_at", "created_at='infinity'::timestamptz", "revoked=true"} {
		if _, err := f.db.Exec("UPDATE "+f.store.table("agent_grants")+" SET "+clause+" WHERE id=$1", g.ID); err == nil {
			t.Fatal("database structural constraint did not refuse invalid row")
		}
	}
	if ok, err := f.store.ConsumeAssertion(ctx, assertionUse(g, "retained")); err != nil || !ok {
		t.Fatal("retained fixture consume failed")
	}
	now := time.Now().UTC()
	if f.store.RevokeToken(ctx, fixtureHash("retained-token"), "owner", now, now.Add(time.Minute)) != nil {
		t.Fatal("retained fixture token revoke failed")
	}
	for _, table := range []string{"agent_assertion_uses", "agent_token_revocations", "agent_management_audit"} {
		before := f.count(t, table)
		for _, operation := range []string{"DELETE FROM ", "TRUNCATE "} {
			if _, err := f.db.Exec(operation + f.store.table(table)); err == nil {
				t.Fatal("retained record rewrite accepted")
			}
		}
		if f.count(t, table) != before {
			t.Fatal("retained records changed")
		}
	}
	if _, err := f.db.Exec("UPDATE " + f.store.table("agent_management_audit") + " SET event='{}'::jsonb"); err == nil {
		t.Fatal("audit update accepted")
	}
}

type ownerContextKey struct{}
type additionalOwnerPolicy struct{ tenants map[string]int64 }

func (p additionalOwnerPolicy) ResolveOwner(r *http.Request) (agentidentity.Owner, error) {
	owner, ok := r.Context().Value(ownerContextKey{}).(agentidentity.Owner)
	if !ok {
		return owner, agentidentity.ErrDenied
	}
	return owner, nil
}
func (p additionalOwnerPolicy) AuthorizeOwner(_ context.Context, owner agentidentity.Owner, operation string, g agentidentity.Grant) error {
	tenant, ok := p.tenants[owner.ID]
	if !ok {
		return agentidentity.ErrDenied
	}
	if operation == "list" || tenant == g.TenantID {
		return nil
	}
	return agentidentity.ErrDenied
}

func TestPostgresOwnerListAndResourcePolicyApplyCurrentTenantAuthority(t *testing.T) {
	ctx := context.Background()
	one, two := fixtureGrant(t, "fixture-owner-one", 501), fixtureGrant(t, "fixture-owner-two", 502)
	two.PublicKey = one.PublicKey
	two.UpdatePageIDs = []string{"20"}
	two.Preview = &agentidentity.PreviewGrant{Audience: "https://second.example.test/audience", Origin: "https://second.example.test", Paths: []string{"/", "/music"}}
	configs := fixtureTenantConfigs(one, two)
	policy, err := agentidentity.NewTenantPolicy(configs)
	if err != nil {
		t.Fatal("two-tenant policy failed before database skip")
	}
	f := newPGFixture(t)
	for _, g := range []agentidentity.Grant{one, two} {
		if f.store.CreateGrant(ctx, g) != nil {
			t.Fatal("owner list fixture create failed")
		}
	}
	for i, g := range []agentidentity.Grant{one, two} {
		loaded, err := f.reconnect(t).GetGrant(ctx, g.ID)
		if err != nil || policy.AllowGrant(ctx, loaded) != nil {
			t.Fatal("tenant policy positive failed")
		}
		resource := agentidentity.Resource{TenantID: g.TenantID, Audience: g.APIAudience, Scope: agentidentity.PagesUpdate, PageID: g.UpdatePageIDs[0], Path: configs[i].PagesPath + "/" + g.UpdatePageIDs[0]}
		if policy.AllowResource(ctx, loaded, resource) != nil {
			t.Fatal("tenant resource positive failed")
		}
		resource.TenantID = 503
		if policy.AllowResource(ctx, loaded, resource) != agentidentity.ErrDenied {
			t.Fatal("cross-tenant resource admitted")
		}
		resource.TenantID = g.TenantID
		resource.PageID, resource.Path = "999", configs[i].PagesPath+"/999"
		if policy.AllowResource(ctx, loaded, resource) != agentidentity.ErrDenied {
			t.Fatal("other tenant/page ceiling admitted")
		}
	}
	owners := additionalOwnerPolicy{tenants: map[string]int64{"current-one": 501, "current-two": 502}}
	service, err := agentidentity.NewService(agentidentity.Options{IssuerURL: "https://issuer.example.test", TokenEndpoint: "https://issuer.example.test/agent/token", IssuerKeys: map[string]*ecdsa.PublicKey{"issuer-kid": one.PublicKey}, Store: f.reconnect(t), Audit: f.store, Policy: policy, Issuer: agentidentity.IssuerFunc(func(context.Context, agentidentity.IssueRequest) (string, error) { return "", agentidentity.ErrDenied })})
	if err != nil {
		t.Fatal("durable management fixture service failed")
	}
	handler, err := service.ManagementHandler(agentidentity.ManagementOptions{Path: fixtureManagementPath, OwnerOrigin: "https://owner.example.test", Owners: owners})
	if err != nil {
		t.Fatal("management fixture handler failed")
	}
	for _, owner := range []string{"current-one", "current-two"} {
		r := httptest.NewRequest("GET", "https://owner.example.test"+fixtureManagementPath, nil)
		r = r.WithContext(context.WithValue(r.Context(), ownerContextKey{}, agentidentity.Owner{ID: owner}))
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		var grants []agentidentity.Grant
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &grants) != nil || len(grants) != 1 || grants[0].TenantID != owners.tenants[owner] {
			t.Fatal("current owner tenant filtering failed")
		}
	}
	// Request metadata cannot substitute for the verified owner context.
	r := httptest.NewRequest("GET", "https://owner.example.test"+fixtureManagementPath, nil)
	r.Header.Set("X-Owner-ID", "current-one")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("header owner spoof accepted")
	}
	delete(owners.tenants, "current-one")
	r = r.WithContext(context.WithValue(r.Context(), ownerContextKey{}, agentidentity.Owner{ID: "current-one"}))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("removed current owner retained list access")
	}
	if _, err := f.store.GetGrant(ctx, "unconfigured-new-site"); !errors.Is(err, agentidentity.ErrDenied) {
		t.Fatal("site/config creation inferred an agent grant")
	}
}

// This signer is a synthetic fixture, not a Workflow managed issuer adapter.
// It proves persistence/core interoperability without external key custody.
type fixtureAccessClaims struct {
	jwt.RegisteredClaims
	TokenUse     string `json:"token_use"`
	GrantID      string `json:"grant_id"`
	GrantVersion int64  `json:"grant_version"`
	TenantID     int64  `json:"tenant_id"`
	Scope        string `json:"scope"`
}

func TestPostgresServiceExchangeAuthorizeAcrossTenantsAndRevocations(t *testing.T) {
	ctx := context.Background()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("synthetic issuer key fixture failed")
	}
	workload, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("synthetic workload key fixture failed")
	}
	one, two := fixtureGrant(t, "service-one", 501), fixtureGrant(t, "service-two", 502)
	one.PublicKey, two.PublicKey = &workload.PublicKey, &workload.PublicKey
	configs := fixtureTenantConfigs(one, two)
	policy, err := agentidentity.NewTenantPolicy(configs)
	if err != nil {
		t.Fatal("service tenant fixture policy failed before database skip")
	}
	f := newPGFixture(t)
	for _, g := range []agentidentity.Grant{one, two} {
		if f.store.CreateGrant(ctx, g) != nil {
			t.Fatal("service grant fixture create failed")
		}
	}
	const endpoint = "https://issuer.example.test/agent/token"
	issuer := agentidentity.IssuerFunc(func(_ context.Context, r agentidentity.IssueRequest) (string, error) {
		claims := fixtureAccessClaims{
			RegisteredClaims: jwt.RegisteredClaims{Issuer: "https://issuer.example.test", Subject: r.Subject, Audience: jwt.ClaimStrings{r.Audience}, IssuedAt: jwt.NewNumericDate(r.IssuedAt), ExpiresAt: jwt.NewNumericDate(r.ExpiresAt), ID: "issued-" + r.GrantID},
			TokenUse:         "agent_access", GrantID: r.GrantID, GrantVersion: r.GrantVersion, TenantID: r.TenantID, Scope: strings.Join(r.Scopes, " "),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = "synthetic-issuer-key"
		raw, err := token.SignedString(issuerKey)
		if err != nil {
			return "", agentidentity.ErrUnavailable
		}
		return raw, nil
	})
	newService := func() *agentidentity.Service {
		s, err := agentidentity.NewService(agentidentity.Options{IssuerURL: "https://issuer.example.test", TokenEndpoint: endpoint, IssuerKeys: map[string]*ecdsa.PublicKey{"synthetic-issuer-key": &issuerKey.PublicKey}, Store: f.reconnect(t), Audit: f.store, Policy: policy, Issuer: issuer})
		if err != nil {
			t.Fatal("durable service fixture construction failed")
		}
		return s
	}
	assertion := func(id string) string {
		now := time.Now().UTC().Truncate(time.Second)
		token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{Issuer: one.AssertionIssuer, Subject: one.Subject, Audience: jwt.ClaimStrings{endpoint}, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(45 * time.Second)), ID: id})
		token.Header["kid"] = one.KeyID
		raw, err := token.SignedString(workload)
		if err != nil {
			t.Fatal("synthetic assertion fixture signing failed")
		}
		return raw
	}
	service := newService()
	sharedAssertion := assertion("global-service-assertion")
	first, err := service.Exchange(ctx, agentidentity.ExchangeRequest{GrantID: one.ID, Assertion: sharedAssertion, Audience: one.APIAudience, Scopes: []string{agentidentity.PagesRead}})
	if err != nil {
		t.Fatal("durable first tenant service exchange failed")
	}
	if _, err := newService().Exchange(ctx, agentidentity.ExchangeRequest{GrantID: two.ID, Assertion: sharedAssertion, Audience: two.APIAudience, Scopes: []string{agentidentity.PagesRead}}); err != agentidentity.ErrDenied {
		t.Fatal("core global bound assertion replay across tenant grants admitted")
	}
	second, err := newService().Exchange(ctx, agentidentity.ExchangeRequest{GrantID: two.ID, Assertion: assertion("second-service-assertion"), Audience: two.APIAudience, Scopes: []string{agentidentity.PagesRead}})
	if err != nil {
		t.Fatal("durable second tenant service exchange failed")
	}
	var firstPrincipal agentidentity.Principal
	for i, g := range []agentidentity.Grant{one, two} {
		raw := first.AccessToken
		if i == 1 {
			raw = second.AccessToken
		}
		resource := agentidentity.Resource{TenantID: g.TenantID, Audience: g.APIAudience, Scope: agentidentity.PagesRead, Method: "GET", Path: configs[i].PagesPath}
		principal, err := newService().Authorize(ctx, raw, resource)
		if err != nil || principal.TenantID != g.TenantID {
			t.Fatal("durable current tenant service authorization failed")
		}
		if i == 0 {
			firstPrincipal = principal
		}
		resource.TenantID = 503
		if _, err := service.Authorize(ctx, raw, resource); err != agentidentity.ErrDenied {
			t.Fatal("core cross-tenant token admitted")
		}
	}
	now := time.Now().UTC()
	if f.store.RevokeToken(ctx, firstPrincipal.JTIHash, "current-owner", now, now.Add(time.Minute)) != nil {
		t.Fatal("service token revocation fixture failed")
	}
	if _, err := newService().Authorize(ctx, first.AccessToken, agentidentity.Resource{TenantID: one.TenantID, Audience: one.APIAudience, Scope: agentidentity.PagesRead, Method: "GET", Path: configs[0].PagesPath}); err != agentidentity.ErrDenied {
		t.Fatal("durable revoked token admitted after new service/pool")
	}
	if f.store.RevokeGrant(ctx, two.ID, 1, "current-owner", time.Now()) != nil {
		t.Fatal("service grant revoke fixture failed")
	}
	if _, err := newService().Authorize(ctx, second.AccessToken, agentidentity.Resource{TenantID: two.TenantID, Audience: two.APIAudience, Scope: agentidentity.PagesRead, Method: "GET", Path: configs[1].PagesPath}); err != agentidentity.ErrDenied {
		t.Fatal("durable revoked grant token admitted after new service/pool")
	}
}
