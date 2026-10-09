package agentidentity

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type ownerFixture struct{ deny bool }

func (p *ownerFixture) ResolveOwner(r *http.Request) (Owner, error) {
	if p.deny || r.Header.Get("Cookie") != "existing-human-session=test-fixture" || r.Header.Get("Authorization") != "" {
		return Owner{}, ErrDenied
	}
	return Owner{ID: "verified-human-owner"}, nil
}
func (p *ownerFixture) AuthorizeOwner(_ context.Context, o Owner, action string, g Grant) error {
	if p.deny || o.ID != "verified-human-owner" || (g.TenantID != 0 && g.TenantID != 234) {
		return ErrDenied
	}
	return nil
}
func (s *testStore) CreateGrant(_ context.Context, g Grant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grants == nil {
		s.grants = map[string]Grant{s.grant.ID: s.grant}
	}
	if _, ok := s.grants[g.ID]; ok {
		return ErrConflict
	}
	s.grants[g.ID] = g
	return nil
}
func (s *testStore) RevokeGrant(_ context.Context, id string, v int64, _ string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grants == nil {
		s.grants = map[string]Grant{s.grant.ID: s.grant}
	}
	g, ok := s.grants[id]
	if !ok || g.Version != v || g.Revoked {
		return ErrConflict
	}
	g.Revoked = true
	g.Version++
	s.grants[id] = g
	return nil
}
func (s *testStore) ListGrants(_ context.Context, _ Owner) ([]Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grants == nil {
		return []Grant{s.grant}, nil
	}
	out := make([]Grant, 0, len(s.grants))
	for _, g := range s.grants {
		out = append(out, g)
	}
	return out, nil
}

func publicProposal(t *testing.T, f *fixture) map[string]any {
	t.Helper()
	b, e := x509.MarshalPKIXPublicKey(&f.workload.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	return map[string]any{"subject": "agent-new-preview", "assertion_issuer": "https://workload.example.test", "key_id": "workload-key", "public_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b})), "tenant_id": 234, "expires_at": f.now.Add(24 * time.Hour).Format(time.RFC3339), "api_audience": testAPI, "scopes": []string{PagesRead, HistoryRead}, "confirmed": true}
}
func manageRequest(p string, body map[string]any) *http.Request {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", "https://owner.example.test"+p, strings.NewReader(string(b)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://owner.example.test")
	r.Header.Set("Cookie", "existing-human-session=test-fixture")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	return r
}

// A read-only wrapper deliberately hides GrantManager even if its underlying
// store can manage grants. Management cannot be mounted against another store.
type validationOnlyStore struct{ Store }

func TestOwnerManagementRequiresValidationStoreManagement(t *testing.T) {
	f := setup(t)
	opts := f.s.options
	opts.Store = validationOnlyStore{f.store}
	s, err := NewService(opts)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := s.ManagementHandler(ManagementOptions{Path: "/api/v1/admin/auth/agent-grants", OwnerOrigin: "https://owner.example.test", Owners: &ownerFixture{}}); err != ErrUnavailable || h != nil {
		t.Fatal("management mounted without the validation authority's manager", err)
	}
}

func TestOwnerRegistrationAndRevocationUseExistingHumanSession(t *testing.T) {
	f := setup(t)
	h, e := f.s.ManagementHandler(ManagementOptions{Path: "/api/v1/admin/auth/agent-grants", OwnerOrigin: "https://owner.example.test", Owners: &ownerFixture{}})
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, manageRequest("/api/v1/admin/auth/agent-grants", publicProposal(t, f)))
	if w.Code != 201 {
		t.Fatal("public-key grant registration failed", w.Code, w.Body.String())
	}
	var g Grant
	if e = json.Unmarshal(w.Body.Bytes(), &g); e != nil || g.ID == "" || g.ApprovedBy != "verified-human-owner" || g.Version != 1 || g.Revoked {
		t.Fatal("untrusted owner identity persisted", e)
	}
	if strings.Contains(w.Body.String(), "PUBLIC KEY") || strings.Contains(w.Body.String(), "test-fixture") {
		t.Fatal("credential/public-key payload unexpectedly echoed")
	}
	r := httptest.NewRequest("GET", "https://owner.example.test/api/v1/admin/auth/agent-grants", nil)
	r.Header.Set("Cookie", "existing-human-session=test-fixture")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), g.ID) {
		t.Fatal("owner grant inventory absent")
	}
	f.store.grant = g
	out, e := f.s.Exchange(context.Background(), ExchangeRequest{GrantID: g.ID, Assertion: f.assertion(t, "new-grant-jti", nil), Audience: testAPI, Scopes: []string{PagesRead}})
	if e != nil {
		t.Fatal(e)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, manageRequest("/api/v1/admin/auth/agent-grants/revoke", map[string]any{"id": g.ID, "expected_version": g.Version, "confirmed": true}))
	if w.Code != 204 {
		t.Fatal("owner revoke refused", w.Code)
	}
	if _, e = f.s.Authorize(context.Background(), out.AccessToken, apiRead()); e != ErrDenied {
		t.Fatal("revoked token retained authority", e)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, manageRequest("/api/v1/admin/auth/agent-grants/revoke", map[string]any{"id": g.ID, "expected_version": g.Version, "confirmed": true}))
	if w.Code != 409 {
		t.Fatal("stale revoke did not conflict", w.Code)
	}
}

func TestOwnerGrantMutationDenialsAndNoPersonalCredentialFallback(t *testing.T) {
	for _, kind := range []string{"agent", "no-owner", "wrong-origin", "missing-origin", "wrong-host", "cross-site", "not-confirmed", "role", "live-tenant", "grant-overlong", "privileged-scope", "private-key", "unapproved-page", "audit-down"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			h, e := f.s.ManagementHandler(ManagementOptions{Path: "/api/v1/admin/auth/agent-grants", OwnerOrigin: "https://owner.example.test", Owners: &ownerFixture{}})
			if e != nil {
				t.Fatal(e)
			}
			body := publicProposal(t, f)
			switch kind {
			case "not-confirmed":
				body["confirmed"] = false
			case "role":
				body["role"] = "super_admin"
			case "live-tenant":
				body["tenant_id"] = 999
			case "grant-overlong":
				body["expires_at"] = f.now.Add(MaxGrantLifetime + time.Second).Format(time.RFC3339)
			case "privileged-scope":
				body["scopes"] = []string{"admin:auth.users:update"}
			case "private-key":
				b, _ := x509.MarshalECPrivateKey(f.workload)
				body["public_key_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
			case "unapproved-page":
				body["scopes"] = []string{PagesUpdate}
				body["update_page_ids"] = []string{"999"}
			case "audit-down":
				f.audit.fail = true
			}
			r := manageRequest("/api/v1/admin/auth/agent-grants", body)
			switch kind {
			case "agent":
				r.Header.Del("Cookie")
				r.Header.Set("Authorization", "Bearer synthetic-agent-token")
			case "no-owner":
				r.Header.Del("Cookie")
			case "wrong-origin":
				r.Header.Set("Origin", "https://evil.example.test")
			case "missing-origin":
				r.Header.Del("Origin")
			case "wrong-host":
				r.Host = "alias.example.test"
			case "cross-site":
				r.Header.Set("Sec-Fetch-Site", "cross-site")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || f.store.grants != nil || strings.Contains(w.Body.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), "test-fixture") {
				t.Fatal("unapproved grant/secret accepted", w.Code)
			}
		})
	}
}

func TestOwnerPageUsesConfiguredTenantsAndExistingSession(t *testing.T) {
	f := setup(t)
	p, e := NewTenantPolicy(tenantConfigs())
	if e != nil {
		t.Fatal(e)
	}
	o := f.s.options
	o.Policy = p
	s, e := NewService(o)
	if e != nil {
		t.Fatal(e)
	}
	h, e := s.ManagementHandler(ManagementOptions{Path: "/api/v1/admin/auth/agent-grants", OwnerOrigin: "https://owner.example.test", PagePath: "/admin/agent-access", Owners: &ownerFixture{}})
	if e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("GET", "https://owner.example.test/admin/agent-access", nil)
	r.Header.Set("Cookie", "existing-human-session=test-fixture")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "data-agent-grant-admin") || !strings.Contains(w.Body.String(), testAPI) || strings.Contains(w.Body.String(), "other-preview") || strings.Contains(w.Body.String(), "localStorage") || strings.Contains(w.Body.String(), "sessionStorage") {
		t.Fatal("owner page leaked/unusable config or borrowed credentials")
	}
	r.Header.Del("Cookie")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("anonymous owner page admitted")
	}
}

// The declarations remain fixed while the host's current domain authority can
// change independently. UI declarations must never replace this policy.
type currentPreviewPolicyFixture struct {
	Policy
	live        map[int64]bool
	unavailable bool
	proposed    []Grant
}

func (p *currentPreviewPolicyFixture) AllowGrant(ctx context.Context, g Grant) error {
	p.proposed = append(p.proposed, g)
	if p.unavailable {
		return ErrUnavailable
	}
	if p.live[g.TenantID] {
		return ErrDenied
	}
	return p.Policy.AllowGrant(ctx, g)
}

func (p *currentPreviewPolicyFixture) AllowResource(ctx context.Context, g Grant, r Resource) error {
	if err := p.AllowGrant(ctx, g); err != nil {
		return err
	}
	return p.Policy.AllowResource(ctx, g, r)
}

type tenantOwnerFixture struct {
	ownerFixture
	allowed map[int64]bool
}

func (p *tenantOwnerFixture) AuthorizeOwner(_ context.Context, o Owner, _ string, g Grant) error {
	if p.deny || o.ID != "verified-human-owner" || (g.TenantID != 0 && !p.allowed[g.TenantID]) {
		return ErrDenied
	}
	return nil
}

func TestOwnerPageUsesDeclarationsThroughCurrentWrappedPolicy(t *testing.T) {
	f := setup(t)
	tenants, err := NewTenantPolicy(tenantConfigs())
	if err != nil {
		t.Fatal(err)
	}
	gate := &currentPreviewPolicyFixture{Policy: tenants, live: map[int64]bool{345: true}}
	opts := f.s.options
	opts.Policy = gate
	s, err := NewService(opts)
	if err != nil {
		t.Fatal(err)
	}
	owners := &tenantOwnerFixture{allowed: map[int64]bool{234: true, 345: true}}
	management := ManagementOptions{Path: "/api/v1/admin/auth/agent-grants", OwnerOrigin: "https://owner.example.test", PagePath: "/admin/agent-access", Owners: owners, Tenants: tenants}
	h, err := s.ManagementHandler(management)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://owner.example.test/admin/agent-access", nil)
	r.Header.Set("Cookie", "existing-human-session=test-fixture")
	check := func(handler http.Handler, status int, visible, hidden string) {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != status || (visible != "" && !strings.Contains(w.Body.String(), visible)) || (hidden != "" && strings.Contains(w.Body.String(), hidden)) {
			t.Fatal("declarations bypassed current policy or owner authority", w.Code)
		}
	}
	check(h, http.StatusOK, testAPI, "https://other-preview.example.test/api")
	if len(gate.proposed) != 2 {
		t.Fatal("both declared proposals must consume the wrapped policy")
	}
	for _, g := range gate.proposed {
		if g.TenantID == 0 || g.APIAudience == "" || g.ID != "" || g.Subject != "" || len(g.Scopes) != 0 || g.Preview != nil {
			t.Fatal("owner UI did not use a minimal tenant/audience proposal")
		}
	}
	gate.live[234] = true
	delete(gate.live, 345)
	check(h, http.StatusOK, "https://other-preview.example.test/api", testAPI)
	owners.allowed[345] = false
	check(h, http.StatusUnauthorized, "", "https://other-preview.example.test/api")
	owners.allowed[345] = true
	gate.unavailable = true
	check(h, http.StatusUnauthorized, "", testAPI)
	management.Tenants = nil
	unavailable, err := s.ManagementHandler(management)
	if err != nil {
		t.Fatal(err)
	}
	check(unavailable, http.StatusServiceUnavailable, "", testAPI)
}

func TestOwnerManagementAndAuthorizationRetainWrappedPolicy(t *testing.T) {
	f := setup(t)
	tenants, err := NewTenantPolicy(tenantConfigs())
	if err != nil {
		t.Fatal(err)
	}
	gate := &currentPreviewPolicyFixture{Policy: tenants, live: map[int64]bool{}}
	opts := f.s.options
	opts.Policy = gate
	s, err := NewService(opts)
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.ManagementHandler(ManagementOptions{Path: "/api/v1/admin/auth/agent-grants", OwnerOrigin: "https://owner.example.test", PagePath: "/admin/agent-access", Owners: &tenantOwnerFixture{allowed: map[int64]bool{234: true, 345: true}}, Tenants: tenants})
	if err != nil {
		t.Fatal(err)
	}
	g := f.store.grant
	token, err := s.Exchange(context.Background(), ExchangeRequest{GrantID: g.ID, Assertion: f.assertion(t, "wrapped-policy-before", nil), Audience: testAPI, Scopes: []string{PagesRead}})
	if err != nil {
		t.Fatal(err)
	}
	gate.live[234] = true
	list := httptest.NewRequest("GET", "https://owner.example.test/api/v1/admin/auth/agent-grants", nil)
	list.Header.Set("Cookie", "existing-human-session=test-fixture")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, list)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatal("inventory exposed a currently live tenant")
	}
	for _, r := range []*http.Request{
		manageRequest("/api/v1/admin/auth/agent-grants", publicProposal(t, f)),
		manageRequest("/api/v1/admin/auth/agent-grants/revoke", map[string]any{"id": g.ID, "expected_version": g.Version, "confirmed": true}),
	} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || f.store.grants != nil {
			t.Fatal("management bypassed the current wrapped policy", w.Code)
		}
	}
	if _, err := s.Authorize(context.Background(), token.AccessToken, apiRead()); err != ErrDenied {
		t.Fatal("issued token bypassed the current domain gate", err)
	}
	if _, err := s.Exchange(context.Background(), ExchangeRequest{GrantID: g.ID, Assertion: f.assertion(t, "wrapped-policy-after", nil), Audience: testAPI, Scopes: []string{PagesRead}}); err != ErrDenied {
		t.Fatal("exchange bypassed the current domain gate", err)
	}
	delete(gate.live, 234)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, manageRequest("/api/v1/admin/auth/agent-grants/revoke", map[string]any{"id": g.ID, "expected_version": g.Version, "confirmed": true}))
	if w.Code != http.StatusNoContent {
		t.Fatal("approved owner revoke denied after current gate reopened", w.Code)
	}
}
