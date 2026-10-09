package agentidentity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://issuer.example.test"
const testEndpoint = "https://issuer.example.test/oauth/agent/token"
const testAPI = "https://preview.example.test/api"
const testView = "https://preview.example.test/view"

type testStore struct {
	mu                                   sync.Mutex
	grant                                Grant
	grants                               map[string]Grant
	uses                                 map[string]bool
	revoked                              map[string]bool
	failRead, failReplay, failRevocation bool
}

func (s *testStore) GetGrant(_ context.Context, id string) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failRead {
		return Grant{}, errors.New("STORE-SECRET-DO-NOT-LOG")
	}
	if s.grants != nil {
		g, ok := s.grants[id]
		if !ok {
			return Grant{}, ErrDenied
		}
		return g, nil
	}
	if id != s.grant.ID {
		return Grant{}, ErrDenied
	}
	return s.grant, nil
}
func (s *testStore) ConsumeAssertion(_ context.Context, u AssertionUse) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failReplay {
		return false, errors.New("REPLAY-SECRET-DO-NOT-LOG")
	}
	g := s.grant
	if s.grants != nil {
		g = s.grants[u.GrantID]
	}
	if g.ID != u.GrantID || g.Version != u.GrantVersion || g.Revoked || !g.ExpiresAt.After(u.Now) {
		return false, nil
	}
	key := u.JTIHash
	if s.uses[key] {
		return false, nil
	}
	s.uses[key] = true
	return true, nil
}
func (s *testStore) IsTokenRevoked(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failRevocation {
		return false, errors.New("REVOCATION-SECRET-DO-NOT-LOG")
	}
	return s.revoked[jti], nil
}

type testAudit struct {
	mu     sync.Mutex
	events []Audit
	fail   bool
}

func (a *testAudit) Record(_ context.Context, e Audit) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("AUDIT-SECRET-DO-NOT-LOG")
	}
	a.events = append(a.events, e)
	return nil
}

type testPolicy struct{ deny bool }

func (p *testPolicy) AllowGrant(_ context.Context, g Grant) error {
	if p.deny || g.TenantID != 234 || g.APIAudience != testAPI || (g.Preview != nil && (g.Preview.Origin != "https://preview.example.test" || g.Preview.Audience != testView)) {
		return ErrDenied
	}
	for _, id := range g.UpdatePageIDs {
		if id != "3" && id != "6" {
			return ErrDenied
		}
	}
	return nil
}
func (p *testPolicy) AllowResource(_ context.Context, _ Grant, r Resource) error {
	if p.deny || r.TenantID != 234 || strings.Contains(r.Path, "auth") || strings.Contains(r.Path, "platform") || strings.Contains(r.Path, "domains") {
		return ErrDenied
	}
	return nil
}

type testIssuerAdapter struct {
	key    *ecdsa.PrivateKey
	mutate func(*accessClaims)
	fail   bool
}

func (i *testIssuerAdapter) IssueAgentToken(_ context.Context, r IssueRequest) (string, error) {
	if i.fail {
		return "", errors.New("ISSUER-SECRET-DO-NOT-LOG")
	}
	c := accessClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: testIssuer, Subject: r.Subject, Audience: jwt.ClaimStrings{r.Audience}, IssuedAt: jwt.NewNumericDate(r.IssuedAt), ExpiresAt: jwt.NewNumericDate(r.ExpiresAt), ID: "test-issued-jti"}, TokenUse: "agent_access", GrantID: r.GrantID, GrantVersion: r.GrantVersion, TenantID: r.TenantID, Scope: strings.Join(r.Scopes, " ")}
	if i.mutate != nil {
		i.mutate(&c)
	}
	return sign(i.key, c, "issuer-key")
}
func sign(k *ecdsa.PrivateKey, c jwt.Claims, kid string) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	t.Header["kid"] = kid
	return t.SignedString(k)
}

type fixture struct {
	s        *Service
	store    *testStore
	audit    *testAudit
	issuer   *testIssuerAdapter
	workload *ecdsa.PrivateKey
	now      time.Time
	policy   *testPolicy
}

func setup(t *testing.T) *fixture {
	t.Helper()
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	w, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	g := Grant{ID: "grant-1", Subject: "agent-tina-preview", AssertionIssuer: "https://workload.example.test", KeyID: "workload-key", PublicKey: &w.PublicKey, Version: 1, TenantID: 234, ApprovedBy: "human-owner", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour), APIAudience: testAPI, Scopes: []string{PagesRead, HistoryRead, PagesUpdate, PreviewRead}, UpdatePageIDs: []string{"3", "6"}, Preview: &PreviewGrant{Audience: testView, Origin: "https://preview.example.test", Paths: []string{"/", "/rock-metal", "/contact", "/assets/tina.css"}}}
	f := &fixture{store: &testStore{grant: g, uses: map[string]bool{}, revoked: map[string]bool{}}, audit: &testAudit{}, issuer: &testIssuerAdapter{key: k}, workload: w, now: now, policy: &testPolicy{}}
	s, e := NewService(Options{IssuerURL: testIssuer, TokenEndpoint: testEndpoint, IssuerKeys: map[string]*ecdsa.PublicKey{"issuer-key": &k.PublicKey}, Store: f.store, Issuer: f.issuer, Policy: f.policy, Audit: f.audit, Clock: func() time.Time { return f.now }})
	if e != nil {
		t.Fatal(e)
	}
	f.s = s
	return f
}
func (f *fixture) assertion(t *testing.T, id string, mutate func(*jwt.RegisteredClaims)) string {
	t.Helper()
	c := jwt.RegisteredClaims{Issuer: f.store.grant.AssertionIssuer, Subject: f.store.grant.Subject, Audience: jwt.ClaimStrings{testEndpoint}, IssuedAt: jwt.NewNumericDate(f.now), ExpiresAt: jwt.NewNumericDate(f.now.Add(time.Minute)), ID: id}
	if mutate != nil {
		mutate(&c)
	}
	raw, e := sign(f.workload, c, "workload-key")
	if e != nil {
		t.Fatal(e)
	}
	return raw
}
func (f *fixture) exchange(t *testing.T, scopes []string, aud string) TokenResponse {
	t.Helper()
	out, e := f.s.Exchange(context.Background(), ExchangeRequest{GrantID: "grant-1", Assertion: f.assertion(t, "assertion-1", nil), Audience: aud, Scopes: scopes})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func apiRead() Resource {
	return Resource{TenantID: 234, Audience: testAPI, Scope: PagesRead, Method: "GET", Path: "/api/v1/admin/tenants/234/pages"}
}
func apiUpdate() Resource {
	return Resource{TenantID: 234, Audience: testAPI, Scope: PagesUpdate, PageID: "3", Method: "PUT", Fields: []string{"body_html"}, ExpectedVersion: 3, RootPage: true, Path: "/api/v1/admin/tenants/234/pages/3"}
}

func TestExchangeAndLeastPrivilegeResource(t *testing.T) {
	f := setup(t)
	out := f.exchange(t, []string{PagesRead, HistoryRead, PagesUpdate}, testAPI)
	if out.TokenType != "Bearer" || out.ExpiresIn != 900 {
		t.Fatal("incorrect bounded response")
	}
	for _, r := range []Resource{apiRead(), apiUpdate(), {TenantID: 234, Audience: testAPI, Scope: HistoryRead, Method: "GET", Path: "/api/v1/admin/tenants/234/pages/history"}} {
		p, e := f.s.Authorize(context.Background(), out.AccessToken, r)
		if e != nil || p.Subject != "agent-tina-preview" || p.TenantID != 234 || p.JTIHash == "test-issued-jti" {
			t.Fatalf("typed principal missing: %v", e)
		}
	}
	var parsed accessClaims
	_, _, e := jwt.NewParser().ParseUnverified(out.AccessToken, &parsed)
	if e != nil || parsed.TokenUse != "agent_access" {
		t.Fatal("missing service token discriminator")
	}
}

func TestAssertionBoundaries(t *testing.T) {
	cases := map[string]func(*jwt.RegisteredClaims){
		"issuer":             func(c *jwt.RegisteredClaims) { c.Issuer = "https://other.example.test" },
		"subject":            func(c *jwt.RegisteredClaims) { c.Subject = "human-owner" },
		"audience":           func(c *jwt.RegisteredClaims) { c.Audience = jwt.ClaimStrings{testAPI} },
		"multiple audiences": func(c *jwt.RegisteredClaims) { c.Audience = append(c.Audience, testAPI) },
		"expiry required":    func(c *jwt.RegisteredClaims) { c.ExpiresAt = nil },
		"iat required":       func(c *jwt.RegisteredClaims) { c.IssuedAt = nil },
		"jti required":       func(c *jwt.RegisteredClaims) { c.ID = "" },
		"expired":            func(c *jwt.RegisteredClaims) { c.ExpiresAt = c.IssuedAt },
		"future":             func(c *jwt.RegisteredClaims) { c.IssuedAt = jwt.NewNumericDate(c.IssuedAt.Add(time.Second)) },
		"overlong":           func(c *jwt.RegisteredClaims) { c.ExpiresAt = jwt.NewNumericDate(c.IssuedAt.Add(61 * time.Second)) },
		"stale":              func(c *jwt.RegisteredClaims) { c.IssuedAt = jwt.NewNumericDate(c.IssuedAt.Add(-61 * time.Second)) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			_, e := f.s.Exchange(context.Background(), ExchangeRequest{GrantID: "grant-1", Assertion: f.assertion(t, "jti", mutate), Audience: testAPI, Scopes: []string{PagesRead}})
			if e != ErrDenied || len(f.store.uses) != 0 {
				t.Fatal("invalid assertion consumed/accepted", e)
			}
		})
	}
	for _, kind := range []string{"wrong-key", "wrong-kid", "HS256", "none"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			raw := f.assertion(t, "jti", nil)
			c := jwt.MapClaims{}
			_, _, _ = jwt.NewParser().ParseUnverified(raw, c)
			switch kind {
			case "wrong-key":
				raw, _ = sign(f.issuer.key, c, "workload-key")
			case "wrong-kid":
				raw, _ = sign(f.workload, c, "other-key")
			case "HS256":
				raw, _ = jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte("test-only-secret"))
			case "none":
				raw, _ = jwt.NewWithClaims(jwt.SigningMethodNone, c).SignedString(jwt.UnsafeAllowNoneSignatureType)
			}
			_, e := f.s.Exchange(context.Background(), ExchangeRequest{GrantID: "grant-1", Assertion: raw, Audience: testAPI, Scopes: []string{PagesRead}})
			if e != ErrDenied {
				t.Fatal("untrusted assertion accepted", e)
			}
		})
	}
}

func TestScopesAndCrossTenant(t *testing.T) {
	for _, scopes := range [][]string{nil, {"cms.admin"}, {"admin:auth.users:write"}, {PagesRead, PagesRead}, {PreviewRead, PagesRead}, {"admin:multisite.pages:create"}} {
		t.Run(strings.Join(scopes, "-"), func(t *testing.T) {
			f := setup(t)
			_, e := f.s.Exchange(context.Background(), ExchangeRequest{GrantID: "grant-1", Assertion: f.assertion(t, "jti", nil), Audience: testAPI, Scopes: scopes})
			if e != ErrDenied {
				t.Fatal("excess/ambiguous scopes accepted")
			}
		})
	}
	for _, mutation := range []func(*Grant){func(g *Grant) { g.TenantID = 235 }, func(g *Grant) { g.Scopes = []string{PagesRead}; g.Preview = nil }, func(g *Grant) { g.UpdatePageIDs = []string{"999"} }, func(g *Grant) { g.ExpiresAt = g.CreatedAt.Add(MaxGrantLifetime + time.Second) }, func(g *Grant) { g.Revoked = true }} {
		f := setup(t)
		mutation(&f.store.grant)
		_, e := f.s.Exchange(context.Background(), ExchangeRequest{GrantID: "grant-1", Assertion: f.assertion(t, "jti", nil), Audience: testAPI, Scopes: []string{PagesUpdate}})
		if e != ErrDenied {
			t.Fatal("changed grant accepted", e)
		}
	}
	f := setup(t)
	out := f.exchange(t, []string{PagesRead}, testAPI)
	r := apiRead()
	r.TenantID = 235
	if _, e := f.s.Authorize(context.Background(), out.AccessToken, r); e != ErrDenied {
		t.Fatal("cross tenant allowed")
	}
}

func TestReplayAtomicAcrossServiceInstances(t *testing.T) {
	f := setup(t)
	other, e := NewService(f.s.options)
	if e != nil {
		t.Fatal(e)
	}
	in := ExchangeRequest{GrantID: "grant-1", Assertion: f.assertion(t, "one-use", nil), Audience: testAPI, Scopes: []string{PagesRead}}
	var wg sync.WaitGroup
	success := make(chan bool, 12)
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			s := f.s
			if n%2 == 0 {
				s = other
			}
			_, e := s.Exchange(context.Background(), in)
			success <- e == nil
		}(n)
	}
	wg.Wait()
	close(success)
	count := 0
	for ok := range success {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("replayed assertion issued %d times", count)
	}
}

func TestTokenAndGrantCurrentState(t *testing.T) {
	for _, name := range []string{"token-expired", "grant-expired", "grant-revoked", "version-changed", "token-revoked", "read-unavailable", "revocation-unavailable", "audit-unavailable", "policy-removed"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			out := f.exchange(t, []string{PagesRead}, testAPI)
			switch name {
			case "token-expired":
				f.now = f.now.Add(MaxTokenLifetime)
			case "grant-expired":
				f.store.grant.ExpiresAt = f.now
			case "grant-revoked":
				f.store.grant.Revoked = true
			case "version-changed":
				f.store.grant.Version++
			case "token-revoked":
				f.store.revoked[digest("test-issued-jti")] = true
			case "read-unavailable":
				f.store.failRead = true
			case "revocation-unavailable":
				f.store.failRevocation = true
			case "audit-unavailable":
				f.audit.fail = true
			case "policy-removed":
				f.policy.deny = true
			}
			// A reconstructed service consults the same authoritative adapter; no
			// local token/revocation cache can undo a persisted decision.
			restarted, e := NewService(f.s.options)
			if e != nil {
				t.Fatal(e)
			}
			_, e = restarted.Authorize(context.Background(), out.AccessToken, apiRead())
			if e == nil {
				t.Fatal("current-state denial lost after reconstruction")
			}
		})
	}
}

func TestBodyOnlyRootPageBoundary(t *testing.T) {
	cases := map[string]func(*Resource){
		"page": func(r *Resource) { r.PageID = "4" }, "version": func(r *Resource) { r.ExpectedVersion = 0 }, "blocks": func(r *Resource) { r.HasCanonicalBlocks = true }, "overlay": func(r *Resource) { r.RootPage = false }, "status": func(r *Resource) { r.Fields = append(r.Fields, "status") }, "only status": func(r *Resource) { r.Fields = []string{"status"} }, "delete": func(r *Resource) { r.Method = "DELETE" }, "create": func(r *Resource) { r.Scope = "admin:multisite.pages:create" }, "live": func(r *Resource) { r.TenantID = 42 }, "users": func(r *Resource) { r.Path = "/api/v1/admin/auth/users" }, "read token": func(r *Resource) { r.Scope = PagesRead },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			out := f.exchange(t, []string{PagesUpdate}, testAPI)
			r := apiUpdate()
			mutate(&r)
			if _, e := f.s.Authorize(context.Background(), out.AccessToken, r); e != ErrDenied {
				t.Fatal("forbidden operation authorized", e)
			}
		})
	}
	f := setup(t)
	out := f.exchange(t, []string{PagesRead}, testAPI)
	if _, e := f.s.Authorize(context.Background(), out.AccessToken, apiUpdate()); e != ErrDenied {
		t.Fatal("read-only token wrote")
	}
}

func TestSeparatePreviewPlane(t *testing.T) {
	f := setup(t)
	out := f.exchange(t, []string{PreviewRead}, testView)
	r := Resource{TenantID: 234, Audience: testView, Scope: PreviewRead, Method: "GET", Origin: "https://preview.example.test", Path: "/rock-metal"}
	if _, e := f.s.Authorize(context.Background(), out.AccessToken, r); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Resource){func(r *Resource) { r.Audience = testAPI }, func(r *Resource) { r.Origin = "https://alias.example.test" }, func(r *Resource) { r.Path = "/admin" }, func(r *Resource) { r.Path = "/api/v1/admin" }, func(r *Resource) { r.Path = "/editor" }, func(r *Resource) { r.Path = "/oauth/token" }, func(r *Resource) { r.Path = "/%61dmin" }, func(r *Resource) { r.Path = "/unlisted" }, func(r *Resource) { r.Method = "POST" }, func(r *Resource) { r.TenantID = 235 }} {
		c := r
		mutate(&c)
		if _, e := f.s.Authorize(context.Background(), out.AccessToken, c); e != ErrDenied {
			t.Fatal("preview scope widened", e)
		}
	}
	if _, e := f.s.Authorize(context.Background(), out.AccessToken, apiRead()); e != ErrDenied {
		t.Fatal("view token accepted on API")
	}
}

func TestIssuerOutputStrictAndRedactedFailures(t *testing.T) {
	for name, mutate := range map[string]func(*accessClaims){"audience": func(c *accessClaims) { c.Audience = jwt.ClaimStrings{testView} }, "issuer": func(c *accessClaims) { c.Issuer = "https://other.example.test" }, "subject": func(c *accessClaims) { c.Subject = "human-owner" }, "scope": func(c *accessClaims) { c.Scope = PagesUpdate }, "grant": func(c *accessClaims) { c.GrantVersion++ }, "tenant": func(c *accessClaims) { c.TenantID = 235 }, "expiry": func(c *accessClaims) { c.ExpiresAt = jwt.NewNumericDate(c.ExpiresAt.Add(time.Second)) }, "human": func(c *accessClaims) { c.TokenUse = "human_session" }} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			f.issuer.mutate = mutate
			_, e := f.s.Exchange(context.Background(), ExchangeRequest{GrantID: "grant-1", Assertion: f.assertion(t, "jti", nil), Audience: testAPI, Scopes: []string{PagesRead}})
			if e != ErrUnavailable {
				t.Fatal("unsafe issuer output disclosed", e)
			}
		})
	}
	f := setup(t)
	f.store.failRead = true
	_, e := f.s.Exchange(context.Background(), ExchangeRequest{GrantID: "grant-1", Assertion: "ASSERTION-SECRET-DO-NOT-LOG", Audience: testAPI, Scopes: []string{PagesRead}})
	b, _ := json.Marshal(f.audit.events)
	if e != ErrUnavailable || strings.Contains(string(b), "SECRET") || strings.Contains(e.Error(), "SECRET") {
		t.Fatal("audit/error disclosed sensitive input")
	}
	for _, kind := range []string{"replay", "revocation", "audit", "issuer"} {
		t.Run(kind, func(t *testing.T) {
			f := setup(t)
			switch kind {
			case "replay":
				f.store.failReplay = true
			case "revocation":
				f.store.failRevocation = true
			case "audit":
				f.audit.fail = true
			case "issuer":
				f.issuer.fail = true
			}
			out, e := f.s.Exchange(context.Background(), ExchangeRequest{GrantID: "grant-1", Assertion: f.assertion(t, "RAW-JTI", nil), Audience: testAPI, Scopes: []string{PagesRead}})
			if e != ErrUnavailable || out.AccessToken != "" || strings.Contains(e.Error(), "SECRET") {
				t.Fatal("storage/issuer failure failed open")
			}
			b, _ := json.Marshal(f.audit.events)
			if strings.Contains(string(b), "RAW-JTI") || strings.Contains(string(b), "SECRET") {
				t.Fatal("raw auth data logged")
			}
		})
	}
}

func TestGrantCapsTokenAtFiniteExpiry(t *testing.T) {
	f := setup(t)
	f.store.grant.ExpiresAt = f.now.Add(45 * time.Second)
	out := f.exchange(t, []string{PagesRead}, testAPI)
	if out.ExpiresIn != 45 {
		t.Fatal("grant expiry not applied to issued token")
	}
}

func TestMountedExchangeHTTPBoundary(t *testing.T) {
	f := setup(t)
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "grant_id": {"grant-1"}, "assertion": {f.assertion(t, "http-jti", nil)}, "audience": {testAPI}, "scope": {PagesRead}}
	server := httptest.NewServer(f.s.ExchangeHandler())
	defer server.Close()
	response, e := http.Post(server.URL+"/oauth/agent/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	var result TokenResponse
	if e = json.NewDecoder(response.Body).Decode(&result); e != nil || response.StatusCode != 200 || result.AccessToken == "" || response.Header.Get("Cache-Control") != "private, no-store" {
		t.Fatal("mounted exchange failure", e, response.StatusCode)
	}
	for _, kind := range []string{"cookie", "basic", "query", "duplicate", "refresh", "extra", "alias", "GET"} {
		t.Run(kind, func(t *testing.T) {
			copyForm := url.Values{}
			for k, v := range form {
				copyForm[k] = append([]string(nil), v...)
			}
			p := "/oauth/agent/token"
			method := "POST"
			switch kind {
			case "query":
				p += "?grant_id=grant-1"
			case "duplicate":
				copyForm.Add("grant_id", "grant-1")
			case "refresh":
				copyForm.Set("grant_type", "refresh_token")
			case "extra":
				copyForm.Set("role", "super_admin")
			case "alias":
				p = "/other/oauth/agent/token"
			case "GET":
				method = "GET"
			}
			r := httptest.NewRequest(method, p, strings.NewReader(copyForm.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if kind == "cookie" {
				r.Header.Set("Cookie", "personal=SECRET")
			}
			if kind == "basic" {
				r.SetBasicAuth("human", "SECRET")
			}
			w := httptest.NewRecorder()
			f.s.ExchangeHandler().ServeHTTP(w, r)
			if w.Code < 400 || strings.Contains(w.Body.String(), "SECRET") {
				t.Fatal("alternate auth/request accepted", w.Code)
			}
		})
	}
}

func TestConstructorHasNoInsecureFallback(t *testing.T) {
	f := setup(t)
	for _, mutate := range []func(*Options){func(o *Options) { o.Store = nil }, func(o *Options) { o.Audit = nil }, func(o *Options) { o.Policy = nil }, func(o *Options) { o.Issuer = nil }, func(o *Options) { o.IssuerURL = "http://issuer.example.test" }, func(o *Options) { o.TokenEndpoint = "" }, func(o *Options) { o.IssuerKeys = nil }} {
		o := f.s.options
		mutate(&o)
		if _, e := NewService(o); e != ErrUnavailable {
			t.Fatal("insecure constructor accepted")
		}
	}
}
