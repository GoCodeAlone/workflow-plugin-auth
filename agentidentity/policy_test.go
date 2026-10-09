package agentidentity

import (
	"context"
	"testing"
)

func tenantConfigs() []TenantConfig {
	return []TenantConfig{
		{TenantID: 234, APIAudience: testAPI, PagesPath: "/api/v1/admin/tenants/234/pages", HistoryPath: "/api/v1/admin/tenants/234/pages/history", Scopes: []string{PagesRead, HistoryRead, PagesUpdate, PreviewRead}, UpdatePageIDs: []string{"3", "6"}, Preview: &PreviewGrant{Audience: testView, Origin: "https://preview.example.test", Paths: []string{"/", "/rock-metal", "/contact", "/assets/tina.css"}}},
		{TenantID: 345, APIAudience: "https://other-preview.example.test/api", PagesPath: "/api/v1/admin/tenants/345/pages", HistoryPath: "/api/v1/admin/tenants/345/pages/history", Scopes: []string{PagesRead, HistoryRead, PagesUpdate, PreviewRead}, UpdatePageIDs: []string{"17", "18"}, Preview: &PreviewGrant{Audience: "https://other-preview.example.test/view", Origin: "https://other-preview.example.test", Paths: []string{"/", "/about", "/assets/site.css"}}},
	}
}

func TestDeclarativeTwoTenantAccessAndIsolation(t *testing.T) {
	f := setup(t)
	config := tenantConfigs()
	p, e := NewTenantPolicy(config)
	if e != nil {
		t.Fatal(e)
	}
	a := f.store.grant
	b := a
	b.ID = "grant-2"
	b.Subject = "agent-other-preview"
	b.TenantID = 345
	b.APIAudience = config[1].APIAudience
	b.UpdatePageIDs = config[1].UpdatePageIDs
	b.Preview = config[1].Preview
	f.store.grants = map[string]Grant{a.ID: a, b.ID: b}
	o := f.s.options
	o.Policy = p
	service, e := NewService(o)
	if e != nil {
		t.Fatal(e)
	}
	for _, g := range []Grant{a, b} {
		f.store.grant = g // assertion fixture selects the grant's verified subject.
		out, e := service.Exchange(context.Background(), ExchangeRequest{GrantID: g.ID, Assertion: f.assertion(t, g.ID+"-assertion", nil), Audience: g.APIAudience, Scopes: []string{PagesRead, PagesUpdate}})
		if e != nil {
			t.Fatal("configured tenant exchange", e)
		}
		c := config[0]
		other := config[1]
		if g.TenantID == 345 {
			c, other = other, c
		}
		read := Resource{TenantID: c.TenantID, Audience: c.APIAudience, Scope: PagesRead, Method: "GET", Path: c.PagesPath}
		write := Resource{TenantID: c.TenantID, Audience: c.APIAudience, Scope: PagesUpdate, Method: "PUT", Path: c.PagesPath + "/" + c.UpdatePageIDs[0], PageID: c.UpdatePageIDs[0], RootPage: true, Fields: []string{"body_html"}, ExpectedVersion: 1}
		for _, r := range []Resource{read, write} {
			if _, e := service.Authorize(context.Background(), out.AccessToken, r); e != nil {
				t.Fatal("configured resource denied", e)
			}
		}
		wrong := read
		wrong.TenantID = other.TenantID
		wrong.Path = other.PagesPath
		wrong.Audience = other.APIAudience
		if _, e := service.Authorize(context.Background(), out.AccessToken, wrong); e == nil {
			t.Fatal("cross-tenant token accepted")
		}
		wrong = write
		wrong.PageID = other.UpdatePageIDs[0]
		wrong.Path = c.PagesPath + "/" + wrong.PageID
		if _, e := service.Authorize(context.Background(), out.AccessToken, wrong); e == nil {
			t.Fatal("other tenant page ceiling accepted")
		}
		view, e := service.Exchange(context.Background(), ExchangeRequest{GrantID: g.ID, Assertion: f.assertion(t, g.ID+"-view", nil), Audience: g.Preview.Audience, Scopes: []string{PreviewRead}})
		if e != nil {
			t.Fatal(e)
		}
		r := Resource{TenantID: c.TenantID, Audience: c.Preview.Audience, Scope: PreviewRead, Method: "HEAD", Origin: c.Preview.Origin, Path: "/"}
		if _, e := service.Authorize(context.Background(), view.AccessToken, r); e != nil {
			t.Fatal(e)
		}
		r.Origin = other.Preview.Origin
		if _, e := service.Authorize(context.Background(), view.AccessToken, r); e == nil {
			t.Fatal("alternate tenant origin accepted")
		}
	}
	// A third/live tenant omitted from configuration is denied, even if a store
	// mistakenly supplies an apparently valid signed/approved grant for it.
	live := a
	live.TenantID = 999
	if p.AllowGrant(context.Background(), live) != ErrDenied {
		t.Fatal("unconfigured tenant admitted")
	}
	// The copied policy remains immutable when a caller edits source config.
	config[0].UpdatePageIDs[0] = "999"
	config[0].Preview.Paths[0] = "/admin"
	if p.AllowGrant(context.Background(), a) != nil {
		t.Fatal("source config alias mutated policy")
	}
}

func TestDeclaredRouteClassificationIsExact(t *testing.T) {
	f := setup(t)
	p, e := NewTenantPolicy(tenantConfigs())
	if e != nil {
		t.Fatal(e)
	}
	for _, route := range []string{"/api/v1/admin/auth/users", "/api/v1/admin/tenants/234/pages/history", "/api/v1/admin/tenants/345/pages", "/api/v1/admin/tenants/234/pages/", "/api/v1/admin/tenants/234/%70ages", "/api/v1/admin/tenants/234/pages?tenant=345"} {
		r := apiRead()
		r.Path = route
		if p.AllowResource(context.Background(), f.store.grant, r) != ErrDenied {
			t.Fatal("misclassified route admitted", route)
		}
	}
	r := apiRead()
	r.PageID = "history"
	r.Path += "/history"
	if p.AllowResource(context.Background(), f.store.grant, r) != ErrDenied {
		t.Fatal("page read mislabeled history scope")
	}
	for _, mutate := range []func([]TenantConfig){func(c []TenantConfig) { c[1].TenantID = c[0].TenantID }, func(c []TenantConfig) { c[0].Preview.Paths = append(c[0].Preview.Paths, "/admin") }, func(c []TenantConfig) { c[0].Scopes = append(c[0].Scopes, "cms.admin") }, func(c []TenantConfig) { c[0].UpdatePageIDs = nil }} {
		config := tenantConfigs()
		mutate(config)
		if _, e := NewTenantPolicy(config); e != ErrUnavailable {
			t.Fatal("invalid declaration accepted")
		}
	}
}

func TestAssertionOneUseAcrossTenantsAndVersionChanges(t *testing.T) {
	f := setup(t)
	config := tenantConfigs()
	p, e := NewTenantPolicy(config)
	if e != nil {
		t.Fatal(e)
	}
	a := f.store.grant
	b := a
	b.ID = "grant-2"
	b.TenantID = 345
	b.APIAudience = config[1].APIAudience
	b.UpdatePageIDs = config[1].UpdatePageIDs
	b.Preview = config[1].Preview
	f.store.grants = map[string]Grant{a.ID: a, b.ID: b}
	o := f.s.options
	o.Policy = p
	s, e := NewService(o)
	if e != nil {
		t.Fatal(e)
	}
	raw := f.assertion(t, "global-one-use", nil)
	if _, e = s.Exchange(context.Background(), ExchangeRequest{GrantID: a.ID, Assertion: raw, Audience: a.APIAudience, Scopes: []string{PagesRead}}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Exchange(context.Background(), ExchangeRequest{GrantID: b.ID, Assertion: raw, Audience: b.APIAudience, Scopes: []string{PagesRead}}); e != ErrDenied {
		t.Fatal("same assertion reused for another tenant", e)
	}
	a.Version++
	f.store.grants[a.ID] = a
	if _, e = s.Exchange(context.Background(), ExchangeRequest{GrantID: a.ID, Assertion: raw, Audience: a.APIAudience, Scopes: []string{PagesRead}}); e != ErrDenied {
		t.Fatal("same assertion reused after version change", e)
	}
}
