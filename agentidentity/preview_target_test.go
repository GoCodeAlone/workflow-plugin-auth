package agentidentity

import (
	"context"
	"strings"
	"testing"
)

func TestPreviewQueryRequiresExactCurrentGrantAndTenantTarget(t *testing.T) {
	f := setup(t)
	configs := tenantConfigs()
	target := "/contact?interest=voice-study"
	configs[0].Preview.Paths = append(configs[0].Preview.Paths, target)
	policy, err := NewTenantPolicy(configs)
	if err != nil {
		t.Fatal(err)
	}
	f.store.grant.Preview = configs[0].Preview
	options := f.s.options
	options.Policy = policy
	f.s, err = NewService(options)
	if err != nil {
		t.Fatal(err)
	}
	out := f.exchange(t, []string{PreviewRead}, testView)
	resource := Resource{TenantID: 234, Audience: testView, Scope: PreviewRead, Method: "GET", Origin: configs[0].Preview.Origin, Path: "/contact", Query: "interest=voice-study"}
	for _, method := range []string{"GET", "HEAD"} {
		resource.Method = method
		if _, err := f.s.Authorize(context.Background(), out.AccessToken, resource); err != nil {
			t.Fatalf("exact query %s refused: %v", method, err)
		}
	}
	for _, mutate := range []func(*Resource){
		func(r *Resource) { r.Query = "interest=booking" },
		func(r *Resource) { r.Query = "interest=voice-study&other=1" },
		func(r *Resource) { r.Query = "interest=voice-study&interest=voice-study" },
		func(r *Resource) { r.Query = "interest=%76oice-study" },
		func(r *Resource) { r.Query = "interest=voice-study&" },
		func(r *Resource) { r.Query = "interest=voice-study;other=1" },
		func(r *Resource) { r.Path = "/contact?interest=voice-study"; r.Query = "" },
		func(r *Resource) { r.Path = "/admin" },
		func(r *Resource) { r.Method = "POST" },
		func(r *Resource) { r.Origin = configs[1].Preview.Origin },
		func(r *Resource) { r.Audience = configs[1].Preview.Audience },
		func(r *Resource) { r.TenantID = 345 },
	} {
		changed := resource
		mutate(&changed)
		if _, err := f.s.Authorize(context.Background(), out.AccessToken, changed); err != ErrDenied {
			t.Fatalf("query ceiling widened: %v", err)
		}
	}
	// A current grant narrowing removes authority from the already-issued token.
	f.store.grant.Preview = &PreviewGrant{Audience: testView, Origin: configs[0].Preview.Origin, Paths: []string{"/contact"}}
	if _, err := f.s.Authorize(context.Background(), out.AccessToken, resource); err != ErrDenied {
		t.Fatal("bare path inherited query authority")
	}
	if policy.AllowResource(context.Background(), f.store.grant, resource) != nil {
		// The host declaration still lists the target; the service's current-grant
		// check above is what denies the narrowed persisted grant.
		t.Fatal("unchanged host declaration unexpectedly lost its target")
	}
	other := f.store.grant
	other.TenantID, other.APIAudience, other.Preview = 345, configs[1].APIAudience, configs[1].Preview
	other.UpdatePageIDs = configs[1].UpdatePageIDs
	otherResource := resource
	otherResource.TenantID, otherResource.Audience, otherResource.Origin = 345, configs[1].Preview.Audience, configs[1].Preview.Origin
	if policy.AllowResource(context.Background(), other, otherResource) != ErrDenied {
		t.Fatal("second tenant inherited the first tenant's query declaration")
	}
	apiFixture := setup(t)
	apiToken := apiFixture.exchange(t, []string{PagesRead}, testAPI)
	api := apiRead()
	if _, err := apiFixture.s.Authorize(context.Background(), apiToken.AccessToken, api); err != nil {
		t.Fatal("unchanged API read refused")
	}
	api.Query = "interest=voice-study"
	if _, err := apiFixture.s.Authorize(context.Background(), apiToken.AccessToken, api); err != ErrDenied {
		t.Fatal("preview query accepted on API plane")
	}
}

func TestPreviewQueryInvalidDeclarationsAndStoredGrantsRefuse(t *testing.T) {
	for _, target := range []string{
		"/contact?", "/contact?interest=", "/contact?interest", "/contact?interest=voice-study&", "/contact?interest=voice-study&interest=voice-study",
		"/contact?interest=%76oice-study", "/contact?%69nterest=voice-study", "/contact?interest=voice+study", "/contact?interest=voice-study#x",
		"/contact?interest=voice-study;other=1", "/contact?z=1&a=2", "/contact?interest=" + strings.Repeat("a", 129), "/admin?interest=voice-study",
	} {
		t.Run(target, func(t *testing.T) {
			configs := tenantConfigs()
			configs[0].Preview.Paths = append(configs[0].Preview.Paths, target)
			if _, err := NewTenantPolicy(configs); err != ErrUnavailable {
				t.Fatal("invalid query declaration accepted")
			}
			f := setup(t)
			f.store.grant.Preview.Paths = append(f.store.grant.Preview.Paths, target)
			if ValidateGrantForStorage(f.store.grant) != ErrDenied {
				t.Fatal("invalid persisted query grant accepted")
			}
			_, err := f.s.Exchange(context.Background(), ExchangeRequest{GrantID: f.store.grant.ID, Assertion: f.assertion(t, "invalid-query-grant", nil), Audience: testView, Scopes: []string{PreviewRead}})
			if err != ErrDenied {
				t.Fatal("invalid current query grant issued a token")
			}
		})
	}
}
