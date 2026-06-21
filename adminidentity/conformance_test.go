package adminidentity

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConformancePassesForMountedIdentitySurface(t *testing.T) {
	h := newTestHandler(t, &testStores{
		credentials: []Credential{{ID: "cred-1", UserID: "user-1", Kind: CredentialKindTOTP}},
	})

	result := CheckConformance(ConformanceOptions{
		Handler: h,
		Routes: DefaultRoutesForOptions(Options{
			PagePath:        "/admin/account/profile/",
			ProfilePath:     "/api/v1/admin/account/profile",
			CredentialsPath: "/api/v1/admin/account/credentials",
			UsersPath:       "/api/v1/admin/auth/users",
			SetupRedeemPath: "/api/v1/admin/setup/redeem",
			TOTPBeginPath:   "/api/v1/admin/account/totp/begin",
			TOTPVerifyPath:  "/api/v1/admin/account/totp/verify",
		}),
	})

	if !result.Pass {
		t.Fatalf("conformance failed: %#v", result.Failures)
	}
}

func TestConformanceNamesMissingRoute(t *testing.T) {
	result := CheckConformance(ConformanceOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/admin/account/profile/" {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("profile"))
				return
			}
			http.NotFound(w, r)
		}),
		Routes: []RouteProbe{
			{Name: "profile page", Method: http.MethodGet, Path: "/admin/account/profile/", ExpectedStatus: http.StatusOK, RequireBody: true},
			{Name: "credentials api", Method: http.MethodGet, Path: "/api/v1/admin/account/credentials", ExpectedStatus: http.StatusOK, RequireBody: true},
		},
	})

	if result.Pass {
		t.Fatal("conformance passed for missing credentials route")
	}
	if len(result.Failures) != 1 {
		t.Fatalf("failures len = %d, want 1: %#v", len(result.Failures), result.Failures)
	}
	if !strings.Contains(result.Failures[0], "credentials api") || !strings.Contains(result.Failures[0], "/api/v1/admin/account/credentials") {
		t.Fatalf("failure does not name route: %#v", result.Failures)
	}
}

func TestConformanceDetectsEmptyContributionPage(t *testing.T) {
	result := CheckConformance(ConformanceOptions{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		Routes: []RouteProbe{{Name: "profile page", Method: http.MethodGet, Path: "/admin/account/profile/", ExpectedStatus: http.StatusOK, RequireBody: true}},
	})

	if result.Pass {
		t.Fatal("conformance passed for empty page")
	}
	if !strings.Contains(result.Failures[0], "empty body") {
		t.Fatalf("failure = %#v, want empty body", result.Failures)
	}
}

func TestConformanceWorksWithHTTPServer(t *testing.T) {
	h := newTestHandler(t, &testStores{})
	server := httptest.NewServer(h)
	defer server.Close()

	result := CheckConformance(ConformanceOptions{
		BaseURL: server.URL,
		Client:  server.Client(),
		Routes:  []RouteProbe{{Name: "profile page", Method: http.MethodGet, Path: "/admin/account/profile/", ExpectedStatus: http.StatusOK, RequireBody: true}},
	})

	if !result.Pass {
		t.Fatalf("conformance failed: %#v", result.Failures)
	}
}
