package adminui_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-auth/adminui"
)

func TestConfigHTMLInjectsRuntimeConfig(t *testing.T) {
	html, err := adminui.ConfigHTML(adminui.Options{
		DescribePath: "/api/v1/admin/auth/config",
		ValidatePath: "/api/v1/admin/auth/config/validate",
	})
	if err != nil {
		t.Fatalf("ConfigHTML: %v", err)
	}
	body := string(html)
	for _, want := range []string{
		`data-auth-admin-config-ui="1"`,
		`window.__WORKFLOW_AUTH_CONFIG_UI__=`,
		`"describePath":"/api/v1/admin/auth/config"`,
		`"validatePath":"/api/v1/admin/auth/config/validate"`,
		`Authentication Settings`,
		`Save Settings`,
		`if(value==="secret"){return "password";}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("config html missing %q: %s", want, body)
		}
	}
	if strings.TrimSpace(body) == "/admin/auth/config" {
		t.Fatal("config html rendered only the route path")
	}
}

func TestConfigHTMLDefaultsMatchContributionMetadata(t *testing.T) {
	html, err := adminui.ConfigHTML(adminui.Options{})
	if err != nil {
		t.Fatalf("ConfigHTML: %v", err)
	}
	body := string(html)
	for _, want := range []string{
		`"adminBasePath":"/admin/auth/config"`,
		`"describePath":"/api/admin/auth/config"`,
		`"validatePath":"/api/admin/auth/config/validate"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("default config html missing %q: %s", want, body)
		}
	}
}

func TestHandlerServesConfigUI(t *testing.T) {
	handler := adminui.Handler(adminui.Options{
		AdminBasePath: "/admin/auth/config",
		DescribePath:  "/api/v1/admin/auth/config",
		ValidatePath:  "/api/v1/admin/auth/config/validate",
	})

	req := httptest.NewRequest(http.MethodGet, "https://admin.example.test/admin/auth/config", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("GET /admin/auth/config status = %d, want 301", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/admin/auth/config/" {
		t.Fatalf("Location = %q, want /admin/auth/config/", got)
	}

	req = httptest.NewRequest(http.MethodGet, "https://admin.example.test/admin/auth/config/", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/auth/config/ status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"describePath":"/api/v1/admin/auth/config"`) {
		t.Fatalf("runtime config missing from page: %s", rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodHead, "https://admin.example.test/admin/auth/config/", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD /admin/auth/config/ status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("HEAD response body len = %d, want 0", rec.Body.Len())
	}
}

func TestHandlerRejectsMutations(t *testing.T) {
	handler := adminui.Handler(adminui.Options{})
	req := httptest.NewRequest(http.MethodPost, "https://admin.example.test/admin/auth/config/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q, want GET, HEAD", got)
	}
}
