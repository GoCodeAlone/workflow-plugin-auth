package agentidentity

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ExchangeHandler handles only the exact configured RFC7523 token endpoint.
// There is no client-secret, cookie, human-session or refresh-token fallback.
// The TLS/reverse-proxy gate is host-owned and MUST reject untrusted forwarding
// metadata. Do not mount Workflow's generic OAuth issuer beside this handler.
func (s *Service) ExchangeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		privateHeaders(w)
		endpoint, _ := parseHTTPS(s.options.TokenEndpoint)
		if r.URL.Path != endpoint.Path || r.URL.RawPath != "" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		content, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || content != "application/x-www-form-urlencoded" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			httpError(w, ErrDenied)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 20000)
		if err = r.ParseForm(); err != nil {
			httpError(w, ErrDenied)
			return
		}
		for key, values := range r.PostForm {
			if len(values) != 1 || (key != "grant_type" && key != "grant_id" && key != "assertion" && key != "audience" && key != "scope") {
				httpError(w, ErrDenied)
				return
			}
		}
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			httpError(w, ErrDenied)
			return
		}
		scopes := strings.Fields(r.PostForm.Get("scope"))
		if strings.Join(scopes, " ") != r.PostForm.Get("scope") {
			httpError(w, ErrDenied)
			return
		}
		response, err := s.Exchange(r.Context(), ExchangeRequest{GrantID: r.PostForm.Get("grant_id"), Assertion: r.PostForm.Get("assertion"), Audience: r.PostForm.Get("audience"), Scopes: scopes})
		if err != nil {
			httpError(w, err)
			return
		}
		_ = json.NewEncoder(w).Encode(response)
	})
}

type ManagementOptions struct {
	Path        string
	OwnerOrigin string
	PagePath    string
	Owners      OwnerPolicy
	// Tenants supplies immutable owner-UI declarations when Policy is wrapped
	// by a host's current preview gate. It confers no authority: every visible
	// proposal must also pass the service's required Policy and OwnerPolicy.
	// If omitted, the UI uses Policy directly when it is a *TenantPolicy.
	Tenants *TenantPolicy
}

type proposal struct {
	Subject         string        `json:"subject"`
	AssertionIssuer string        `json:"assertion_issuer"`
	KeyID           string        `json:"key_id"`
	PublicKeyPEM    string        `json:"public_key_pem"`
	TenantID        int64         `json:"tenant_id"`
	ExpiresAt       time.Time     `json:"expires_at"`
	APIAudience     string        `json:"api_audience"`
	Scopes          []string      `json:"scopes"`
	UpdatePageIDs   []string      `json:"update_page_ids"`
	Preview         *PreviewGrant `json:"preview"`
	// The policy adapter must ALSO authorize the exact requested boundary.
	Confirmed bool `json:"confirmed"`
}

// ManagementHandler owns reusable registration/list/revocation behavior.
// Mount only behind existing HUMAN owner authorization and CSRF protection.
// Its typed resolver/policy cannot be replaced with a service principal. Hosts
// are responsible for a durable transaction plus audit/outbox for management
// mutations; no rollback can safely erase an already applied revoke.
func (s *Service) ManagementHandler(o ManagementOptions) (http.Handler, error) {
	// Management and validation must use the same authoritative adapter. A
	// separately configured manager could report a successful revoke while the
	// store used by Authorize still admits the old grant and its tokens.
	manager, ok := s.options.Store.(GrantManager)
	if !ok || o.Owners == nil || !managementPath(o.Path) || !httpsOrigin(o.OwnerOrigin) {
		return nil, ErrUnavailable
	}
	if o.PagePath != "" && (!managementPagePath(o.PagePath) || o.PagePath == o.Path) {
		return nil, ErrUnavailable
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		privateHeaders(w)
		if r.URL.RawPath != "" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Path != o.Path && r.URL.Path != o.Path+"/revoke" && (o.PagePath == "" || r.URL.Path != o.PagePath) {
			http.NotFound(w, r)
			return
		}
		owner, err := o.Owners.ResolveOwner(r)
		if err != nil || !identifier(owner.ID) {
			httpError(w, ErrDenied)
			return
		}
		if r.URL.Path == o.PagePath {
			if r.Method != "GET" {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			policy := o.Tenants
			if policy == nil {
				policy, _ = s.options.Policy.(*TenantPolicy)
			}
			if policy == nil {
				httpError(w, ErrUnavailable)
				return
			}
			visible := []TenantConfig{}
			for _, c := range policy.configs() {
				proposed := Grant{TenantID: c.TenantID, APIAudience: c.APIAudience}
				if o.Owners.AuthorizeOwner(r.Context(), owner, "propose", proposed) == nil && s.options.Policy.AllowGrant(r.Context(), proposed) == nil {
					visible = append(visible, c)
				}
			}
			if len(visible) == 0 {
				httpError(w, ErrDenied)
				return
			}
			body, err := managementHTML(o, visible)
			if err != nil {
				httpError(w, ErrUnavailable)
				return
			}
			if err = s.record(r.Context(), Audit{Operation: "grant-page", Decision: "allow", Reason: "authorized", OwnerID: owner.ID}); err != nil {
				httpError(w, err)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(body)
			return
		}
		if r.URL.Path == o.Path && r.Method == http.MethodGet {
			if err = o.Owners.AuthorizeOwner(r.Context(), owner, "list", Grant{}); err != nil {
				httpError(w, ErrDenied)
				return
			}
			grants, err := manager.ListGrants(r.Context(), owner)
			if err != nil {
				httpError(w, ErrUnavailable)
				return
			}
			visible := make([]Grant, 0, len(grants))
			for _, g := range grants {
				if o.Owners.AuthorizeOwner(r.Context(), owner, "read", g) == nil && s.options.Policy.AllowGrant(r.Context(), g) == nil {
					visible = append(visible, g)
				}
			}
			if err = s.record(r.Context(), Audit{Operation: "grant-list", Decision: "allow", Reason: "authorized", OwnerID: owner.ID}); err != nil {
				httpError(w, err)
				return
			}
			_ = json.NewEncoder(w).Encode(visible)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Existing verified HUMAN cookie sessions remain usable by the owner
		// surface. A pinned Origin/Host and fetch-site check block ambient CSRF;
		// the resolver must reject service principals, even with a valid token.
		origin, _ := parseHTTPS(o.OwnerOrigin)
		if r.Header.Get("Origin") != o.OwnerOrigin || r.Host != origin.Host || len(r.Header.Values("Authorization")) > 1 || (r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") {
			httpError(w, ErrDenied)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 20000)
		if r.URL.Path == o.Path+"/revoke" {
			var input struct {
				ID              string `json:"id"`
				ExpectedVersion int64  `json:"expected_version"`
				Confirmed       bool   `json:"confirmed"`
			}
			if !readJSON(r, &input) || !input.Confirmed || input.ExpectedVersion <= 0 {
				httpError(w, ErrDenied)
				return
			}
			g, err := s.options.Store.GetGrant(r.Context(), input.ID)
			if err != nil {
				httpError(w, ErrUnavailable)
				return
			}
			if !identifier(input.ID) || g.ID != input.ID || g.Version != input.ExpectedVersion {
				httpError(w, ErrConflict)
				return
			}
			if err = o.Owners.AuthorizeOwner(r.Context(), owner, "revoke", g); err != nil {
				httpError(w, ErrDenied)
				return
			}
			if err = s.options.Policy.AllowGrant(r.Context(), g); err != nil {
				httpError(w, ErrDenied)
				return
			}
			if err = s.record(r.Context(), Audit{Operation: "grant-revoke", Decision: "allow", Reason: "approved", GrantID: g.ID, GrantVersion: g.Version, TenantID: g.TenantID, OwnerID: owner.ID, Subject: g.Subject}); err != nil {
				httpError(w, err)
				return
			}
			if err = manager.RevokeGrant(r.Context(), g.ID, g.Version, owner.ID, s.now()); err != nil {
				if err != ErrConflict {
					err = ErrUnavailable
				}
				httpError(w, err)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		var input proposal
		if !readJSON(r, &input) || !input.Confirmed {
			httpError(w, ErrDenied)
			return
		}
		block, rest := pem.Decode([]byte(input.PublicKeyPEM))
		if block == nil || block.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
			httpError(w, ErrDenied)
			return
		}
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			httpError(w, ErrDenied)
			return
		}
		public, ok := asPublicKey(key)
		if !ok {
			httpError(w, ErrDenied)
			return
		}
		id := make([]byte, 16)
		if _, err = rand.Read(id); err != nil {
			httpError(w, ErrUnavailable)
			return
		}
		g := Grant{ID: hex.EncodeToString(id), Subject: input.Subject, AssertionIssuer: input.AssertionIssuer, KeyID: input.KeyID, PublicKey: public, Version: 1, TenantID: input.TenantID, ApprovedBy: owner.ID, CreatedAt: s.now(), ExpiresAt: input.ExpiresAt.UTC().Truncate(time.Second), APIAudience: input.APIAudience, Scopes: input.Scopes, UpdatePageIDs: input.UpdatePageIDs, Preview: input.Preview}
		if !validGrant(g, s.now()) {
			httpError(w, ErrDenied)
			return
		}
		if err = s.options.Policy.AllowGrant(r.Context(), g); err != nil {
			httpError(w, ErrDenied)
			return
		}
		if err = o.Owners.AuthorizeOwner(r.Context(), owner, "create", g); err != nil {
			httpError(w, ErrDenied)
			return
		}
		if err = s.record(r.Context(), Audit{Operation: "grant-create", Decision: "allow", Reason: "approved", GrantID: g.ID, GrantVersion: 1, TenantID: g.TenantID, OwnerID: owner.ID, Subject: g.Subject}); err != nil {
			httpError(w, err)
			return
		}
		if err = manager.CreateGrant(r.Context(), g); err != nil {
			if err != ErrConflict {
				err = ErrUnavailable
			}
			httpError(w, err)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(g)
	}), nil
}

func privateHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Vary", "Authorization")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}
func httpError(w http.ResponseWriter, err error) {
	code := http.StatusUnauthorized
	if err == ErrUnavailable {
		code = http.StatusServiceUnavailable
	}
	if err == ErrConflict {
		code = http.StatusConflict
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
func readJSON(r *http.Request, v any) bool {
	content, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || content != "application/json" {
		return false
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	return d.Decode(v) == nil && d.Decode(new(any)) == io.EOF
}
func parseHTTPS(raw string) (*url.URL, error) { return url.Parse(raw) }
func managementPath(p string) bool {
	return strings.HasPrefix(p, "/api/") && len(p) > 5 && !strings.HasSuffix(p, "/") && !strings.ContainsAny(p, "%?#\\\t\r\n ") && strings.TrimSpace(p) == p && !strings.Contains(p, "//") && !strings.Contains(p, "/.")
}
func managementPagePath(p string) bool {
	return strings.HasPrefix(p, "/admin/") && len(p) > 7 && !strings.ContainsAny(p, "%?#\\\t\r\n ") && !strings.HasSuffix(p, "/") && !strings.Contains(p, "//") && !strings.Contains(p, "/.")
}
func asPublicKey(key any) (*ecdsa.PublicKey, bool) {
	k, ok := key.(*ecdsa.PublicKey)
	return k, ok && publicKey(k)
}
