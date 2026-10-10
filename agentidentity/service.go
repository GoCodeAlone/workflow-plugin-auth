package agentidentity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Service struct{ options Options }

type accessClaims struct {
	jwt.RegisteredClaims
	TokenUse     string `json:"token_use"`
	GrantID      string `json:"grant_id"`
	GrantVersion int64  `json:"grant_version"`
	TenantID     int64  `json:"tenant_id"`
	Scope        string `json:"scope"`
}

func NewService(o Options) (*Service, error) {
	if !httpsURL(o.IssuerURL) || !httpsURL(o.TokenEndpoint) || o.Store == nil || o.Issuer == nil || o.Policy == nil || o.Audit == nil || len(o.IssuerKeys) == 0 {
		return nil, ErrUnavailable
	}
	keys := make(map[string]*ecdsa.PublicKey, len(o.IssuerKeys))
	for id, k := range o.IssuerKeys {
		if !identifier(id) || !publicKey(k) {
			return nil, ErrUnavailable
		}
		// Copy the curve coordinates so external configuration mutation cannot
		// silently replace a trusted key after construction.
		keys[id] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).Set(k.X), Y: new(big.Int).Set(k.Y)}
	}
	o.IssuerKeys = keys
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return &Service{options: o}, nil
}

func (s *Service) now() time.Time { return s.options.Clock().UTC().Truncate(time.Second) }

func (s *Service) current(ctx context.Context, id string) (Grant, error) {
	if !identifier(id) {
		return Grant{}, ErrDenied
	}
	g, err := s.options.Store.GetGrant(ctx, id)
	if err != nil {
		return Grant{}, ErrUnavailable
	}
	if g.ID != id || !validGrant(g, s.now()) {
		return Grant{}, ErrDenied
	}
	if err = s.options.Policy.AllowGrant(ctx, g); err != nil {
		return Grant{}, ErrDenied
	}
	return g, nil
}

func (s *Service) Exchange(ctx context.Context, in ExchangeRequest) (TokenResponse, error) {
	g, err := s.current(ctx, in.GrantID)
	if err != nil {
		return TokenResponse{}, s.reject(ctx, "exchange", Grant{}, err)
	}
	if len(in.Assertion) > 16384 || in.Assertion == "" || !audienceScopes(g, in.Audience, in.Scopes) {
		return TokenResponse{}, s.reject(ctx, "exchange", g, ErrDenied)
	}
	now := s.now()
	c := new(jwt.RegisteredClaims)
	t, err := jwt.ParseWithClaims(in.Assertion, c, func(t *jwt.Token) (any, error) {
		if t.Header["kid"] != g.KeyID {
			return nil, ErrDenied
		}
		return g.PublicKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(g.AssertionIssuer), jwt.WithSubject(g.Subject), jwt.WithAudience(s.options.TokenEndpoint), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || t == nil || !t.Valid || !exactAudience(c.Audience, s.options.TokenEndpoint) || c.IssuedAt == nil || c.ExpiresAt == nil || !identifier(c.ID) || !shortTimes(c.IssuedAt, c.ExpiresAt, now, MaxAssertionLifetime) {
		return TokenResponse{}, s.reject(ctx, "exchange", g, ErrDenied)
	}
	used, err := s.options.Store.ConsumeAssertion(ctx, AssertionUse{GrantID: g.ID, GrantVersion: g.Version, JTIHash: digest(c.Issuer + "\x00" + c.Subject + "\x00" + g.KeyID + "\x00" + c.ID), ExpiresAt: c.ExpiresAt.Time, Now: now})
	if err != nil {
		return TokenResponse{}, s.reject(ctx, "exchange", g, ErrUnavailable)
	}
	if !used {
		return TokenResponse{}, s.reject(ctx, "exchange", g, ErrDenied)
	}
	exp := now.Add(MaxTokenLifetime)
	if g.ExpiresAt.Before(exp) {
		exp = g.ExpiresAt.UTC().Truncate(time.Second)
	}
	if !exp.After(now) {
		return TokenResponse{}, s.reject(ctx, "exchange", g, ErrDenied)
	}
	request := IssueRequest{Subject: g.Subject, Audience: in.Audience, GrantID: g.ID, GrantVersion: g.Version, TenantID: g.TenantID, Scopes: slices.Clone(in.Scopes), IssuedAt: now, ExpiresAt: exp}
	raw, err := s.options.Issuer.IssueAgentToken(ctx, request)
	if err != nil {
		return TokenResponse{}, s.reject(ctx, "exchange", g, ErrUnavailable)
	}
	// Verify the issuer adapter's complete output before disclosing it. This
	// catches accidental human/legacy issuer wiring, audience/scope widening,
	// overlong expiry and grant mutation during issuance.
	issued, err := s.parseAccess(raw, in.Audience, now)
	if err != nil || issued.Subject != g.Subject || issued.GrantID != g.ID || issued.GrantVersion != g.Version || issued.TenantID != g.TenantID || issued.IssuedAt.Time.Unix() != now.Unix() || issued.ExpiresAt.Time.Unix() != exp.Unix() || !sameScopes(strings.Fields(issued.Scope), in.Scopes) {
		return TokenResponse{}, s.reject(ctx, "exchange", g, ErrUnavailable)
	}
	current, err := s.current(ctx, g.ID)
	if err != nil || current.Version != g.Version || !audienceScopes(current, in.Audience, in.Scopes) {
		return TokenResponse{}, s.reject(ctx, "exchange", g, ErrDenied)
	}
	revoked, err := s.options.Store.IsTokenRevoked(ctx, digest(issued.ID))
	if err != nil {
		return TokenResponse{}, s.reject(ctx, "exchange", g, ErrUnavailable)
	}
	if revoked {
		return TokenResponse{}, s.reject(ctx, "exchange", g, ErrDenied)
	}
	if err = s.record(ctx, Audit{Operation: "exchange", Decision: "allow", Reason: "issued", Subject: g.Subject, GrantID: g.ID, GrantVersion: g.Version, TenantID: g.TenantID, OwnerID: g.ApprovedBy, JTIHash: digest(issued.ID)}); err != nil {
		return TokenResponse{}, err
	}
	return TokenResponse{AccessToken: raw, TokenType: "Bearer", ExpiresIn: int64(exp.Sub(now).Seconds()), Scope: strings.Join(in.Scopes, " ")}, nil
}

func (s *Service) Authorize(ctx context.Context, raw string, r Resource) (Principal, error) {
	now := s.now()
	c, err := s.parseAccess(raw, r.Audience, now)
	if err != nil {
		return Principal{}, s.reject(ctx, "access", Grant{}, ErrDenied)
	}
	g, err := s.current(ctx, c.GrantID)
	if err != nil {
		return Principal{}, s.reject(ctx, "access", Grant{}, err)
	}
	if c.Subject != g.Subject || c.GrantVersion != g.Version || c.TenantID != g.TenantID || r.TenantID != g.TenantID || c.ExpiresAt.Time.After(g.ExpiresAt) || !audienceScopes(g, r.Audience, strings.Fields(c.Scope)) || !slices.Contains(strings.Fields(c.Scope), r.Scope) || !resourceAllowed(g, r) {
		return Principal{}, s.reject(ctx, "access", g, ErrDenied)
	}
	revoked, err := s.options.Store.IsTokenRevoked(ctx, digest(c.ID))
	if err != nil {
		return Principal{}, s.reject(ctx, "access", g, ErrUnavailable)
	}
	if revoked {
		return Principal{}, s.reject(ctx, "access", g, ErrDenied)
	}
	if err = s.options.Policy.AllowResource(ctx, g, r); err != nil {
		return Principal{}, s.reject(ctx, "access", g, ErrDenied)
	}
	if err = s.record(ctx, Audit{Operation: "access", Decision: "allow", Reason: "authorized", Subject: g.Subject, GrantID: g.ID, GrantVersion: g.Version, TenantID: g.TenantID, OwnerID: g.ApprovedBy, PageID: r.PageID, Scope: r.Scope, JTIHash: digest(c.ID)}); err != nil {
		return Principal{}, err
	}
	return Principal{Subject: g.Subject, GrantID: g.ID, GrantVersion: g.Version, TenantID: g.TenantID, Scopes: strings.Fields(c.Scope), JTIHash: digest(c.ID)}, nil
}

func (s *Service) parseAccess(raw, audience string, now time.Time) (*accessClaims, error) {
	if len(raw) == 0 || len(raw) > 16384 || !httpsURL(audience) {
		return nil, ErrDenied
	}
	c := new(accessClaims)
	t, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || s.options.IssuerKeys[kid] == nil {
			return nil, ErrDenied
		}
		return s.options.IssuerKeys[kid], nil
	}, jwt.WithValidMethods([]string{"ES256"}), jwt.WithIssuer(s.options.IssuerURL), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil || t == nil || !t.Valid || c.TokenUse != "agent_access" || !identifier(c.Subject) || !identifier(c.ID) || !identifier(c.GrantID) || c.GrantVersion <= 0 || c.TenantID <= 0 || !exactAudience(c.Audience, audience) || !shortTimes(c.IssuedAt, c.ExpiresAt, now, MaxTokenLifetime) || !canonicalScopes(strings.Fields(c.Scope)) || strings.Join(strings.Fields(c.Scope), " ") != c.Scope {
		return nil, ErrDenied
	}
	return c, nil
}

func (s *Service) record(ctx context.Context, e Audit) error {
	e.At = s.now()
	if err := s.options.Audit.Record(ctx, e); err != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Service) reject(ctx context.Context, operation string, g Grant, err error) error {
	reason := "denied"
	if err == ErrUnavailable {
		reason = "unavailable"
	}
	if e := s.record(ctx, Audit{Operation: operation, Decision: "deny", Reason: reason, Subject: g.Subject, GrantID: g.ID, GrantVersion: g.Version, TenantID: g.TenantID, OwnerID: g.ApprovedBy}); e != nil {
		return e
	}
	return err
}

// ValidateGrantForStorage checks the structural grant and resource bounds.
// It permits expired or revoked rows so durable adapters can load historical
// state; it does not authorize access, apply the host policy, or approve a new
// grant. Create adapters must additionally require Version 1 and !Revoked.
func ValidateGrantForStorage(g Grant) error {
	g.Revoked = false
	if !validGrant(g, g.CreatedAt) {
		return ErrDenied
	}
	return nil
}

func validGrant(g Grant, now time.Time) bool {
	if !identifier(g.ID) || !identifier(g.Subject) || !identifier(g.KeyID) || !identifier(g.ApprovedBy) || !httpsURL(g.AssertionIssuer) || !httpsURL(g.APIAudience) || !publicKey(g.PublicKey) || g.Version <= 0 || g.TenantID <= 0 || g.Revoked || g.CreatedAt.IsZero() || g.CreatedAt.After(now) || !g.ExpiresAt.After(now) || g.ExpiresAt.Sub(g.CreatedAt) > MaxGrantLifetime || !canonicalScopes(g.Scopes) {
		return false
	}
	if slices.Contains(g.Scopes, PagesUpdate) && len(g.UpdatePageIDs) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range g.UpdatePageIDs {
		if !pageIdentifier(id) || seen[id] {
			return false
		}
		seen[id] = true
	}
	if slices.Contains(g.Scopes, PreviewRead) {
		if g.Preview == nil || !httpsOrigin(g.Preview.Origin) || !httpsURL(g.Preview.Audience) || g.Preview.Audience == g.APIAudience || len(g.Preview.Paths) == 0 {
			return false
		}
		seen = map[string]bool{}
		for _, p := range g.Preview.Paths {
			if !previewTarget(p) || seen[p] {
				return false
			}
			seen[p] = true
		}
	} else if g.Preview != nil {
		return false
	}
	return true
}

func audienceScopes(g Grant, a string, scopes []string) bool {
	if !canonicalScopes(scopes) {
		return false
	}
	for _, scope := range scopes {
		if !slices.Contains(g.Scopes, scope) {
			return false
		}
		if scope == PreviewRead {
			if g.Preview == nil || a != g.Preview.Audience {
				return false
			}
		} else if a != g.APIAudience {
			return false
		}
	}
	return true
}

func resourceAllowed(g Grant, r Resource) bool {
	switch r.Scope {
	case PagesRead, HistoryRead:
		return r.Query == "" && (r.Method == "GET" || r.Method == "HEAD") && len(r.Fields) == 0 && r.Audience == g.APIAudience && (r.PageID == "" || pageIdentifier(r.PageID))
	case PagesUpdate:
		return r.Query == "" && r.Method == "PUT" && r.RootPage && !r.HasCanonicalBlocks && r.ExpectedVersion > 0 && len(r.Fields) == 1 && r.Fields[0] == "body_html" && slices.Contains(g.UpdatePageIDs, r.PageID) && r.Audience == g.APIAudience
	case PreviewRead:
		target, valid := previewResourceTarget(r)
		return valid && g.Preview != nil && r.Audience == g.Preview.Audience && r.Origin == g.Preview.Origin && (r.Method == "GET" || r.Method == "HEAD") && len(r.Fields) == 0 && slices.Contains(g.Preview.Paths, target)
	}
	return false
}

func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return len(raw) > 0 && len(raw) <= 2048 && err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && u.RawPath == "" && (u.Path == "" || path.Clean(u.Path) == u.Path) && u.Host == strings.ToLower(u.Host) && u.String() == raw && !strings.ContainsAny(raw, "* \t\n\r\\")
}
func httpsOrigin(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && httpsURL(raw) && u.Path == ""
}
func identifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("-_.:", r)) {
			return false
		}
	}
	return true
}
func pageIdentifier(s string) bool {
	id, err := strconv.ParseUint(s, 10, 64)
	return err == nil && id > 0 && strconv.FormatUint(id, 10) == s
}
func previewPath(p string) bool {
	if p == "" || !strings.HasPrefix(p, "/") || path.Clean(p) != p || strings.ContainsAny(p, "%?#\\\t\r\n ") {
		return false
	}
	first := strings.ToLower(strings.Split(strings.TrimPrefix(p, "/"), "/")[0])
	return first != "admin" && first != "api" && first != "editor" && first != "oauth" && first != ".well-known"
}
func canonicalScopes(scopes []string) bool {
	if len(scopes) == 0 || len(scopes) > 4 {
		return false
	}
	seen := map[string]bool{}
	for _, s := range scopes {
		if seen[s] || (s != PagesRead && s != HistoryRead && s != PagesUpdate && s != PreviewRead) {
			return false
		}
		seen[s] = true
	}
	return true
}
func sameScopes(a, b []string) bool                      { return len(a) == len(b) && slices.Equal(a, b) }
func exactAudience(a jwt.ClaimStrings, want string) bool { return len(a) == 1 && a[0] == want }
func shortTimes(i, e *jwt.NumericDate, now time.Time, max time.Duration) bool {
	return i != nil && e != nil && !i.Time.After(now) && e.Time.After(now) && e.Time.After(i.Time) && e.Time.Sub(i.Time) <= max && now.Sub(i.Time) <= max
}
func publicKey(k *ecdsa.PublicKey) bool {
	return k != nil && k.Curve == elliptic.P256() && k.X != nil && k.Y != nil && k.Curve.IsOnCurve(k.X, k.Y)
}
func digest(raw string) string { b := sha256.Sum256([]byte(raw)); return hex.EncodeToString(b[:]) }
