// Package agentidentity implements opt-in, tenant-scoped service grants. Hosts
// supply durable adapters and Workflow's managed issuer; no human sessions or
// issuer/private keys are created by this package.
package agentidentity

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"time"
)

const (
	PagesRead            = "admin:multisite.pages:read"
	HistoryRead          = "admin:multisite.pages:history:read"
	PagesUpdate          = "admin:multisite.pages:update"
	PreviewRead          = "admin:multisite.preview:read"
	MaxGrantLifetime     = 30 * 24 * time.Hour
	MaxTokenLifetime     = 15 * time.Minute
	MaxAssertionLifetime = time.Minute
)

var (
	ErrDenied      = errors.New("agent access denied")
	ErrUnavailable = errors.New("agent access unavailable")
	ErrConflict    = errors.New("agent grant conflict")
)

type PreviewGrant struct {
	Audience string   `json:"audience"`
	Origin   string   `json:"origin"`
	Paths    []string `json:"paths"`
}

// Grant is a host-owned durable row. Rotation and any permission edit MUST
// increment Version atomically; revocation must not delete the audit record.
// The public assertion key is not issuer key material or a human credential.
type Grant struct {
	ID              string           `json:"id"`
	Subject         string           `json:"subject"`
	AssertionIssuer string           `json:"assertion_issuer"`
	KeyID           string           `json:"key_id"`
	PublicKey       *ecdsa.PublicKey `json:"-"`
	Version         int64            `json:"version"`
	TenantID        int64            `json:"tenant_id"`
	ApprovedBy      string           `json:"approved_by"`
	CreatedAt       time.Time        `json:"created_at"`
	ExpiresAt       time.Time        `json:"expires_at"`
	Revoked         bool             `json:"revoked"`
	APIAudience     string           `json:"api_audience"`
	Scopes          []string         `json:"scopes"`
	UpdatePageIDs   []string         `json:"update_page_ids,omitempty"`
	Preview         *PreviewGrant    `json:"preview,omitempty"`
}

type AssertionUse struct {
	GrantID      string
	GrantVersion int64
	JTIHash      string
	ExpiresAt    time.Time
	Now          time.Time
}

// Store methods MUST use durable state. ConsumeAssertion atomically checks the
// current grant version, enabled/expiry state AND inserts its globally unique
// assertion identity hash (issuer/subject/key/JTI binding). Uniqueness MUST NOT
// be partitioned by grant/version: one assertion cannot be reused on another
// tenant grant or after a permission edit. Return false for replay or changed/
// revoked grants. Create and Revoke must be
// transactional and never alter a human identity/factor/bootstrap record.
// No in-memory production fallback is supplied.
type Store interface {
	GetGrant(context.Context, string) (Grant, error)
	ConsumeAssertion(context.Context, AssertionUse) (bool, error)
	IsTokenRevoked(context.Context, string) (bool, error)
}

type GrantManager interface {
	CreateGrant(context.Context, Grant) error
	RevokeGrant(context.Context, string, int64, string, time.Time) error
	ListGrants(context.Context, Owner) ([]Grant, error)
}

type Owner struct{ ID string }

// OwnerPolicy must resolve a verified HUMAN owner and explicitly authorize the
// proposed tenant/resource/field ceiling. Request JSON never supplies identity.
// A service principal must not be projected into this resolver.
type OwnerPolicy interface {
	ResolveOwner(*http.Request) (Owner, error)
	AuthorizeOwner(context.Context, Owner, string, Grant) error
}

// Policy is the consuming app's exact tenant/resource allowlist. It is required
// even for already persisted grants: the library does not know which tenant is
// live or which routes exist. It must reject live tenants and privileged routes
// for the preview assistant. An omitted policy never grants access.
type Policy interface {
	AllowGrant(context.Context, Grant) error
	AllowResource(context.Context, Grant, Resource) error
}

type IssueRequest struct {
	Subject, Audience, GrantID string
	GrantVersion, TenantID     int64
	Scopes                     []string
	IssuedAt, ExpiresAt        time.Time
}

// Issuer is an adapter to Workflow M2M IssueManagedToken with managed-only
// issuance and an explicitly configured stable ES256 key. Hosts map this typed
// request; never implement this with a human cookie/HMAC or generic OAuth route.
type Issuer interface {
	IssueAgentToken(context.Context, IssueRequest) (string, error)
}

type IssuerFunc func(context.Context, IssueRequest) (string, error)

func (f IssuerFunc) IssueAgentToken(ctx context.Context, r IssueRequest) (string, error) {
	return f(ctx, r)
}

// Audit contains fixed reason codes and verified metadata, never raw tokens,
// assertions, keys, headers, bodies, arbitrary error strings or human emails.
type Audit struct {
	At           time.Time `json:"at"`
	Operation    string    `json:"operation"`
	Decision     string    `json:"decision"`
	Reason       string    `json:"reason"`
	Subject      string    `json:"subject,omitempty"`
	GrantID      string    `json:"grant_id,omitempty"`
	GrantVersion int64     `json:"grant_version,omitempty"`
	TenantID     int64     `json:"tenant_id,omitempty"`
	OwnerID      string    `json:"owner_id,omitempty"`
	PageID       string    `json:"page_id,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	JTIHash      string    `json:"jti_hash,omitempty"`
}
type Auditor interface {
	Record(context.Context, Audit) error
}

type Options struct {
	IssuerURL     string
	TokenEndpoint string
	IssuerKeys    map[string]*ecdsa.PublicKey
	Store         Store
	Issuer        Issuer
	Policy        Policy
	Audit         Auditor
	// Clock is for deterministic tests; production hosts normally omit it.
	Clock func() time.Time
}

type ExchangeRequest struct {
	GrantID   string
	Assertion string
	Audience  string
	Scopes    []string
}
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// Resource must be built from the matched route/current saved row by the host,
// never copied unverified from JSON or X-Tenant/actor headers. All writes are
// body_html-only root-page CAS; canonical blocks are refused.
type Resource struct {
	TenantID                int64
	Audience, Scope, PageID string
	Fields                  []string
	ExpectedVersion         uint64
	RootPage                bool
	HasCanonicalBlocks      bool
	Method, Origin, Path    string
}

type Principal struct {
	Subject, GrantID, JTIHash string
	GrantVersion, TenantID    int64
	Scopes                    []string
}
