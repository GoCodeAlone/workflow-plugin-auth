// Package adminidentity exposes reusable identity-administration HTTP handlers
// for Workflow auth consumers.
package adminidentity

import (
	"context"
	"errors"
	"net/http"
	"time"
)

const (
	CredentialKindPasskey = "passkey"
	CredentialKindTOTP    = "totp"
)

var (
	ErrSetupCodeNotFound   = errors.New("setup code not found")
	ErrSetupCodeWrongEmail = errors.New("setup code email mismatch")
	ErrSetupCodeExpired    = errors.New("setup code expired")
)

// Options configures the identity admin handler. The host owns persistence and
// policy by supplying typed adapters.
type Options struct {
	PagePath          string
	ProfilePath       string
	CredentialsPath   string
	PasskeyBeginPath  string
	PasskeyFinishPath string
	TOTPBeginPath     string
	TOTPVerifyPath    string
	UsersPath         string
	SetupRedeemPath   string
	LogoutPath        string

	PrincipalResolver PrincipalResolver
	UserStore         UserStore
	CredentialStore   CredentialStore
	SetupCodeStore    SetupCodeStore
	SessionIssuer     SessionIssuer
	StepInvoker       StepInvoker
	Authorizer        Authorizer
}

type Principal struct {
	UserID string
	Email  string
	Role   string
}

type User struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name,omitempty"`
	Role        string   `json:"role,omitempty"`
	TenantIDs   []string `json:"tenant_ids,omitempty"`
}

type Credential struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id,omitempty"`
	Kind           string     `json:"kind"`
	Label          string     `json:"label,omitempty"`
	CreatedAt      time.Time  `json:"created_at,omitempty"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	SecretMaterial string     `json:"-"`
}

type SetupCode struct {
	ID        string
	Code      string
	Email     string
	UserID    string
	Role      string
	TenantIDs []string
	ExpiresAt time.Time
	UsedAt    *time.Time
}

type IssueSetupCodeInput struct {
	Email     string
	Role      string
	TenantIDs []string
	ExpiresAt time.Time
}

type AddTOTPCredentialInput struct {
	Secret string
	Label  string
}

type AddPasskeyCredentialInput struct {
	CredentialID   string
	CredentialJSON string
	PublicKey      string
	Label          string
}

type ListUsersFilter struct {
	Principal Principal
}

type SessionRequest struct {
	UserID    string
	Email     string
	Role      string
	TenantIDs []string
}

type Session struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type StepCall struct {
	StepType string
	Input    map[string]any
}

type PrincipalResolver interface {
	CurrentPrincipal(*http.Request) (Principal, bool)
}

type UserStore interface {
	CurrentUser(context.Context, Principal) (User, error)
	ListUsers(context.Context, ListUsersFilter) ([]User, error)
}

type CredentialStore interface {
	ListCredentials(context.Context, string) ([]Credential, error)
	AddTOTPCredential(context.Context, string, AddTOTPCredentialInput) (Credential, error)
	AddPasskeyCredential(context.Context, string, AddPasskeyCredentialInput) (Credential, error)
}

type SetupCodeStore interface {
	IssueSetupCode(context.Context, IssueSetupCodeInput) (SetupCode, error)
	RedeemSetupCode(context.Context, string, string) (SetupCode, error)
}

type SessionIssuer interface {
	IssueSession(context.Context, SessionRequest) (Session, error)
}

type StepInvoker interface {
	InvokeStep(context.Context, StepCall) (map[string]any, error)
}

type Authorizer interface {
	Authorize(context.Context, Principal, string, string) error
}
