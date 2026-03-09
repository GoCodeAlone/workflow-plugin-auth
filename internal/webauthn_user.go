package internal

import "github.com/go-webauthn/webauthn/webauthn"

// pipelineUser implements webauthn.User for ceremony operations.
// Populated from pipeline current context (DB data passed via step.set).
type pipelineUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *pipelineUser) WebAuthnID() []byte                         { return u.id }
func (u *pipelineUser) WebAuthnName() string                       { return u.name }
func (u *pipelineUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *pipelineUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }
