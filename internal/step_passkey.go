package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- BEGIN REGISTER ---

type passkeyBeginRegisterStep struct{ name, module string }

func newPasskeyBeginRegisterStep(name string, config map[string]any) *passkeyBeginRegisterStep {
	module, _ := config["module"].(string)
	return &passkeyBeginRegisterStep{name: name, module: module}
}

func (s *passkeyBeginRegisterStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	mod := getModule(s.module)
	if mod == nil {
		return nil, fmt.Errorf("auth.credential module %q not found", s.module)
	}

	userID, _ := current["user_id"].(string)
	email, _ := current["email"].(string)
	displayName, _ := current["display_name"].(string)
	if displayName == "" {
		displayName = email
	}

	user := &pipelineUser{
		id:          []byte(userID),
		name:        email,
		displayName: displayName,
	}

	options, session, err := mod.webauthn.BeginRegistration(user)
	if err != nil {
		return nil, fmt.Errorf("begin registration: %w", err)
	}

	sessionJSON, _ := json.Marshal(session)
	optionsJSON, _ := json.Marshal(options)

	return &sdk.StepResult{
		Output: map[string]any{
			"options":      string(optionsJSON),
			"session_data": base64.StdEncoding.EncodeToString(sessionJSON),
		},
	}, nil
}

// --- FINISH REGISTER ---

type passkeyFinishRegisterStep struct{ name, module string }

func newPasskeyFinishRegisterStep(name string, config map[string]any) *passkeyFinishRegisterStep {
	module, _ := config["module"].(string)
	return &passkeyFinishRegisterStep{name: name, module: module}
}

func (s *passkeyFinishRegisterStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	mod := getModule(s.module)
	if mod == nil {
		return nil, fmt.Errorf("auth.credential module %q not found", s.module)
	}

	userID, _ := current["user_id"].(string)
	email, _ := current["email"].(string)
	displayName, _ := current["display_name"].(string)
	sessionB64, _ := current["session_data"].(string)
	attestationJSON, _ := current["attestation"].(string)

	if sessionB64 == "" || attestationJSON == "" {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "missing session_data or attestation"}}, nil
	}

	sessionBytes, err := base64.StdEncoding.DecodeString(sessionB64)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "invalid session_data"}}, nil
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "invalid session data"}}, nil
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(
		strings.NewReader(attestationJSON),
	)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": fmt.Sprintf("parse attestation: %v", err)}}, nil
	}

	user := &pipelineUser{
		id:          []byte(userID),
		name:        email,
		displayName: displayName,
	}

	credential, err := mod.webauthn.CreateCredential(user, session, parsedResponse)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": fmt.Sprintf("verify attestation: %v", err)}}, nil
	}

	credJSON, _ := json.Marshal(credential)

	return &sdk.StepResult{
		Output: map[string]any{
			"valid":         true,
			"credential_id": base64.URLEncoding.EncodeToString(credential.ID),
			"public_key":    base64.StdEncoding.EncodeToString(credential.PublicKey),
			"aaguid":        base64.StdEncoding.EncodeToString(credential.Authenticator.AAGUID),
			"sign_count":    credential.Authenticator.SignCount,
			"credential":    string(credJSON),
		},
	}, nil
}

// --- BEGIN LOGIN ---

type passkeyBeginLoginStep struct{ name, module string }

func newPasskeyBeginLoginStep(name string, config map[string]any) *passkeyBeginLoginStep {
	module, _ := config["module"].(string)
	return &passkeyBeginLoginStep{name: name, module: module}
}

func (s *passkeyBeginLoginStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	mod := getModule(s.module)
	if mod == nil {
		return nil, fmt.Errorf("auth.credential module %q not found", s.module)
	}

	userID, _ := current["user_id"].(string)
	credentialsJSON, _ := current["credentials"].(string)

	var user *pipelineUser
	if userID != "" && credentialsJSON != "" {
		var creds []webauthn.Credential
		json.Unmarshal([]byte(credentialsJSON), &creds)
		user = &pipelineUser{
			id:          []byte(userID),
			credentials: creds,
		}
	}

	var options *protocol.CredentialAssertion
	var session *webauthn.SessionData
	var err error

	if user != nil {
		options, session, err = mod.webauthn.BeginLogin(user)
	} else {
		options, session, err = mod.webauthn.BeginDiscoverableLogin()
	}
	if err != nil {
		return nil, fmt.Errorf("begin login: %w", err)
	}

	sessionJSON, _ := json.Marshal(session)
	optionsJSON, _ := json.Marshal(options)

	return &sdk.StepResult{
		Output: map[string]any{
			"options":      string(optionsJSON),
			"session_data": base64.StdEncoding.EncodeToString(sessionJSON),
		},
	}, nil
}

// --- FINISH LOGIN ---

type passkeyFinishLoginStep struct{ name, module string }

func newPasskeyFinishLoginStep(name string, config map[string]any) *passkeyFinishLoginStep {
	module, _ := config["module"].(string)
	return &passkeyFinishLoginStep{name: name, module: module}
}

func (s *passkeyFinishLoginStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	mod := getModule(s.module)
	if mod == nil {
		return nil, fmt.Errorf("auth.credential module %q not found", s.module)
	}

	userID, _ := current["user_id"].(string)
	email, _ := current["email"].(string)
	credentialsJSON, _ := current["credentials"].(string)
	sessionB64, _ := current["session_data"].(string)
	assertionJSON, _ := current["assertion"].(string)

	if sessionB64 == "" || assertionJSON == "" {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "missing session_data or assertion"}}, nil
	}

	sessionBytes, _ := base64.StdEncoding.DecodeString(sessionB64)
	var session webauthn.SessionData
	json.Unmarshal(sessionBytes, &session)

	parsedAssertion, err := protocol.ParseCredentialRequestResponseBody(
		strings.NewReader(assertionJSON),
	)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": fmt.Sprintf("parse assertion: %v", err)}}, nil
	}

	var creds []webauthn.Credential
	if credentialsJSON != "" {
		json.Unmarshal([]byte(credentialsJSON), &creds)
	}

	user := &pipelineUser{
		id:          []byte(userID),
		name:        email,
		credentials: creds,
	}

	updatedCred, err := mod.webauthn.ValidateLogin(user, session, parsedAssertion)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": fmt.Sprintf("validate login: %v", err)}}, nil
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"valid":         true,
			"credential_id": base64.URLEncoding.EncodeToString(updatedCred.ID),
			"sign_count":    updatedCred.Authenticator.SignCount,
		},
	}, nil
}
