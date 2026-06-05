package internal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type passkeyCredentialJSON struct {
	ID              string                            `json:"id"`
	PublicKey       string                            `json:"publicKey"`
	AttestationType string                            `json:"attestationType"`
	Transport       []protocol.AuthenticatorTransport `json:"transport"`
	Flags           *passkeyCredentialFlagsJSON       `json:"flags"`
	Authenticator   passkeyAuthenticatorJSON          `json:"authenticator"`
	Attestation     passkeyAttestationJSON            `json:"attestation"`
}

type passkeyCredentialFlagsJSON struct {
	UserPresent    *bool `json:"userPresent"`
	UserVerified   *bool `json:"userVerified"`
	BackupEligible *bool `json:"backupEligible"`
	BackupState    *bool `json:"backupState"`
}

type passkeyAuthenticatorJSON struct {
	AAGUID       string                           `json:"AAGUID"`
	SignCount    uint32                           `json:"signCount"`
	CloneWarning bool                             `json:"cloneWarning"`
	Attachment   protocol.AuthenticatorAttachment `json:"attachment"`
}

type passkeyAttestationJSON struct {
	ClientDataJSON     string `json:"clientDataJSON"`
	ClientDataHash     string `json:"clientDataHash"`
	AuthenticatorData  string `json:"authenticatorData"`
	PublicKeyAlgorithm int64  `json:"publicKeyAlgorithm"`
	Object             string `json:"object"`
}

func parsePasskeyCredentials(credentialsJSON string) ([]webauthn.Credential, error) {
	return parsePasskeyCredentialsForAssertion(credentialsJSON, nil)
}

func parsePasskeyCredentialsForAssertion(credentialsJSON string, assertion *protocol.ParsedCredentialAssertionData) ([]webauthn.Credential, error) {
	var rawCredentials []passkeyCredentialJSON
	if err := json.Unmarshal([]byte(credentialsJSON), &rawCredentials); err != nil {
		return nil, err
	}

	credentials := make([]webauthn.Credential, 0, len(rawCredentials))
	for i, raw := range rawCredentials {
		id, err := decodePasskeyBytes(raw.ID)
		if err != nil {
			return nil, fmt.Errorf("credential %d id: %w", i, err)
		}
		if len(id) == 0 {
			return nil, fmt.Errorf("credential %d id: empty", i)
		}

		publicKey, err := decodeOptionalPasskeyBytes(raw.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("credential %d publicKey: %w", i, err)
		}
		aaguid, err := decodeOptionalPasskeyBytes(raw.Authenticator.AAGUID)
		if err != nil {
			return nil, fmt.Errorf("credential %d authenticator.AAGUID: %w", i, err)
		}
		clientDataJSON, err := decodeOptionalPasskeyBytes(raw.Attestation.ClientDataJSON)
		if err != nil {
			return nil, fmt.Errorf("credential %d attestation.clientDataJSON: %w", i, err)
		}
		clientDataHash, err := decodeOptionalPasskeyBytes(raw.Attestation.ClientDataHash)
		if err != nil {
			return nil, fmt.Errorf("credential %d attestation.clientDataHash: %w", i, err)
		}
		authenticatorData, err := decodeOptionalPasskeyBytes(raw.Attestation.AuthenticatorData)
		if err != nil {
			return nil, fmt.Errorf("credential %d attestation.authenticatorData: %w", i, err)
		}
		object, err := decodeOptionalPasskeyBytes(raw.Attestation.Object)
		if err != nil {
			return nil, fmt.Errorf("credential %d attestation.object: %w", i, err)
		}

		credentials = append(credentials, webauthn.Credential{
			ID:              id,
			PublicKey:       publicKey,
			AttestationType: raw.AttestationType,
			Transport:       raw.Transport,
			Flags:           passkeyFlags(raw.Flags, id, assertion),
			Authenticator: webauthn.Authenticator{
				AAGUID:       aaguid,
				SignCount:    raw.Authenticator.SignCount,
				CloneWarning: raw.Authenticator.CloneWarning,
				Attachment:   raw.Authenticator.Attachment,
			},
			Attestation: webauthn.CredentialAttestation{
				ClientDataJSON:     clientDataJSON,
				ClientDataHash:     clientDataHash,
				AuthenticatorData:  authenticatorData,
				PublicKeyAlgorithm: raw.Attestation.PublicKeyAlgorithm,
				Object:             object,
			},
		})
	}

	return credentials, nil
}

func passkeyFlags(raw *passkeyCredentialFlagsJSON, credentialID []byte, assertion *protocol.ParsedCredentialAssertionData) webauthn.CredentialFlags {
	flags := webauthn.CredentialFlags{}
	if raw != nil {
		flags.UserPresent = boolValue(raw.UserPresent)
		flags.UserVerified = boolValue(raw.UserVerified)
		flags.BackupEligible = boolValue(raw.BackupEligible)
		flags.BackupState = boolValue(raw.BackupState)
	}
	if raw != nil && raw.BackupEligible != nil {
		return flags
	}
	if assertion == nil || !bytes.Equal(credentialID, assertion.RawID) {
		return flags
	}
	authFlags := assertion.Response.AuthenticatorData.Flags
	flags.UserPresent = authFlags.HasUserPresent()
	flags.UserVerified = authFlags.HasUserVerified()
	flags.BackupEligible = authFlags.HasBackupEligible()
	flags.BackupState = authFlags.HasBackupState()
	return flags
}

func boolValue(value *bool) bool {
	return value != nil && *value
}

func decodeOptionalPasskeyBytes(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return decodePasskeyBytes(value)
}

func decodePasskeyBytes(value string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

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
		creds, err := parsePasskeyCredentials(credentialsJSON)
		if err != nil {
			return nil, fmt.Errorf("parse credentials: %w", err)
		}
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
		var err error
		creds, err = parsePasskeyCredentialsForAssertion(credentialsJSON, parsedAssertion)
		if err != nil {
			return &sdk.StepResult{Output: map[string]any{"valid": false, "error": fmt.Sprintf("parse credentials: %v", err)}}, nil
		}
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
	credJSON, err := json.Marshal(updatedCred)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": fmt.Sprintf("encode credential: %v", err)}}, nil
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"valid":         true,
			"credential_id": base64.URLEncoding.EncodeToString(updatedCred.ID),
			"sign_count":    updatedCred.Authenticator.SignCount,
			"credential":    string(credJSON),
		},
	}, nil
}
