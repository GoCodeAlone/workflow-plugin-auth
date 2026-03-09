package internal

import (
	"context"
	"encoding/json"
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- LIST ---
// Pipeline does the DB query, this step formats the output.
// Reads credentials_json from current (json_agg result).

type credentialListStep struct{ name string }

func newCredentialListStep(name string, _ map[string]any) *credentialListStep {
	return &credentialListStep{name: name}
}

func (s *credentialListStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	credJSON, _ := current["credentials_json"].(string)

	var creds []map[string]any
	if credJSON != "" {
		json.Unmarshal([]byte(credJSON), &creds)
	}

	// Strip sensitive fields (public_key bytes, totp_secret)
	sanitized := make([]map[string]any, len(creds))
	for i, c := range creds {
		sanitized[i] = map[string]any{
			"id":          c["id"],
			"type":        c["type"],
			"device_name": c["device_name"],
			"created_at":  c["created_at"],
			"last_used":   c["last_used_at"],
		}
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"credentials": sanitized,
			"count":       len(sanitized),
		},
	}, nil
}

// --- REVOKE ---
// Validates the credential belongs to the user before pipeline deletes it.

type credentialRevokeStep struct{ name string }

func newCredentialRevokeStep(name string, _ map[string]any) *credentialRevokeStep {
	return &credentialRevokeStep{name: name}
}

func (s *credentialRevokeStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	credentialID, _ := current["credential_id"].(string)
	ownerUserID, _ := current["owner_user_id"].(string)
	requestUserID, _ := current["user_id"].(string)

	if credentialID == "" {
		return &sdk.StepResult{Output: map[string]any{"authorized": false, "error": "missing credential_id"}}, nil
	}

	if ownerUserID != requestUserID {
		return &sdk.StepResult{Output: map[string]any{
			"authorized": false,
			"error":      fmt.Sprintf("credential does not belong to user %s", requestUserID),
		}}, nil
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"authorized":    true,
			"credential_id": credentialID,
		},
	}, nil
}
