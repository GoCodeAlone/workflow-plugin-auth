package internal

import (
	"context"
	"crypto/subtle"
	"os"
	"strconv"
	"strings"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

const bootstrapMinCodeLength = 16

type bootstrapRedeemStep struct {
	name            string
	superAdminEmail string
	superAdminRole  string
	codeEnv         string
}

func newBootstrapRedeemStep(name string, config map[string]any) *bootstrapRedeemStep {
	role := configString(config, "super_admin_role")
	if role == "" {
		role = "super_admin"
	}
	codeEnv := configString(config, "code_env")
	if codeEnv == "" {
		codeEnv = "AUTH_BOOTSTRAP_CODE"
	}
	return &bootstrapRedeemStep{
		name:            name,
		superAdminEmail: configString(config, "super_admin_email"),
		superAdminRole:  role,
		codeEnv:         codeEnv,
	}
}

func (s *bootstrapRedeemStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	envCode := strings.TrimSpace(os.Getenv(s.codeEnv))
	if len(envCode) < bootstrapMinCodeLength {
		return deny("not_configured"), nil
	}
	count, ok := coerceCount(current["existing_admin_count"])
	if !ok || count != 0 {
		return deny("bootstrap_closed"), nil // default-deny on missing/uncoercible/>0
	}
	code, _ := current["code"].(string)
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(code)), []byte(envCode)) != 1 {
		return deny("invalid_code"), nil
	}
	return &sdk.StepResult{Output: map[string]any{
		"redeemed": true, "email": s.superAdminEmail, "role": s.superAdminRole, "reason": "",
	}}, nil
}

func deny(reason string) *sdk.StepResult {
	return &sdk.StepResult{Output: map[string]any{"redeemed": false, "reason": reason}}
}

// coerceCount returns (count, true) only for an unambiguous integer 0..N.
func coerceCount(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return 0, false
		}
		return i, true
	default:
		return 0, false
	}
}
