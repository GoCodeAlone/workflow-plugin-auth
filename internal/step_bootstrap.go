package internal

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"math"
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
	// Hash both sides to a fixed 32-byte digest before comparing: subtle.ConstantTimeCompare
	// short-circuits on unequal lengths, which would leak the configured code's length via a
	// timing side-channel. Equal-length digests make the compare genuinely constant-time.
	gotSum := sha256.Sum256([]byte(strings.TrimSpace(code)))
	wantSum := sha256.Sum256([]byte(envCode))
	if subtle.ConstantTimeCompare(gotSum[:], wantSum[:]) != 1 {
		return deny("invalid_code"), nil
	}
	return &sdk.StepResult{Output: map[string]any{
		"redeemed": true, "email": s.superAdminEmail, "role": s.superAdminRole, "reason": "",
	}}, nil
}

func deny(reason string) *sdk.StepResult {
	return &sdk.StepResult{Output: map[string]any{"redeemed": false, "reason": reason}}
}

// coerceCount returns (count, true) only for an unambiguous non-negative integer
// (0..N). Negative, fractional, and uncoercible values return (_, false) →
// default-deny at the call site (a credential count is never negative or fractional).
func coerceCount(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return nonNeg(n)
	case int64:
		return nonNeg(int(n))
	case float64:
		// Reject non-integer floats: int(0.9)==0 would otherwise open bootstrap
		// (V-B1 requires the count be EXACTLY 0). Default-deny on fractional input.
		if n != math.Trunc(n) {
			return 0, false
		}
		return nonNeg(int(n))
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(n))
		if err != nil {
			return 0, false
		}
		return nonNeg(i)
	default:
		return 0, false
	}
}

func nonNeg(n int) (int, bool) {
	if n < 0 {
		return 0, false
	}
	return n, true
}
