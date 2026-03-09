package internal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/pquerna/otp/totp"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"golang.org/x/crypto/bcrypt"
)

// --- GENERATE SECRET ---

type totpGenerateSecretStep struct{ name string }

func newTOTPGenerateSecretStep(name string, _ map[string]any) *totpGenerateSecretStep {
	return &totpGenerateSecretStep{name: name}
}

func (s *totpGenerateSecretStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	email, _ := current["email"].(string)
	issuer, _ := current["issuer"].(string)
	if issuer == "" {
		issuer = "BuyMyWishlist"
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: email,
	})
	if err != nil {
		return nil, fmt.Errorf("generate TOTP secret: %w", err)
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"secret":           key.Secret(),
			"provisioning_uri": key.URL(),
			"issuer":           issuer,
			"account":          email,
		},
	}, nil
}

// --- VERIFY ---

type totpVerifyStep struct{ name string }

func newTOTPVerifyStep(name string, _ map[string]any) *totpVerifyStep {
	return &totpVerifyStep{name: name}
}

func (s *totpVerifyStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	code, _ := current["code"].(string)
	secret, _ := current["secret"].(string)

	if code == "" || secret == "" {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "missing code or secret"}}, nil
	}

	valid := totp.Validate(code, secret)

	return &sdk.StepResult{
		Output: map[string]any{
			"valid": valid,
		},
	}, nil
}

// --- RECOVERY CODES ---

type totpRecoveryCodesStep struct{ name string }

func newTOTPRecoveryCodesStep(name string, _ map[string]any) *totpRecoveryCodesStep {
	return &totpRecoveryCodesStep{name: name}
}

func (s *totpRecoveryCodesStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, _, _, _ map[string]any) (*sdk.StepResult, error) {
	count := 10
	codes := make([]string, count)
	hashes := make([]string, count)

	for i := range count {
		b := make([]byte, 5) // 10 hex chars
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		codes[i] = hex.EncodeToString(b)
		hash, err := bcrypt.GenerateFromPassword([]byte(codes[i]), 10)
		if err != nil {
			return nil, fmt.Errorf("hash recovery code: %w", err)
		}
		hashes[i] = string(hash)
	}

	return &sdk.StepResult{
		Output: map[string]any{
			"codes":  codes,
			"hashes": hashes,
		},
	}, nil
}
