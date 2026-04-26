package internal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type challengeGenerateStep struct{ name string }

func newChallengeGenerateStep(name string, _ map[string]any) *challengeGenerateStep {
	return &challengeGenerateStep{name: name}
}

func (s *challengeGenerateStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	channel, _ := current["channel"].(string)
	destination, _ := current["destination"].(string)
	tenantID, _ := current["tenant_id"].(string)
	purpose, _ := current["purpose"].(string)
	signingSecret, _ := current["signing_secret"].(string)
	if strings.TrimSpace(channel) == "" || strings.TrimSpace(destination) == "" || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(purpose) == "" || signingSecret == "" {
		return &sdk.StepResult{Output: map[string]any{"error": "missing channel, destination, tenant_id, purpose, or signing_secret"}}, nil
	}

	normalizedDestination := normalizeChallengeDestination(destination)
	code, err := randomSixDigitCode()
	if err != nil {
		return nil, fmt.Errorf("generate challenge code: %w", err)
	}

	ttlMinutes := intFromAny(current["ttl_minutes"], 10)
	if ttlMinutes <= 0 {
		ttlMinutes = 10
	}
	expiresAt := time.Now().UTC().Add(time.Duration(ttlMinutes) * time.Minute)

	return &sdk.StepResult{Output: map[string]any{
		"code":        code,
		"code_hash":   hashChallengeCode(channel, normalizedDestination, tenantID, purpose, code, signingSecret),
		"channel":     strings.TrimSpace(channel),
		"destination": normalizedDestination,
		"expires_at":  expiresAt.Format(time.RFC3339),
	}}, nil
}

type challengeVerifyStep struct{ name string }

func newChallengeVerifyStep(name string, _ map[string]any) *challengeVerifyStep {
	return &challengeVerifyStep{name: name}
}

func (s *challengeVerifyStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	channel, _ := current["channel"].(string)
	code, _ := current["code"].(string)
	codeHash, _ := current["code_hash"].(string)
	destination, _ := current["destination"].(string)
	tenantID, _ := current["tenant_id"].(string)
	purpose, _ := current["purpose"].(string)
	signingSecret, _ := current["signing_secret"].(string)
	if strings.TrimSpace(channel) == "" || code == "" || codeHash == "" || strings.TrimSpace(destination) == "" || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(purpose) == "" || signingSecret == "" {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "missing channel, code, code_hash, destination, tenant_id, purpose, or signing_secret"}}, nil
	}

	attempts, attemptsPresent, attemptsOK := currentInt(current, "attempts")
	if attemptsPresent && !attemptsOK {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "invalid attempts"}}, nil
	}
	if !attemptsPresent {
		attempts = 0
	}
	maxAttempts, maxAttemptsPresent, maxAttemptsOK := currentInt(current, "max_attempts")
	if maxAttemptsPresent && !maxAttemptsOK {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "invalid max_attempts"}}, nil
	}
	if !maxAttemptsPresent {
		maxAttempts = 5
	}
	if maxAttempts <= 0 {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "invalid max_attempts"}}, nil
	}
	if attempts >= maxAttempts {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "max attempts exceeded"}}, nil
	}

	if expiresAtStr, _ := current["expires_at"].(string); expiresAtStr != "" {
		expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "invalid expires_at"}}, nil
		}
		if !time.Now().UTC().Before(expiresAt) {
			return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "challenge expired"}}, nil
		}
	}

	computedHash := hashChallengeCode(channel, normalizeChallengeDestination(destination), tenantID, purpose, code, signingSecret)
	return &sdk.StepResult{Output: map[string]any{"valid": hmac.Equal([]byte(computedHash), []byte(codeHash))}}, nil
}

func randomSixDigitCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func normalizeChallengeDestination(destination string) string {
	destination = strings.TrimSpace(destination)
	if strings.Contains(destination, "@") {
		return strings.ToLower(destination)
	}
	return destination
}

func hashChallengeCode(channel, destination, tenantID, purpose, code, signingSecret string) string {
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(strings.TrimSpace(channel)))
	mac.Write([]byte{0})
	mac.Write([]byte(normalizeChallengeDestination(destination)))
	mac.Write([]byte{0})
	mac.Write([]byte(strings.TrimSpace(tenantID)))
	mac.Write([]byte{0})
	mac.Write([]byte(strings.TrimSpace(purpose)))
	mac.Write([]byte{0})
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

func currentInt(current map[string]any, key string) (int, bool, bool) {
	value, ok := current[key]
	if !ok {
		return 0, false, false
	}
	switch v := value.(type) {
	case int:
		return v, true, true
	case int64:
		return int(v), true, true
	case float64:
		return int(v), true, true
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(v))
		return i, true, err == nil
	default:
		return 0, true, false
	}
}

func intFromAny(value any, fallback int) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil {
			return i
		}
	}
	return fallback
}
