package internal

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"

	mail "github.com/wneessen/go-mail"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// --- GENERATE ---

type magicLinkGenerateStep struct{ name string }

func newMagicLinkGenerateStep(name string, _ map[string]any) *magicLinkGenerateStep {
	return &magicLinkGenerateStep{name: name}
}

func (s *magicLinkGenerateStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	email, _ := current["email"].(string)
	secret, _ := current["signing_secret"].(string)
	expiryMinutes := 15

	if email == "" || secret == "" {
		return &sdk.StepResult{Output: map[string]any{"error": "missing email or signing_secret"}}, nil
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	expiresAt := time.Now().UTC().Add(time.Duration(expiryMinutes) * time.Minute)

	// HMAC signature: sign(token + email + expiry) with secret
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(token + email + expiresAt.Format(time.RFC3339)))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

	// Hash token for DB storage (don't store raw token)
	tokenHash := sha256.Sum256([]byte(token))

	return &sdk.StepResult{
		Output: map[string]any{
			"token":      token,
			"token_hash": hex.EncodeToString(tokenHash[:]),
			"signature":  signature,
			"email":      email,
			"expires_at": expiresAt.Format(time.RFC3339),
		},
	}, nil
}

// --- VERIFY ---

type magicLinkVerifyStep struct{ name string }

func newMagicLinkVerifyStep(name string, _ map[string]any) *magicLinkVerifyStep {
	return &magicLinkVerifyStep{name: name}
}

func (s *magicLinkVerifyStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	token, _ := current["token"].(string)
	storedHash, _ := current["stored_hash"].(string)
	expiresAtStr, _ := current["expires_at"].(string)

	if token == "" || storedHash == "" {
		return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "missing token or stored_hash"}}, nil
	}

	// Check expiry
	if expiresAtStr != "" {
		expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
		if err == nil && time.Now().UTC().After(expiresAt) {
			return &sdk.StepResult{Output: map[string]any{"valid": false, "error": "token expired"}}, nil
		}
	}

	// Hash provided token and compare
	tokenHash := sha256.Sum256([]byte(token))
	computedHash := hex.EncodeToString(tokenHash[:])

	valid := hmac.Equal([]byte(computedHash), []byte(storedHash))

	return &sdk.StepResult{
		Output: map[string]any{
			"valid": valid,
		},
	}, nil
}

// --- SEND ---

type magicLinkSendStep struct {
	name        string
	smtpHost    string
	smtpPort    int
	smtpUser    string
	smtpPass    string
	fromAddress string
}

func newMagicLinkSendStep(name string, config map[string]any) *magicLinkSendStep {
	s := &magicLinkSendStep{name: name}
	s.smtpHost = configStrOrEnv(config, "smtp_host", "SMTP_HOST", "")
	s.smtpPort = configIntOrEnv(config, "smtp_port", "SMTP_PORT", 587)
	s.smtpUser = configStrOrEnv(config, "smtp_user", "SMTP_USER", "")
	s.smtpPass = configStrOrEnv(config, "smtp_pass", "SMTP_PASSWORD", "")
	s.fromAddress = configStrOrEnv(config, "from_address", "SMTP_FROM", "noreply@buymywishlist.com")
	return s
}

func (s *magicLinkSendStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	to, _ := current["to"].(string)
	magicURL, _ := current["magic_link_url"].(string)

	if to == "" || magicURL == "" {
		return &sdk.StepResult{Output: map[string]any{"sent": false, "error": "missing to or magic_link_url"}}, nil
	}

	if s.smtpHost == "" {
		// No SMTP configured — return the link without sending (dev mode)
		return &sdk.StepResult{Output: map[string]any{"sent": false, "dev_mode": true, "magic_link_url": magicURL}}, nil
	}

	msg := mail.NewMsg()
	if err := msg.From(s.fromAddress); err != nil {
		return &sdk.StepResult{Output: map[string]any{"sent": false, "error": err.Error()}}, nil
	}
	if err := msg.To(to); err != nil {
		return &sdk.StepResult{Output: map[string]any{"sent": false, "error": err.Error()}}, nil
	}
	msg.Subject("Sign in to BuyMyWishlist")
	msg.SetBodyString(mail.TypeTextHTML, fmt.Sprintf(
		`<p>Click the link below to sign in:</p><p><a href="%s">Sign in to BuyMyWishlist</a></p><p>This link expires in 15 minutes.</p>`,
		magicURL,
	))

	client, err := mail.NewClient(s.smtpHost,
		mail.WithPort(s.smtpPort),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
		mail.WithUsername(s.smtpUser),
		mail.WithPassword(s.smtpPass),
		mail.WithTLSPortPolicy(mail.TLSMandatory),
	)
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"sent": false, "error": err.Error()}}, nil
	}

	if err := client.DialAndSend(msg); err != nil {
		return &sdk.StepResult{Output: map[string]any{"sent": false, "error": err.Error()}}, nil
	}

	return &sdk.StepResult{
		Output: map[string]any{"sent": true, "to": to},
	}, nil
}

// --- HELPERS ---

func configStrOrEnv(config map[string]any, key, envKey, def string) string {
	if v, ok := config[key].(string); ok && v != "" {
		return v
	}
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return def
}

func configIntOrEnv(config map[string]any, key, envKey string, def int) int {
	if v, ok := config[key].(float64); ok {
		return int(v)
	}
	if v := os.Getenv(envKey); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return def
}
