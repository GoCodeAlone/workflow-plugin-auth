package internal

import (
	"context"
	"strings"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type normalizePhoneStep struct{ name string }

func newNormalizePhoneStep(name string, _ map[string]any) *normalizePhoneStep {
	return &normalizePhoneStep{name: name}
}

func (s *normalizePhoneStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	phone, _ := current["phone"].(string)
	phone = strings.TrimSpace(phone)
	if phone == "" {
		return invalidPhoneResult("missing phone"), nil
	}

	normalized := stripPhoneFormatting(phone)
	digits := strings.TrimPrefix(normalized, "+")
	if digits == "" || !allDigits(digits) {
		return invalidPhoneResult("invalid phone"), nil
	}

	switch {
	case strings.HasPrefix(normalized, "+") && len(digits) >= 8 && len(digits) <= 15:
		return validPhoneResult(normalized), nil
	case len(digits) == 10:
		return validPhoneResult("+1" + digits), nil
	case len(digits) == 11 && strings.HasPrefix(digits, "1"):
		return validPhoneResult("+" + digits), nil
	default:
		return invalidPhoneResult("invalid phone length"), nil
	}
}

func stripPhoneFormatting(phone string) string {
	var b strings.Builder
	for i, r := range phone {
		switch {
		case isASCIIDigit(r):
			b.WriteRune(r)
		case r == '+' && i == 0:
			b.WriteRune(r)
		case r == ' ' || r == '(' || r == ')' || r == '-' || r == '.':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func validPhoneResult(phone string) *sdk.StepResult {
	return &sdk.StepResult{Output: map[string]any{
		"valid":       true,
		"phone_e164":  phone,
		"country":     phoneCountry(phone),
		"phone":       phone,
		"phone_valid": true,
	}}
}

func invalidPhoneResult(message string) *sdk.StepResult {
	return &sdk.StepResult{Output: map[string]any{
		"valid":       false,
		"phone_e164":  "",
		"country":     "",
		"phone":       "",
		"phone_valid": false,
		"error":       message,
	}}
}

func phoneCountry(phone string) string {
	if strings.HasPrefix(phone, "+1") {
		return "US"
	}
	return ""
}

func allDigits(value string) bool {
	for _, r := range value {
		if !isASCIIDigit(r) {
			return false
		}
	}
	return true
}

func isASCIIDigit(r rune) bool {
	return r >= '0' && r <= '9'
}
