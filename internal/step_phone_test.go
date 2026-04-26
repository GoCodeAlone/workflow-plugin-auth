package internal

import (
	"context"
	"testing"
)

func TestNormalizePhone_USNationalNumber(t *testing.T) {
	step := newNormalizePhoneStep("test", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"phone": "(555) 123-4567",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["valid"] != true {
		t.Fatal("expected valid=true")
	}
	if result.Output["phone_e164"] != "+15551234567" {
		t.Fatalf("expected phone_e164 +15551234567, got %#v", result.Output["phone_e164"])
	}
	if result.Output["country"] != "US" {
		t.Fatalf("expected country US, got %#v", result.Output["country"])
	}
	if result.Output["phone"] != "+15551234567" {
		t.Fatalf("expected compatibility phone alias, got %#v", result.Output["phone"])
	}
	if result.Output["phone_valid"] != true {
		t.Fatal("expected compatibility phone_valid=true")
	}
}

func TestNormalizePhone_E164RemainsUnchanged(t *testing.T) {
	step := newNormalizePhoneStep("test", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"phone": "+15551234567",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["valid"] != true {
		t.Fatal("expected valid=true")
	}
	if result.Output["phone_e164"] != "+15551234567" {
		t.Fatalf("expected unchanged E.164 phone, got %#v", result.Output["phone_e164"])
	}
	if result.Output["phone"] != "+15551234567" {
		t.Fatalf("expected compatibility phone alias, got %#v", result.Output["phone"])
	}
	if result.Output["phone_valid"] != true {
		t.Fatal("expected compatibility phone_valid=true")
	}
}

func TestNormalizePhone_EmptyInputReturnsInvalid(t *testing.T) {
	step := newNormalizePhoneStep("test", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["valid"] != false {
		t.Fatal("expected valid=false")
	}
	if result.Output["phone_valid"] != false {
		t.Fatal("expected compatibility phone_valid=false")
	}
	if result.Output["phone"] != "" {
		t.Fatalf("expected empty compatibility phone alias, got %#v", result.Output["phone"])
	}
	if result.Output["phone_e164"] != "" {
		t.Fatalf("expected empty phone_e164, got %#v", result.Output["phone_e164"])
	}
	if result.Output["country"] != "" {
		t.Fatalf("expected empty country, got %#v", result.Output["country"])
	}
}

func TestNormalizePhone_TooShortReturnsInvalidWithError(t *testing.T) {
	step := newNormalizePhoneStep("test", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"phone": "555",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["valid"] != false {
		t.Fatal("expected valid=false")
	}
	if result.Output["phone_valid"] != false {
		t.Fatal("expected compatibility phone_valid=false")
	}
	if _, ok := result.Output["error"].(string); !ok {
		t.Fatal("expected error string")
	}
}

func TestNormalizePhone_RejectsNonASCIIDigits(t *testing.T) {
	step := newNormalizePhoneStep("test", nil)

	result, err := step.Execute(context.Background(), nil, nil, map[string]any{
		"phone": "+１２３４５６７８９０",
	}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Output["valid"] != false {
		t.Fatal("expected valid=false for non-ASCII digits")
	}
	if result.Output["phone_valid"] != false {
		t.Fatal("expected compatibility phone_valid=false")
	}
	if result.Output["phone"] != "" || result.Output["phone_e164"] != "" || result.Output["country"] != "" {
		t.Fatalf("expected stable empty phone fields for invalid input, got %#v", result.Output)
	}
}
