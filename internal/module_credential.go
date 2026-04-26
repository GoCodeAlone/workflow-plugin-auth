package internal

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
)

type credentialModule struct {
	name     string
	config   map[string]any
	webauthn *webauthn.WebAuthn
}

func newCredentialModule(name string, config map[string]any) (*credentialModule, error) {
	return &credentialModule{name: name, config: config}, nil
}

func (m *credentialModule) Init() error {
	rpDisplayName, _ := m.config["rpDisplayName"].(string)
	rpID, _ := m.config["rpID"].(string)
	origin, _ := m.config["origin"].(string)

	if rpDisplayName == "" {
		rpDisplayName = "Workflow App"
	}
	if (rpID == "" || origin == "") && configBool(m.config, "optional") {
		unregisterModule(m.name)
		return nil
	}
	if rpID == "" {
		// Extract from origin
		if origin != "" {
			u, err := url.Parse(origin)
			if err == nil {
				rpID = u.Hostname()
			}
		}
	}
	if rpID == "" {
		return fmt.Errorf("auth.credential module %q: rpID or origin required", m.name)
	}
	if origin == "" {
		return fmt.Errorf("auth.credential module %q: origin required", m.name)
	}

	wconfig := &webauthn.Config{
		RPDisplayName: rpDisplayName,
		RPID:          rpID,
		RPOrigins:     []string{origin},
	}

	w, err := webauthn.New(wconfig)
	if err != nil {
		return fmt.Errorf("auth.credential module %q init: %w", m.name, err)
	}
	m.webauthn = w

	registerModule(m.name, m)
	return nil
}

func (m *credentialModule) Start(_ context.Context) error { return nil }

func (m *credentialModule) Stop(_ context.Context) error {
	unregisterModule(m.name)
	return nil
}

func configBool(config map[string]any, key string) bool {
	switch value := config[key].(type) {
	case bool:
		return value
	case string:
		return strings.EqualFold(strings.TrimSpace(value), "true")
	default:
		return false
	}
}
