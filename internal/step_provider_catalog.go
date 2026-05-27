package internal

import (
	"context"
	"fmt"
	"sort"
	"strings"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type authProviderCatalogStep struct {
	name   string
	config map[string]any
}

func newAuthProviderCatalogStep(name string, config map[string]any) *authProviderCatalogStep {
	return &authProviderCatalogStep{name: name, config: config}
}

func (s *authProviderCatalogStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	merged := make(map[string]authProviderDescriptor)
	var warnings []map[string]any
	for _, source := range []map[string]any{s.config, current} {
		for _, provider := range authProviderDescriptors(source) {
			if provider.ID == "" {
				continue
			}
			if existing, ok := merged[provider.ID]; ok {
				if !authProviderDescriptorsCompatible(existing, provider) {
					warnings = append(warnings, authAdminDiagnostic(provider.ID, "warning", "duplicate provider descriptor ignored"))
				} else {
					warnings = append(warnings, authAdminDiagnostic(provider.ID, "warning", "duplicate provider descriptor ignored"))
				}
				continue
			}
			merged[provider.ID] = provider
		}
	}

	providers := make([]authProviderDescriptor, 0, len(merged))
	for _, provider := range merged {
		providers = append(providers, provider)
	}
	sort.Slice(providers, func(i, j int) bool { return providers[i].ID < providers[j].ID })

	outputProviders := make([]map[string]any, 0, len(providers))
	for _, provider := range providers {
		outputProviders = append(outputProviders, provider.toMap())
	}
	return &sdk.StepResult{Output: map[string]any{
		"providers": outputProviders,
		"warnings":  warnings,
	}}, nil
}

type authProviderDescriptor struct {
	ID             string
	Label          string
	Description    string
	Categories     []string
	Implementation string
	Version        string
	DocsURL        string
	SupportLevel   string
	DisabledReason string
	Capabilities   []authProviderCapability
}

type authProviderCapability struct {
	Key              string
	Label            string
	Category         string
	Description      string
	Supported        bool
	DisabledReason   string
	AppScopes        []string
	AdminReadScopes  []string
	AdminWriteScopes []string
	ConfigFields     []authProviderConfigField
}

type authProviderConfigField struct {
	Key               string
	Label             string
	Description       string
	HelpText          string
	InputType         string
	Secret            bool
	Required          bool
	Options           []authProviderConfigOption
	Lookup            string
	ValidationPattern string
}

type authProviderConfigOption struct {
	Value       string
	Label       string
	Description string
}

func authProviderDescriptors(source map[string]any) []authProviderDescriptor {
	if source == nil {
		return nil
	}
	var providers []authProviderDescriptor
	for _, value := range []any{source["providers"], source["provider_descriptors"]} {
		providers = append(providers, parseAuthProviderDescriptorList(value)...)
	}
	if catalog, ok := source["provider_catalog"].(map[string]any); ok {
		providers = append(providers, parseAuthProviderDescriptorList(catalog["providers"])...)
	}
	return providers
}

func parseAuthProviderDescriptorList(value any) []authProviderDescriptor {
	switch typed := value.(type) {
	case []map[string]any:
		providers := make([]authProviderDescriptor, 0, len(typed))
		for _, item := range typed {
			if provider := parseAuthProviderDescriptor(item); provider.ID != "" {
				providers = append(providers, provider)
			}
		}
		return providers
	case []any:
		providers := make([]authProviderDescriptor, 0, len(typed))
		for _, item := range typed {
			if itemMap, ok := item.(map[string]any); ok {
				if provider := parseAuthProviderDescriptor(itemMap); provider.ID != "" {
					providers = append(providers, provider)
				}
			}
		}
		return providers
	default:
		return nil
	}
}

func parseAuthProviderDescriptor(values map[string]any) authProviderDescriptor {
	provider := authProviderDescriptor{
		ID:             providerString(values, "id"),
		Label:          providerString(values, "label"),
		Description:    providerString(values, "description"),
		Categories:     providerStringSlice(values, "categories"),
		Implementation: providerString(values, "implementation"),
		Version:        providerString(values, "version"),
		DocsURL:        providerString(values, "docs_url"),
		SupportLevel:   providerString(values, "support_level"),
		DisabledReason: providerString(values, "disabled_reason"),
	}
	provider.ID = strings.ToLower(strings.TrimSpace(provider.ID))
	if provider.Label == "" {
		provider.Label = provider.ID
	}
	for _, item := range providerMapSlice(values["capabilities"]) {
		capability := parseAuthProviderCapability(item)
		if capability.Key != "" {
			provider.Capabilities = append(provider.Capabilities, capability)
		}
	}
	return provider
}

func parseAuthProviderCapability(values map[string]any) authProviderCapability {
	capability := authProviderCapability{
		Key:              providerString(values, "key"),
		Label:            providerString(values, "label"),
		Category:         providerString(values, "category"),
		Description:      providerString(values, "description"),
		Supported:        providerBoolDefault(values, "supported", false),
		DisabledReason:   providerString(values, "disabled_reason"),
		AppScopes:        providerStringSlice(values, "app_scopes"),
		AdminReadScopes:  providerStringSlice(values, "admin_read_scopes"),
		AdminWriteScopes: providerStringSlice(values, "admin_write_scopes"),
	}
	if capability.Label == "" {
		capability.Label = capability.Key
	}
	for _, item := range providerMapSlice(values["config_fields"]) {
		field := parseAuthProviderConfigField(item)
		if field.Key != "" {
			capability.ConfigFields = append(capability.ConfigFields, field)
		}
	}
	return capability
}

func parseAuthProviderConfigField(values map[string]any) authProviderConfigField {
	field := authProviderConfigField{
		Key:               providerString(values, "key"),
		Label:             providerString(values, "label"),
		Description:       providerString(values, "description"),
		HelpText:          providerString(values, "help_text"),
		InputType:         providerString(values, "input_type"),
		Secret:            providerBoolDefault(values, "secret", false),
		Required:          providerBoolDefault(values, "required", false),
		Lookup:            providerString(values, "lookup"),
		ValidationPattern: providerString(values, "validation_pattern"),
	}
	if field.Label == "" {
		field.Label = field.Key
	}
	if field.InputType == "" {
		field.InputType = "text"
	}
	if field.HelpText == "" {
		field.HelpText = field.Description
	}
	if field.HelpText == "" {
		field.HelpText = fmt.Sprintf("Configure %s.", field.Label)
	}
	for _, item := range providerMapSlice(values["options"]) {
		option := authProviderConfigOption{
			Value:       providerString(item, "value"),
			Label:       providerString(item, "label"),
			Description: providerString(item, "description"),
		}
		if option.Value != "" {
			if option.Label == "" {
				option.Label = option.Value
			}
			field.Options = append(field.Options, option)
		}
	}
	return field
}

func (p authProviderDescriptor) toMap() map[string]any {
	capabilities := make([]map[string]any, 0, len(p.Capabilities))
	for _, capability := range p.Capabilities {
		capabilities = append(capabilities, capability.toMap())
	}
	return map[string]any{
		"id":              p.ID,
		"label":           p.Label,
		"description":     p.Description,
		"categories":      append([]string(nil), p.Categories...),
		"implementation":  p.Implementation,
		"version":         p.Version,
		"docs_url":        p.DocsURL,
		"support_level":   p.SupportLevel,
		"disabled_reason": p.DisabledReason,
		"capabilities":    capabilities,
	}
}

func (c authProviderCapability) toMap() map[string]any {
	fields := make([]map[string]any, 0, len(c.ConfigFields))
	for _, field := range c.ConfigFields {
		fields = append(fields, field.toMap())
	}
	return map[string]any{
		"key":                c.Key,
		"label":              c.Label,
		"category":           c.Category,
		"description":        c.Description,
		"supported":          c.Supported,
		"disabled_reason":    c.DisabledReason,
		"app_scopes":         append([]string(nil), c.AppScopes...),
		"admin_read_scopes":  append([]string(nil), c.AdminReadScopes...),
		"admin_write_scopes": append([]string(nil), c.AdminWriteScopes...),
		"config_fields":      fields,
	}
}

func (f authProviderConfigField) toMap() map[string]any {
	options := make([]map[string]any, 0, len(f.Options))
	for _, option := range f.Options {
		options = append(options, map[string]any{
			"value":       option.Value,
			"label":       option.Label,
			"description": option.Description,
		})
	}
	return map[string]any{
		"key":                f.Key,
		"label":              f.Label,
		"description":        f.Description,
		"help_text":          f.HelpText,
		"input_type":         f.InputType,
		"secret":             f.Secret,
		"required":           f.Required,
		"options":            options,
		"lookup":             f.Lookup,
		"validation_pattern": f.ValidationPattern,
	}
}

func authProviderDescriptorsCompatible(a, b authProviderDescriptor) bool {
	if a.ID != b.ID {
		return false
	}
	if len(a.Capabilities) != len(b.Capabilities) {
		return false
	}
	keys := make(map[string]struct{}, len(a.Capabilities))
	for _, capability := range a.Capabilities {
		keys[capability.Key] = struct{}{}
	}
	for _, capability := range b.Capabilities {
		if _, ok := keys[capability.Key]; !ok {
			return false
		}
	}
	return true
}

func authProviderOAuthProviders(source map[string]any) []authProviderDescriptor {
	providers := authProviderDescriptors(source)
	oauthProviders := make([]authProviderDescriptor, 0, len(providers))
	for _, provider := range providers {
		if provider.hasCategory("oauth2_oidc") || provider.hasCapabilityCategory("oauth2_oidc") {
			oauthProviders = append(oauthProviders, provider)
		}
	}
	return oauthProviders
}

func (p authProviderDescriptor) hasCategory(category string) bool {
	for _, candidate := range p.Categories {
		if strings.EqualFold(strings.TrimSpace(candidate), category) {
			return true
		}
	}
	return false
}

func (p authProviderDescriptor) hasCapabilityCategory(category string) bool {
	for _, capability := range p.Capabilities {
		if strings.EqualFold(strings.TrimSpace(capability.Category), category) {
			return true
		}
	}
	return false
}

func (p authProviderDescriptor) oauthCapabilities() []authProviderCapability {
	capabilities := make([]authProviderCapability, 0, len(p.Capabilities))
	for _, capability := range p.Capabilities {
		if strings.EqualFold(strings.TrimSpace(capability.Category), "oauth2_oidc") {
			capabilities = append(capabilities, capability)
		}
	}
	return capabilities
}

func providerString(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	switch typed := values[key].(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		if typed == nil {
			return ""
		}
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func providerStringSlice(values map[string]any, key string) []string {
	value, ok := values[key]
	if !ok {
		return nil
	}
	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			text := strings.TrimSpace(fmt.Sprint(item))
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	case string:
		if strings.TrimSpace(typed) == "" {
			return nil
		}
		return []string{strings.TrimSpace(typed)}
	default:
		return nil
	}
}

func providerBoolDefault(values map[string]any, key string, def bool) bool {
	value, ok := values[key]
	if !ok {
		return def
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return def
	}
}

func providerMapSlice(value any) []map[string]any {
	switch typed := value.(type) {
	case []map[string]any:
		return typed
	case []any:
		out := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if itemMap, ok := item.(map[string]any); ok {
				out = append(out, itemMap)
			}
		}
		return out
	default:
		return nil
	}
}
