package agentidentity

import (
	"context"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"
)

// TenantConfig is declarative per-preview configuration, independent of keys
// and grants. Adding a tenant requires a configuration entry and owner-approved
// grant, not a source fork, implicit enrollment or shared personal credential.
type TenantConfig struct {
	TenantID      int64         `json:"tenant_id"`
	APIAudience   string        `json:"api_audience"`
	PagesPath     string        `json:"pages_path"`
	HistoryPath   string        `json:"history_path"`
	Scopes        []string      `json:"scopes"`
	UpdatePageIDs []string      `json:"update_page_ids"`
	Preview       *PreviewGrant `json:"preview,omitempty"`
}

// TenantPolicy is an immutable allowlist of explicit preview tenants. Never
// include a live tenant in this configuration. It matches real host routes,
// field/page ceilings and protected preview origins; it confers no credential.
type TenantPolicy struct{ tenants map[int64]TenantConfig }

func (p *TenantPolicy) configs() []TenantConfig {
	out := make([]TenantConfig, 0, len(p.tenants))
	for _, c := range p.tenants {
		c.Scopes = slices.Clone(c.Scopes)
		c.UpdatePageIDs = slices.Clone(c.UpdatePageIDs)
		if c.Preview != nil {
			copy := *c.Preview
			copy.Paths = slices.Clone(copy.Paths)
			c.Preview = &copy
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantID < out[j].TenantID })
	return out
}

func NewTenantPolicy(config []TenantConfig) (*TenantPolicy, error) {
	if len(config) == 0 {
		return nil, ErrUnavailable
	}
	p := &TenantPolicy{tenants: map[int64]TenantConfig{}}
	for _, c := range config {
		if c.TenantID <= 0 || p.tenants[c.TenantID].TenantID != 0 || !httpsURL(c.APIAudience) || !managementPath(c.PagesPath) || path.Clean(c.PagesPath) != c.PagesPath || c.HistoryPath != c.PagesPath+"/history" || !canonicalScopes(c.Scopes) {
			return nil, ErrUnavailable
		}
		if slices.Contains(c.Scopes, PagesUpdate) && len(c.UpdatePageIDs) == 0 {
			return nil, ErrUnavailable
		}
		seen := map[string]bool{}
		for _, id := range c.UpdatePageIDs {
			if !pageIdentifier(id) || seen[id] {
				return nil, ErrUnavailable
			}
			seen[id] = true
		}
		if slices.Contains(c.Scopes, PreviewRead) {
			if c.Preview == nil || !httpsOrigin(c.Preview.Origin) || !httpsURL(c.Preview.Audience) || c.Preview.Audience == c.APIAudience || len(c.Preview.Paths) == 0 {
				return nil, ErrUnavailable
			}
			seen = map[string]bool{}
			for _, route := range c.Preview.Paths {
				if !previewPath(route) || seen[route] {
					return nil, ErrUnavailable
				}
				seen[route] = true
			}
		} else if c.Preview != nil {
			return nil, ErrUnavailable
		}
		c.Scopes = slices.Clone(c.Scopes)
		c.UpdatePageIDs = slices.Clone(c.UpdatePageIDs)
		if c.Preview != nil {
			copy := *c.Preview
			copy.Paths = slices.Clone(copy.Paths)
			c.Preview = &copy
		}
		p.tenants[c.TenantID] = c
	}
	return p, nil
}

func (p *TenantPolicy) AllowGrant(_ context.Context, g Grant) error {
	c, ok := p.tenants[g.TenantID]
	if !ok || g.APIAudience != c.APIAudience {
		return ErrDenied
	}
	for _, scope := range g.Scopes {
		if !slices.Contains(c.Scopes, scope) {
			return ErrDenied
		}
	}
	for _, id := range g.UpdatePageIDs {
		if !slices.Contains(c.UpdatePageIDs, id) {
			return ErrDenied
		}
	}
	if g.Preview != nil {
		if c.Preview == nil || g.Preview.Audience != c.Preview.Audience || g.Preview.Origin != c.Preview.Origin {
			return ErrDenied
		}
		for _, route := range g.Preview.Paths {
			if !slices.Contains(c.Preview.Paths, route) {
				return ErrDenied
			}
		}
	}
	return nil
}

func (p *TenantPolicy) AllowResource(ctx context.Context, g Grant, r Resource) error {
	if p.AllowGrant(ctx, g) != nil || r.TenantID != g.TenantID {
		return ErrDenied
	}
	c := p.tenants[g.TenantID]
	if r.Scope == PreviewRead {
		if c.Preview == nil || r.Origin != c.Preview.Origin || !slices.Contains(c.Preview.Paths, r.Path) {
			return ErrDenied
		}
		return nil
	}
	// Resource paths must come from canonical host route resolution. Reject
	// encoded aliases, trailing slashes, query strings and accidental auth/admin
	// routes even if a host misclassifies one as a page-read permission.
	if strings.ContainsAny(r.Path, "%?#\\") || path.Clean(r.Path) != r.Path {
		return ErrDenied
	}
	switch r.Scope {
	case HistoryRead:
		if r.Path == c.HistoryPath && r.PageID == "" {
			return nil
		}
	case PagesRead:
		if r.Path == c.PagesPath && r.PageID == "" {
			return nil
		}
		if pageIdentifier(r.PageID) && r.Path == fmt.Sprintf("%s/%s", c.PagesPath, r.PageID) {
			return nil
		}
	case PagesUpdate:
		if slices.Contains(c.UpdatePageIDs, r.PageID) && r.Path == c.PagesPath+"/"+r.PageID {
			return nil
		}
	}
	return ErrDenied
}
