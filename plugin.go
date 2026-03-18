// Package workflowpluginauth provides the auth workflow plugin.
package workflowpluginauth

import (
	"github.com/GoCodeAlone/workflow-plugin-auth/internal"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// NewAuthPlugin returns the auth SDK plugin provider.
func NewAuthPlugin() sdk.PluginProvider {
	return internal.NewAuthPlugin()
}
