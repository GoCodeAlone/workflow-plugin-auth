// Command workflow-plugin-auth is a workflow engine external plugin that
// provides passwordless authentication (WebAuthn/passkeys, TOTP, email magic links).
// It runs as a subprocess and communicates with the host workflow engine via
// the go-plugin protocol.
package main

import (
	"github.com/GoCodeAlone/workflow-plugin-auth/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.Serve(internal.NewAuthPlugin())
}
