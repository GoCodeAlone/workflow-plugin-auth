package internal

import "sync"

var (
	mu        sync.RWMutex
	providers = make(map[string]*credentialModule)
)

// passwordAuthDisabled returns true iff any registered credentialModule
// has `disable_password_auth: true`. Any single tenant/host opting out
// is enough — password steps refuse for the whole process. This is the
// fail-safe default for hosts that want passwordless guarantees (V17).
//
// Hosts that need a mixed posture (some pipelines password-OK, others
// not) should run separate plugin processes — the disable knob is a
// per-process invariant, not per-pipeline.
func passwordAuthDisabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	for _, m := range providers {
		if m != nil && m.disablePasswordAuth {
			return true
		}
	}
	return false
}

func registerModule(name string, m *credentialModule) {
	mu.Lock()
	defer mu.Unlock()
	providers[name] = m
}

func getModule(name string) *credentialModule {
	mu.RLock()
	defer mu.RUnlock()
	return providers[name]
}

func unregisterModule(name string) {
	mu.Lock()
	defer mu.Unlock()
	delete(providers, name)
}
