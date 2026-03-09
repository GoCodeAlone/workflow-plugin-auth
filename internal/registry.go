package internal

import "sync"

var (
	mu        sync.RWMutex
	providers = make(map[string]*credentialModule)
)

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
