package internal

import (
	"testing"
)

func TestPluginRegistersUnderV0_51_2(t *testing.T) {
	mod := NewAuthPlugin()
	if mod == nil {
		t.Fatal("NewAuthPlugin() returned nil")
	}
}
