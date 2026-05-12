package internal

import (
	"reflect"
	"testing"
)

func TestPluginRegistersUnderV0_51_2(t *testing.T) {
	p := NewAuthPlugin()
	if p == nil {
		t.Fatal("NewAuthPlugin() returned nil")
	}
	// Guard against typed-nil (interface non-nil but underlying pointer is nil),
	// which would panic at sdk.Serve call time.
	v := reflect.ValueOf(p)
	if v.Kind() == reflect.Ptr && v.IsNil() {
		t.Fatal("NewAuthPlugin() returned a typed-nil interface value")
	}
	// Type-assert to concrete type to confirm factory wiring.
	if _, ok := p.(*authPlugin); !ok {
		t.Fatalf("NewAuthPlugin() returned unexpected type %T", p)
	}
}
