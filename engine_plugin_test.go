package workflowpluginauth

import (
	"context"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow/module"
	"github.com/GoCodeAlone/workflow/plugin"
)

// TestAuthEnginePlugin_Shape verifies the in-process EnginePlugin entry
// (ADR 0056 dual-shape) exposes the expected manifest name + step factories,
// WITHOUT touching the gRPC/sdk path.
func TestAuthEnginePlugin_Shape(t *testing.T) {
	p := NewAuthEnginePlugin()
	if p == nil {
		t.Fatal("NewAuthEnginePlugin() returned nil")
	}
	var _ plugin.EnginePlugin = p

	man := p.EngineManifest()
	if man == nil {
		t.Fatal("EngineManifest() returned nil")
	}
	if man.Name != "workflow-plugin-auth" {
		t.Fatalf("EngineManifest().Name = %q, want %q", man.Name, "workflow-plugin-auth")
	}

	factories := p.StepFactories()
	if factories == nil {
		t.Fatal("StepFactories() returned nil")
	}
	for _, want := range []string{"step.auth_password_hash", "step.auth_password_verify"} {
		if _, ok := factories[want]; !ok {
			t.Errorf("StepFactories() missing %q (have %d keys)", want, len(factories))
		}
	}
}

// TestAuthEnginePlugin_ReverseBridgeDelegates verifies the reverse sdk→in-process
// bridge wraps auth's existing sdk password-hash step such that the in-process
// Execute signature (ctx, *module.PipelineContext) delegates to the sdk step
// and produces a bcrypt hash in the output.
func TestAuthEnginePlugin_ReverseBridgeDelegates(t *testing.T) {
	p := NewAuthEnginePlugin()
	factory, ok := p.StepFactories()["step.auth_password_hash"]
	if !ok {
		t.Fatal("step.auth_password_hash factory missing")
	}

	// StepFactory signature: func(name, config, app) (any, error); app may be nil
	// for steps that don't use the service registry.
	stepAny, err := factory("hash_pw", nil, nil)
	if err != nil {
		t.Fatalf("factory returned error: %v", err)
	}
	pstep, ok := stepAny.(module.PipelineStep)
	if !ok {
		t.Fatalf("factory returned %T, does not implement module.PipelineStep", stepAny)
	}

	result, err := pstep.Execute(context.Background(), &module.PipelineContext{
		Current: map[string]any{"password": "hunter2"},
	})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if result == nil {
		t.Fatal("Execute returned nil result")
	}
	hash, _ := result.Output["hash"].(string)
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("output hash = %q, want a bcrypt hash starting with $2", hash)
	}
}
