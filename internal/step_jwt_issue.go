package internal

import (
	"context"
	"os"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/structpb"
)

const jwtMinSecretLength = 32

type jwtIssueStep struct {
	name      string
	secretEnv string
	issuer    string
	ttl       time.Duration
}

func newJWTIssueStep(name string, config map[string]any) *jwtIssueStep {
	secretEnv := configString(config, "secret_env")
	if secretEnv == "" {
		secretEnv = "AUTH_JWT_SECRET"
	}
	issuer := configString(config, "issuer")
	if issuer == "" {
		issuer = "workflow-plugin-auth"
	}
	ttl := 3600 * time.Second
	if n, ok := coerceCount(config["ttl_seconds"]); ok && n > 0 {
		ttl = time.Duration(n) * time.Second
	}
	return &jwtIssueStep{name: name, secretEnv: secretEnv, issuer: issuer, ttl: ttl}
}

func (s *jwtIssueStep) Execute(_ context.Context, _ map[string]any, _ map[string]map[string]any, current, _, _ map[string]any) (*sdk.StepResult, error) {
	secret := strings.TrimSpace(os.Getenv(s.secretEnv))
	if len(secret) < jwtMinSecretLength {
		return &sdk.StepResult{Output: map[string]any{"error": "signing secret not configured"}}, nil
	}
	subject, _ := current["subject"].(string)
	if strings.TrimSpace(subject) == "" {
		// Never mint an identity-less (sub="") token — a misconfigured pipeline
		// would otherwise produce an anonymous principal that signature-only
		// validation (auth.jwt.Authenticate) accepts.
		return &sdk.StepResult{Output: map[string]any{"error": "subject is required"}}, nil
	}

	claims := jwt.MapClaims{}
	// caller claims FIRST...
	switch caller := current["claims"].(type) {
	case map[string]any:
		for k, v := range caller {
			claims[k] = v
		}
	case *structpb.Struct:
		if caller != nil {
			for k, v := range caller.AsMap() {
				claims[k] = v
			}
		}
	}
	// ...then standard claims ALWAYS overwrite (V-B8: caller cannot override).
	now := time.Now()
	exp := now.Add(s.ttl)
	claims["sub"] = subject
	claims["iat"] = now.Unix()
	claims["exp"] = exp.Unix()
	claims["iss"] = s.issuer
	claims["jti"] = uuid.NewString()

	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		return &sdk.StepResult{Output: map[string]any{"error": "failed to sign token"}}, nil
	}
	return &sdk.StepResult{Output: map[string]any{
		"token": signed, "expires_at": exp.UTC().Format(time.RFC3339),
	}}, nil
}
