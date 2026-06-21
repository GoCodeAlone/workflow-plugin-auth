package adminidentity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewHandlerRequiresTypedAdapters(t *testing.T) {
	_, err := NewHandler(Options{})
	if err == nil {
		t.Fatal("NewHandler without adapters succeeded")
	}
	for _, want := range []string{"PrincipalResolver", "UserStore", "CredentialStore", "SetupCodeStore", "StepInvoker"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing %s", err.Error(), want)
		}
	}
}

func TestHandlerServesIdentityPageWithConfiguredRoutes(t *testing.T) {
	h := newTestHandler(t, &testStores{})

	req := httptest.NewRequest(http.MethodGet, "/admin/account/profile/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`data-auth-identity-admin="1"`,
		`"profilePath":"/api/v1/admin/account/profile"`,
		`"credentialsPath":"/api/v1/admin/account/credentials"`,
		`"passkeyBeginPath":"/api/v1/admin/account/passkeys/register/begin"`,
		`"passkeyFinishPath":"/api/v1/admin/account/passkeys/register/finish"`,
		`"totpBeginPath":"/api/v1/admin/account/totp/begin"`,
		`"totpVerifyPath":"/api/v1/admin/account/totp/verify"`,
		`"usersPath":"/api/v1/admin/auth/users"`,
		`"setupLoginPath":"/login"`,
		`id="profileForm"`,
		`method:"PATCH"`,
		`id="inviteForm"`,
		`Add admin`,
		`loadProfile().catch`,
		`loadCredentials().catch`,
		`loadUsers().catch`,
		`beginTotp.addEventListener("click"`,
		`fetch(config.totpBeginPath`,
		`fetch(config.totpVerifyPath`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("identity page missing %s\n%s", want, body)
		}
	}
	if strings.Contains(body, `Promise.all([loadProfile(),loadCredentials(),loadUsers()]).catch`) {
		t.Fatalf("identity page still routes all loader failures into one shared handler:\n%s", body)
	}
}

func TestProfilePatchUsesTypedUpdater(t *testing.T) {
	stores := &testStores{}
	h := newTestHandler(t, stores)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/admin/account/profile", strings.NewReader(`{"display_name":"Updated Admin","recovery_email":"recovery@example.test"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}
	if stores.profileUpdate.DisplayName != "Updated Admin" || stores.profileUpdate.RecoveryEmail != "recovery@example.test" {
		t.Fatalf("profile update = %#v", stores.profileUpdate)
	}
	var payload struct {
		User User `json:"user"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.User.DisplayName != "Updated Admin" {
		t.Fatalf("user = %#v, want updated display name", payload.User)
	}
}

func TestCredentialsReflectTOTPEnrollmentState(t *testing.T) {
	stores := &testStores{
		credentials: []Credential{
			{ID: "cred-passkey", UserID: "user-1", Kind: CredentialKindPasskey, Label: "MacBook"},
			{ID: "cred-totp", UserID: "user-1", Kind: CredentialKindTOTP, Label: "Authenticator"},
		},
	}
	h := newTestHandler(t, stores)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/account/credentials", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%s", rec.Code, rec.Body.String())
	}
	var payload struct {
		TOTPEnrolled bool            `json:"totp_enrolled"`
		Credentials  []Credential    `json:"credentials"`
		Methods      map[string]bool `json:"methods"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !payload.TOTPEnrolled {
		t.Fatalf("totp_enrolled = false, want true; payload=%s", rec.Body.String())
	}
	if len(payload.Credentials) != 2 {
		t.Fatalf("credentials len = %d, want 2", len(payload.Credentials))
	}
	if !payload.Methods["passkey"] || !payload.Methods["totp"] {
		t.Fatalf("methods = %#v, want passkey and totp", payload.Methods)
	}
}

func TestUsersPostIssuesSetupCodeWithDisplayNameAndSetupURL(t *testing.T) {
	stores := &testStores{}
	h := newTestHandler(t, stores)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/auth/users", strings.NewReader(`{"email":"editor@example.test","display_name":"Editor User","role":"tenant_editor"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 body=%s", rec.Code, rec.Body.String())
	}
	if stores.setupInput.Email != "editor@example.test" || stores.setupInput.DisplayName != "Editor User" || stores.setupInput.Role != "tenant_editor" {
		t.Fatalf("setup input = %#v", stores.setupInput)
	}
	var payload struct {
		Code     string `json:"code"`
		SetupURL string `json:"setup_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != "setup-code" || payload.SetupURL != "/login?setup_code=setup-code" {
		t.Fatalf("payload = %#v", payload)
	}
}

func TestTOTPBeginAndVerifyUseStepInvokerAndCredentialStore(t *testing.T) {
	stores := &testStores{}
	invoker := &recordingInvoker{
		outputs: map[string]map[string]any{
			"step.auth_totp_generate_secret": {
				"secret":           "secret-123",
				"provisioning_uri": "otpauth://totp/example",
			},
			"step.auth_totp_verify": {
				"valid": true,
			},
		},
	}
	h := newTestHandlerWithInvoker(t, stores, invoker)

	begin := httptest.NewRequest(http.MethodPost, "/api/v1/admin/account/totp/begin", nil)
	beginRec := httptest.NewRecorder()
	h.ServeHTTP(beginRec, begin)
	if beginRec.Code != http.StatusOK {
		t.Fatalf("begin status = %d, want 200 body=%s", beginRec.Code, beginRec.Body.String())
	}
	if invoker.calls[0].StepType != "step.auth_totp_generate_secret" {
		t.Fatalf("first step = %s, want generate secret", invoker.calls[0].StepType)
	}

	verify := httptest.NewRequest(http.MethodPost, "/api/v1/admin/account/totp/verify", strings.NewReader(`{"secret":"secret-123","code":"123456","label":"phone"}`))
	verify.Header.Set("Content-Type", "application/json")
	verifyRec := httptest.NewRecorder()
	h.ServeHTTP(verifyRec, verify)
	if verifyRec.Code != http.StatusCreated {
		t.Fatalf("verify status = %d, want 201 body=%s", verifyRec.Code, verifyRec.Body.String())
	}
	if invoker.calls[1].StepType != "step.auth_totp_verify" {
		t.Fatalf("second step = %s, want verify", invoker.calls[1].StepType)
	}
	if got := stores.addedTOTPSecret; got != "secret-123" {
		t.Fatalf("stored TOTP secret = %q, want secret-123", got)
	}
}

func TestPasskeyBeginAndFinishUseStepInvokerAndCredentialStore(t *testing.T) {
	stores := &testStores{}
	invoker := &recordingInvoker{
		outputs: map[string]map[string]any{
			"step.auth_passkey_begin_register": {
				"session_data": `{"challenge":"abc"}`,
				"options":      `{"publicKey":{}}`,
			},
			"step.auth_passkey_finish_register": {
				"valid":         true,
				"credential_id": "passkey-1",
				"credential":    `{"id":"passkey-1"}`,
			},
		},
	}
	h := newTestHandlerWithInvoker(t, stores, invoker)

	begin := httptest.NewRequest(http.MethodPost, "/api/v1/admin/account/passkeys/register/begin", nil)
	beginRec := httptest.NewRecorder()
	h.ServeHTTP(beginRec, begin)
	if beginRec.Code != http.StatusOK {
		t.Fatalf("begin status = %d, want 200 body=%s", beginRec.Code, beginRec.Body.String())
	}
	if invoker.calls[0].StepType != "step.auth_passkey_begin_register" {
		t.Fatalf("first step = %s, want passkey begin", invoker.calls[0].StepType)
	}

	finish := httptest.NewRequest(http.MethodPost, "/api/v1/admin/account/passkeys/register/finish", strings.NewReader(`{"session_data":"{\"challenge\":\"abc\"}","credential":"{\"id\":\"passkey-1\"}","label":"MacBook"}`))
	finish.Header.Set("Content-Type", "application/json")
	finishRec := httptest.NewRecorder()
	h.ServeHTTP(finishRec, finish)
	if finishRec.Code != http.StatusCreated {
		t.Fatalf("finish status = %d, want 201 body=%s", finishRec.Code, finishRec.Body.String())
	}
	if invoker.calls[1].StepType != "step.auth_passkey_finish_register" {
		t.Fatalf("second step = %s, want passkey finish", invoker.calls[1].StepType)
	}
	if got := stores.addedPasskeyCredential; got != `{"id":"passkey-1"}` {
		t.Fatalf("stored passkey credential = %q, want JSON credential", got)
	}
}

func TestSetupCodeRedeemRejectsWrongEmailAndIssuesSession(t *testing.T) {
	stores := &testStores{
		setup: SetupCode{
			ID:        "setup-1",
			Code:      "code-1",
			Email:     "admin@example.test",
			UserID:    "user-2",
			Role:      "tenant_admin",
			TenantIDs: []string{"blackorchid"},
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}
	h := newTestHandler(t, stores)

	wrong := httptest.NewRequest(http.MethodPost, "/api/v1/admin/setup/redeem", strings.NewReader(`{"code":"code-1","email":"other@example.test"}`))
	wrong.Header.Set("Content-Type", "application/json")
	wrongRec := httptest.NewRecorder()
	h.ServeHTTP(wrongRec, wrong)
	if wrongRec.Code != http.StatusForbidden {
		t.Fatalf("wrong email status = %d, want 403 body=%s", wrongRec.Code, wrongRec.Body.String())
	}

	right := httptest.NewRequest(http.MethodPost, "/api/v1/admin/setup/redeem", strings.NewReader(`{"code":"code-1","email":"Admin@Example.TEST"}`))
	right.Header.Set("Content-Type", "application/json")
	rightRec := httptest.NewRecorder()
	h.ServeHTTP(rightRec, right)
	if rightRec.Code != http.StatusOK {
		t.Fatalf("right email status = %d, want 200 body=%s", rightRec.Code, rightRec.Body.String())
	}
	if !stores.sessionIssued {
		t.Fatal("session was not issued")
	}
	if got := stores.lastRedeemEmail; got != "admin@example.test" {
		t.Fatalf("redeem email = %q, want normalized admin@example.test", got)
	}
}

func TestSetupCodeRedeemHidesUnexpectedStoreErrors(t *testing.T) {
	stores := &testStores{
		setup: SetupCode{
			Code:      "code-1",
			Email:     "admin@example.test",
			ExpiresAt: time.Now().Add(time.Hour),
		},
		redeemErr: errors.New("database password leaked in error"),
	}
	h := newTestHandler(t, stores)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/setup/redeem", strings.NewReader(`{"code":"code-1","email":"admin@example.test"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "database password") {
		t.Fatalf("unexpected store error leaked to client: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "setup code unavailable") {
		t.Fatalf("body = %s, want generic setup code unavailable error", rec.Body.String())
	}
}

func TestLogoutRouteRequiresHostSuppliedHandler(t *testing.T) {
	stores := &testStores{}
	h, err := NewHandler(Options{
		LogoutPath:        "/api/v1/admin/logout",
		PrincipalResolver: fixedPrincipal{principal: Principal{UserID: "user-1", Email: "admin@example.test", Role: "super_admin"}},
		UserStore:         stores,
		CredentialStore:   stores,
		SetupCodeStore:    stores,
		SessionIssuer:     stores,
		StepInvoker:       &recordingInvoker{},
		Authorizer:        allowAuthorizer{},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/logout", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("logout without host handler set cookies: %#v", got)
	}
}

func TestHandlerRedactsSensitiveCredentialFields(t *testing.T) {
	stores := &testStores{
		credentials: []Credential{
			{
				ID:             "cred-1",
				UserID:         "user-1",
				Kind:           CredentialKindTOTP,
				Label:          "Authenticator",
				SecretMaterial: "do-not-return",
			},
		},
	}
	h := newTestHandler(t, stores)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/account/credentials", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if strings.Contains(rec.Body.String(), "do-not-return") {
		t.Fatalf("credential response leaked secret material: %s", rec.Body.String())
	}
}

func newTestHandler(t *testing.T, stores *testStores) http.Handler {
	t.Helper()
	return newTestHandlerWithInvoker(t, stores, &recordingInvoker{})
}

func newTestHandlerWithInvoker(t *testing.T, stores *testStores, invoker *recordingInvoker) http.Handler {
	t.Helper()
	if stores == nil {
		stores = &testStores{}
	}
	if stores.user.ID == "" {
		stores.user = User{ID: "user-1", Email: "admin@example.test", DisplayName: "Admin", Role: "super_admin"}
	}
	if stores.sessionToken == "" {
		stores.sessionToken = "session-token"
	}
	h, err := NewHandler(Options{
		PagePath:          "/admin/account/profile/",
		ProfilePath:       "/api/v1/admin/account/profile",
		CredentialsPath:   "/api/v1/admin/account/credentials",
		PasskeyBeginPath:  "/api/v1/admin/account/passkeys/register/begin",
		PasskeyFinishPath: "/api/v1/admin/account/passkeys/register/finish",
		TOTPBeginPath:     "/api/v1/admin/account/totp/begin",
		TOTPVerifyPath:    "/api/v1/admin/account/totp/verify",
		UsersPath:         "/api/v1/admin/auth/users",
		SetupRedeemPath:   "/api/v1/admin/setup/redeem",
		PrincipalResolver: fixedPrincipal{principal: Principal{UserID: stores.user.ID, Email: stores.user.Email, Role: stores.user.Role}},
		UserStore:         stores,
		CredentialStore:   stores,
		SetupCodeStore:    stores,
		SessionIssuer:     stores,
		StepInvoker:       invoker,
		Authorizer:        allowAuthorizer{},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

type fixedPrincipal struct{ principal Principal }

func (r fixedPrincipal) CurrentPrincipal(*http.Request) (Principal, bool) {
	return r.principal, true
}

type allowAuthorizer struct{}

func (allowAuthorizer) Authorize(context.Context, Principal, string, string) error { return nil }

type testStores struct {
	user                   User
	users                  []User
	credentials            []Credential
	setup                  SetupCode
	sessionToken           string
	addedTOTPSecret        string
	addedPasskeyCredential string
	sessionIssued          bool
	redeemErr              error
	lastRedeemEmail        string
	profileUpdate          UpdateProfileInput
	setupInput             IssueSetupCodeInput
}

func (s *testStores) CurrentUser(context.Context, Principal) (User, error) {
	return s.user, nil
}

func (s *testStores) ListUsers(context.Context, ListUsersFilter) ([]User, error) {
	if len(s.users) > 0 {
		return s.users, nil
	}
	return []User{s.user}, nil
}

func (s *testStores) UpdateCurrentUser(_ context.Context, _ Principal, input UpdateProfileInput) (User, error) {
	s.profileUpdate = input
	s.user.DisplayName = input.DisplayName
	return s.user, nil
}

func (s *testStores) ListCredentials(context.Context, string) ([]Credential, error) {
	return s.credentials, nil
}

func (s *testStores) AddTOTPCredential(_ context.Context, userID string, input AddTOTPCredentialInput) (Credential, error) {
	s.addedTOTPSecret = input.Secret
	credential := Credential{ID: "cred-new-totp", UserID: userID, Kind: CredentialKindTOTP, Label: input.Label}
	s.credentials = append(s.credentials, credential)
	return credential, nil
}

func (s *testStores) AddPasskeyCredential(_ context.Context, userID string, input AddPasskeyCredentialInput) (Credential, error) {
	s.addedPasskeyCredential = input.CredentialJSON
	credential := Credential{ID: input.CredentialID, UserID: userID, Kind: CredentialKindPasskey, Label: input.Label}
	s.credentials = append(s.credentials, credential)
	return credential, nil
}

func (s *testStores) IssueSetupCode(_ context.Context, input IssueSetupCodeInput) (SetupCode, error) {
	s.setupInput = input
	s.setup = SetupCode{
		ID:        "setup-issued",
		Code:      "setup-code",
		Email:     input.Email,
		UserID:    "user-issued",
		Role:      input.Role,
		TenantIDs: input.TenantIDs,
		ExpiresAt: input.ExpiresAt,
	}
	return s.setup, nil
}

func (s *testStores) RedeemSetupCode(_ context.Context, code, email string) (SetupCode, error) {
	s.lastRedeemEmail = email
	if s.redeemErr != nil {
		return SetupCode{}, s.redeemErr
	}
	if s.setup.Code != code {
		return SetupCode{}, ErrSetupCodeNotFound
	}
	if normalizeEmail(email) != normalizeEmail(s.setup.Email) {
		return SetupCode{}, ErrSetupCodeWrongEmail
	}
	return s.setup, nil
}

func (s *testStores) IssueSession(context.Context, SessionRequest) (Session, error) {
	s.sessionIssued = true
	return Session{Token: s.sessionToken, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

type recordingInvoker struct {
	calls   []StepCall
	outputs map[string]map[string]any
	err     error
}

func (i *recordingInvoker) InvokeStep(_ context.Context, call StepCall) (map[string]any, error) {
	i.calls = append(i.calls, call)
	if i.err != nil {
		return nil, i.err
	}
	if i.outputs != nil && i.outputs[call.StepType] != nil {
		return i.outputs[call.StepType], nil
	}
	return map[string]any{}, nil
}

func TestStepInvokerErrorReturnsBadGateway(t *testing.T) {
	h := newTestHandlerWithInvoker(t, &testStores{}, &recordingInvoker{err: errors.New("step down")})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/account/totp/begin", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 body=%s", rec.Code, rec.Body.String())
	}
}
