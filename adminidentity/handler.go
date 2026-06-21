package adminidentity

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

type handler struct {
	options Options
	mux     *http.ServeMux
}

// NewHandler returns an HTTP handler for reusable auth identity administration.
func NewHandler(options Options) (http.Handler, error) {
	options = normalizeOptions(options)
	if err := options.validate(); err != nil {
		return nil, err
	}
	h := &handler{options: options, mux: http.NewServeMux()}
	h.routes()
	return h, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}

func (h *handler) routes() {
	h.handle(h.options.PagePath, h.identityPage)
	h.handle(h.options.ProfilePath, h.profile)
	h.handle(h.options.CredentialsPath, h.credentials)
	h.handle(h.options.PasskeyBeginPath, h.passkeyBegin)
	h.handle(h.options.PasskeyFinishPath, h.passkeyFinish)
	h.handle(h.options.TOTPBeginPath, h.totpBegin)
	h.handle(h.options.TOTPVerifyPath, h.totpVerify)
	h.handle(h.options.UsersPath, h.users)
	h.handle(h.options.SetupRedeemPath, h.setupRedeem)
	if h.options.LogoutPath != "" {
		if h.options.LogoutHandler != nil {
			h.handleHandler(h.options.LogoutPath, h.options.LogoutHandler)
		} else {
			h.handle(h.options.LogoutPath, h.logout)
		}
	}
}

func (h *handler) handle(route string, fn http.HandlerFunc) {
	h.handleHandler(route, fn)
}

func (h *handler) handleHandler(route string, handler http.Handler) {
	clean := cleanPath(route)
	h.mux.Handle(clean, handler)
	if strings.HasSuffix(route, "/") {
		h.mux.HandleFunc(strings.TrimSuffix(clean, "/"), func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, clean, http.StatusMovedPermanently)
		})
	}
}

func normalizeOptions(options Options) Options {
	if strings.TrimSpace(options.PagePath) == "" {
		options.PagePath = "/api/admin/auth/identity"
	}
	if strings.TrimSpace(options.ProfilePath) == "" {
		options.ProfilePath = "/api/admin/auth/profile"
	}
	if strings.TrimSpace(options.CredentialsPath) == "" {
		options.CredentialsPath = "/api/admin/auth/credentials"
	}
	if strings.TrimSpace(options.PasskeyBeginPath) == "" {
		options.PasskeyBeginPath = "/api/admin/auth/passkeys/register/begin"
	}
	if strings.TrimSpace(options.PasskeyFinishPath) == "" {
		options.PasskeyFinishPath = "/api/admin/auth/passkeys/register/finish"
	}
	if strings.TrimSpace(options.TOTPBeginPath) == "" {
		options.TOTPBeginPath = "/api/admin/auth/totp/begin"
	}
	if strings.TrimSpace(options.TOTPVerifyPath) == "" {
		options.TOTPVerifyPath = "/api/admin/auth/totp/verify"
	}
	if strings.TrimSpace(options.UsersPath) == "" {
		options.UsersPath = "/api/admin/auth/users"
	}
	if strings.TrimSpace(options.SetupRedeemPath) == "" {
		options.SetupRedeemPath = "/api/admin/auth/setup/redeem"
	}
	if strings.TrimSpace(options.SetupLoginPath) == "" {
		options.SetupLoginPath = "/login"
	}
	options.PagePath = cleanPath(options.PagePath)
	options.ProfilePath = cleanPath(options.ProfilePath)
	options.CredentialsPath = cleanPath(options.CredentialsPath)
	options.PasskeyBeginPath = cleanPath(options.PasskeyBeginPath)
	options.PasskeyFinishPath = cleanPath(options.PasskeyFinishPath)
	options.TOTPBeginPath = cleanPath(options.TOTPBeginPath)
	options.TOTPVerifyPath = cleanPath(options.TOTPVerifyPath)
	options.UsersPath = cleanPath(options.UsersPath)
	options.SetupRedeemPath = cleanPath(options.SetupRedeemPath)
	options.SetupLoginPath = cleanPath(options.SetupLoginPath)
	if strings.TrimSpace(options.LogoutPath) != "" {
		options.LogoutPath = cleanPath(options.LogoutPath)
	}
	return options
}

func (o Options) validate() error {
	var missing []string
	if o.PrincipalResolver == nil {
		missing = append(missing, "PrincipalResolver")
	}
	if o.UserStore == nil {
		missing = append(missing, "UserStore")
	}
	if o.CredentialStore == nil {
		missing = append(missing, "CredentialStore")
	}
	if o.SetupCodeStore == nil {
		missing = append(missing, "SetupCodeStore")
	}
	if o.StepInvoker == nil {
		missing = append(missing, "StepInvoker")
	}
	if len(missing) > 0 {
		return fmt.Errorf("adminidentity: missing required adapters: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (h *handler) identityPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, "GET, HEAD")
		return
	}
	noStore(w)
	if _, ok := h.principal(w, r); !ok {
		return
	}
	html, err := identityHTML(h.options)
	if err != nil {
		http.Error(w, "identity admin unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(html)
}

func (h *handler) profile(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, principal, "auth.profile", "read") {
			return
		}
		user, err := h.options.UserStore.CurrentUser(r.Context(), principal)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "profile unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": user})
	case http.MethodPatch:
		if !h.authorize(w, r, principal, "auth.profile", "update") {
			return
		}
		var input UpdateProfileInput
		if err := decodeJSON(r, &input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		updater, ok := h.options.UserStore.(ProfileUpdater)
		if !ok {
			writeError(w, http.StatusNotImplemented, "profile update unavailable")
			return
		}
		user, err := updater.UpdateCurrentUser(r.Context(), principal, input)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "profile update unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": user})
	default:
		methodNotAllowed(w, "GET, PATCH")
	}
}

func (h *handler) credentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, "GET")
		return
	}
	noStore(w)
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	if !h.authorize(w, r, principal, "auth.credentials", "read") {
		return
	}
	credentials, err := h.options.CredentialStore.ListCredentials(r.Context(), principal.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credentials unavailable")
		return
	}
	totpEnrolled := false
	for _, credential := range credentials {
		if credential.Kind == CredentialKindTOTP {
			totpEnrolled = true
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"credentials":   credentials,
		"count":         len(credentials),
		"methods":       map[string]bool{"passkey": true, "totp": true, "google": false},
		"totp_enrolled": totpEnrolled,
	})
}

func (h *handler) users(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !h.authorize(w, r, principal, "auth.users", "read") {
			return
		}
		users, err := h.options.UserStore.ListUsers(r.Context(), ListUsersFilter{Principal: principal})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "users unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": users})
	case http.MethodPost:
		if !h.authorize(w, r, principal, "auth.invites", "create") {
			return
		}
		var input IssueSetupCodeInput
		if err := decodeJSON(r, &input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if input.ExpiresAt.IsZero() {
			input.ExpiresAt = time.Now().Add(24 * time.Hour)
		}
		code, err := h.options.SetupCodeStore.IssueSetupCode(r.Context(), input)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "setup code unavailable")
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"id":         code.ID,
			"code":       code.Code,
			"email":      code.Email,
			"role":       code.Role,
			"tenant_ids": code.TenantIDs,
			"expires_at": code.ExpiresAt,
			"setup_url":  setupURL(h.options, code.Code),
		})
	default:
		methodNotAllowed(w, "GET, POST")
	}
}

func (h *handler) passkeyBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	if !h.authorize(w, r, principal, "auth.credentials", "update") {
		return
	}
	out, err := h.options.StepInvoker.InvokeStep(r.Context(), StepCall{
		StepType: "step.auth_passkey_begin_register",
		Input: map[string]any{
			"user_id": principal.UserID,
			"email":   principal.Email,
		},
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "passkey unavailable")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	if !h.authorize(w, r, principal, "auth.credentials", "update") {
		return
	}
	var input struct {
		SessionData string `json:"session_data"`
		Credential  string `json:"credential"`
		Label       string `json:"label"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	out, err := h.options.StepInvoker.InvokeStep(r.Context(), StepCall{
		StepType: "step.auth_passkey_finish_register",
		Input: map[string]any{
			"user_id":      principal.UserID,
			"email":        principal.Email,
			"session_data": input.SessionData,
			"credential":   input.Credential,
		},
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "passkey unavailable")
		return
	}
	if out["valid"] != true {
		writeJSON(w, http.StatusBadRequest, map[string]any{"valid": false, "error": "invalid_passkey"})
		return
	}
	credential, err := h.options.CredentialStore.AddPasskeyCredential(r.Context(), principal.UserID, AddPasskeyCredentialInput{
		CredentialID:   stringFromAny(out["credential_id"]),
		CredentialJSON: stringFromAny(out["credential"]),
		PublicKey:      stringFromAny(out["public_key"]),
		Label:          input.Label,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"valid": true, "credential": credential})
}

func (h *handler) totpBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	if !h.authorize(w, r, principal, "auth.credentials", "update") {
		return
	}
	out, err := h.options.StepInvoker.InvokeStep(r.Context(), StepCall{
		StepType: "step.auth_totp_generate_secret",
		Input: map[string]any{
			"email": principal.Email,
		},
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "totp unavailable")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *handler) totpVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	principal, ok := h.principal(w, r)
	if !ok {
		return
	}
	if !h.authorize(w, r, principal, "auth.credentials", "update") {
		return
	}
	var input struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
		Label  string `json:"label"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	out, err := h.options.StepInvoker.InvokeStep(r.Context(), StepCall{
		StepType: "step.auth_totp_verify",
		Input: map[string]any{
			"secret": input.Secret,
			"code":   input.Code,
		},
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "totp unavailable")
		return
	}
	if out["valid"] != true {
		writeJSON(w, http.StatusBadRequest, map[string]any{"valid": false, "error": "invalid_code"})
		return
	}
	credential, err := h.options.CredentialStore.AddTOTPCredential(r.Context(), principal.UserID, AddTOTPCredentialInput{
		Secret: input.Secret,
		Label:  input.Label,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"valid": true, "credential": credential})
}

func (h *handler) setupRedeem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	var input struct {
		Code  string `json:"code"`
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	setup, err := h.options.SetupCodeStore.RedeemSetupCode(r.Context(), input.Code, normalizeEmail(input.Email))
	if err != nil {
		switch {
		case errors.Is(err, ErrSetupCodeNotFound):
			writeError(w, http.StatusNotFound, ErrSetupCodeNotFound.Error())
		case errors.Is(err, ErrSetupCodeWrongEmail):
			writeError(w, http.StatusForbidden, ErrSetupCodeWrongEmail.Error())
		case errors.Is(err, ErrSetupCodeExpired):
			writeError(w, http.StatusGone, ErrSetupCodeExpired.Error())
		default:
			writeError(w, http.StatusInternalServerError, "setup code unavailable")
		}
		return
	}
	if h.options.SessionIssuer == nil {
		writeJSON(w, http.StatusOK, map[string]any{"redeemed": true, "user_id": setup.UserID})
		return
	}
	session, err := h.options.SessionIssuer.IssueSession(r.Context(), SessionRequest{
		UserID:    setup.UserID,
		Email:     setup.Email,
		Role:      setup.Role,
		TenantIDs: setup.TenantIDs,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"redeemed": true, "user_id": setup.UserID, "session": session})
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, "POST")
		return
	}
	writeError(w, http.StatusNotImplemented, "logout requires host handler")
}

func (h *handler) principal(w http.ResponseWriter, r *http.Request) (Principal, bool) {
	principal, ok := h.options.PrincipalResolver.CurrentPrincipal(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return Principal{}, false
	}
	return principal, true
}

func (h *handler) authorize(w http.ResponseWriter, r *http.Request, principal Principal, resource, action string) bool {
	if h.options.Authorizer == nil {
		return true
	}
	if err := h.options.Authorizer.Authorize(r.Context(), principal, resource, action); err != nil {
		writeError(w, http.StatusForbidden, "forbidden")
		return false
	}
	return true
}

func cleanPath(value string) string {
	clean := path.Clean("/" + strings.Trim(strings.TrimSpace(value), "/"))
	if strings.HasSuffix(value, "/") && clean != "/" {
		return clean + "/"
	}
	return clean
}

func setupURL(options Options, code string) string {
	code = strings.TrimSpace(code)
	if code == "" {
		return ""
	}
	return options.SetupLoginPath + "?setup_code=" + url.QueryEscape(code)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func decodeJSON(r *http.Request, out any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(out)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	noStore(w)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": message})
}

func normalizeEmail(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func stringFromAny(value any) string {
	switch v := value.(type) {
	case string:
		return v
	default:
		return ""
	}
}
