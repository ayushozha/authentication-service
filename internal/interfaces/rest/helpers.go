package rest

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/Ayush10/authentication-service/internal/application"
)

const refreshCookieName = "auth_refresh"

type errorPayload struct {
	Error       string `json:"error"`
	Code        string `json:"code"`
	Message     string `json:"message"`
	AuthCode    string `json:"auth_code,omitempty"`
	UserMessage string `json:"user_message,omitempty"`
	Retryable   bool   `json:"retryable"`
	RequestID   string `json:"request_id,omitempty"`
}

type authErrorDefinition struct {
	UserMessage string
	Retryable   bool
}

var authErrorDefinitions = map[string]authErrorDefinition{
	"AUTH_INVALID_REQUEST":            {UserMessage: "We could not process that request. Try again."},
	"AUTH_EMAIL_REQUIRED":             {UserMessage: "Enter your email address."},
	"AUTH_PASSWORD_REQUIRED":          {UserMessage: "Enter your password."},
	"AUTH_EMAIL_PASSWORD_REQUIRED":    {UserMessage: "Enter your email and password."},
	"AUTH_INVALID_EMAIL":              {UserMessage: "Enter a valid email address."},
	"AUTH_PASSWORD_TOO_SHORT":         {UserMessage: "Use at least 8 characters for your password."},
	"AUTH_INVALID_CREDENTIALS":        {UserMessage: "The email or password is incorrect."},
	"AUTH_ACCOUNT_LOCKED":             {UserMessage: "This account is locked. Check your email for next steps."},
	"AUTH_ACCOUNT_DISABLED":           {UserMessage: "This account cannot sign in right now."},
	"AUTH_RATE_LIMITED":               {UserMessage: "Too many attempts. Try again in a few minutes.", Retryable: true},
	"AUTH_SESSION_EXPIRED":            {UserMessage: "Your session expired. Sign in again."},
	"AUTH_TOKEN_MISSING":              {UserMessage: "Sign in again to continue."},
	"AUTH_TOKEN_REVOKED":              {UserMessage: "Your session is no longer active. Sign in again."},
	"AUTH_STORAGE_UNAVAILABLE":        {UserMessage: "Secure storage is unavailable on this device."},
	"AUTH_STORAGE_WRITE_FAILED":       {UserMessage: "We could not save your sign-in securely. Try again.", Retryable: true},
	"AUTH_NETWORK_UNAVAILABLE":        {UserMessage: "Check your connection and try again.", Retryable: true},
	"AUTH_SERVICE_UNAVAILABLE":        {UserMessage: "We could not sign you in right now. Try again later.", Retryable: true},
	"AUTH_OAUTH_FAILED":               {UserMessage: "We could not complete sign-in with that provider.", Retryable: true},
	"AUTH_OAUTH_CANCELLED":            {UserMessage: "Sign-in was cancelled."},
	"AUTH_OAUTH_STATE_MISMATCH":       {UserMessage: "We could not verify that sign-in. Try again."},
	"AUTH_OAUTH_PROVIDER_UNAVAILABLE": {UserMessage: "That sign-in provider is unavailable. Try again later.", Retryable: true},
	"AUTH_SSO_FAILED":                 {UserMessage: "We could not complete single sign-on. Try again.", Retryable: true},
	"AUTH_PASSKEY_FAILED":             {UserMessage: "We could not complete passkey sign-in. Try again.", Retryable: true},
	"AUTH_PASSKEY_CANCELLED":          {UserMessage: "Passkey sign-in was cancelled."},
	"AUTH_BIOMETRIC_UNAVAILABLE":      {UserMessage: "Biometric unlock is unavailable on this device."},
	"AUTH_BIOMETRIC_CANCELLED":        {UserMessage: "Biometric unlock was cancelled."},
	"AUTH_BIOMETRIC_LOCKOUT":          {UserMessage: "Biometric unlock is locked. Use your device passcode."},
	"AUTH_MFA_REQUIRED":               {UserMessage: "Enter the code from your authenticator app."},
	"AUTH_MFA_CODE_INVALID":           {UserMessage: "That code is incorrect. Try again."},
	"AUTH_MFA_CODE_EXPIRED":           {UserMessage: "That code expired. Request a new one.", Retryable: true},
	"AUTH_MFA_RECOVERY_CODE_INVALID":  {UserMessage: "That recovery code is incorrect."},
	"AUTH_MFA_PUSH_TIMEOUT":           {UserMessage: "The approval request timed out. Try again.", Retryable: true},
	"AUTH_MFA_SMS_UNAVAILABLE":        {UserMessage: "SMS codes are unavailable right now. Try another method.", Retryable: true},
	"AUTH_UNKNOWN":                    {UserMessage: "Something went wrong. Try again.", Retryable: true},
}

var (
	authLogEmailPattern    = regexp.MustCompile(`(?i)[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}`)
	authLogJWTLikePattern  = regexp.MustCompile(`\b(?:Bearer\s+)?[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
	authLogSixDigitPattern = regexp.MustCompile(`\b\d{6}\b`)
)

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(payload)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	if message == "" {
		message = code
	}
	authCode, definition := normalizeAuthError(status, code, message)
	payload := errorPayload{
		Error:       message,
		Code:        code,
		Message:     message,
		AuthCode:    authCode,
		UserMessage: definition.UserMessage,
		Retryable:   definition.Retryable,
	}
	if r != nil {
		payload.RequestID = redactAuthLogString(r.Header.Get("X-Request-ID"))
	}
	logAuthError(r, status, payload)
	writeJSON(w, status, payload)
}

func normalizeAuthError(status int, code, message string) (string, authErrorDefinition) {
	authCode := canonicalAuthCode(status, code, message)
	definition, ok := authErrorDefinitions[authCode]
	if !ok {
		authCode = "AUTH_UNKNOWN"
		definition = authErrorDefinitions[authCode]
	}
	return authCode, definition
}

func canonicalAuthCode(status int, code, message string) string {
	trimmedCode := strings.TrimSpace(code)
	if strings.HasPrefix(strings.ToUpper(trimmedCode), "AUTH_") {
		return strings.ToUpper(trimmedCode)
	}

	switch normalizeLegacyErrorCode(trimmedCode) {
	case "invalid_request", "invalid_request_body", "invalid_json", "malformed_body", "method_not_allowed", "origin_not_allowed",
		"token_is_required", "code_is_required", "session_id_required", "passkey_id_required", "token_and_code_are_required", "token_and_new_password_are_required":
		return "AUTH_INVALID_REQUEST"
	case "email_required", "email_is_required":
		return "AUTH_EMAIL_REQUIRED"
	case "password_required", "password_is_required":
		return "AUTH_PASSWORD_REQUIRED"
	case "email_and_password_required":
		return "AUTH_EMAIL_PASSWORD_REQUIRED"
	case "invalid_email":
		return "AUTH_INVALID_EMAIL"
	case "weak_password", "password_too_short":
		return "AUTH_PASSWORD_TOO_SHORT"
	case "invalid_credentials", "wrong_password", "user_not_found":
		return "AUTH_INVALID_CREDENTIALS"
	case "account_locked":
		return "AUTH_ACCOUNT_LOCKED"
	case "account_suspended", "account_disabled", "user_disabled", "security_policy_blocked":
		return "AUTH_ACCOUNT_DISABLED"
	case "rate_limited", "too_many_requests":
		return "AUTH_RATE_LIMITED"
	case "missing_authorization_header", "missing_token", "token_missing", "refresh_token_missing", "invalid_authorization_format", "unauthorized":
		return "AUTH_TOKEN_MISSING"
	case "invalid_access_token", "invalid_or_expired_token", "token_client_mismatch":
		return "AUTH_SESSION_EXPIRED"
	case "invalid_refresh_token", "refresh_token_revoked", "token_revoked":
		return "AUTH_TOKEN_REVOKED"
	case "missing_api_key", "invalid_api_key", "missing_client", "missing_client_context", "invalid_client", "client_suspended",
		"redis_required", "email_not_configured", "internal_error", "service_unavailable", "redirect_code_unavailable":
		return "AUTH_SERVICE_UNAVAILABLE"
	case "network_error", "timeout":
		return "AUTH_NETWORK_UNAVAILABLE"
	case "oauth_failed", "oauth_error", "exchange_failed", "userinfo_failed", "read_failed", "parse_failed", "create_failed":
		return "AUTH_OAUTH_FAILED"
	case "access_denied", "oauth_cancelled":
		return "AUTH_OAUTH_CANCELLED"
	case "invalid_state", "oauth_state_mismatch":
		return "AUTH_OAUTH_STATE_MISMATCH"
	case "oauth_provider_unavailable", "oauth_requires_redis":
		return "AUTH_OAUTH_PROVIDER_UNAVAILABLE"
	case "sso_required", "sso_failed", "invalid_sso_connection":
		return "AUTH_SSO_FAILED"
	case "passkey_failed", "webauthn_failed", "authentication_failed", "registration_failed", "no_registration_in_progress", "no_login_in_progress", "passkey_attestation_rejected":
		return "AUTH_PASSKEY_FAILED"
	case "passkey_cancelled":
		return "AUTH_PASSKEY_CANCELLED"
	case "requires_2fa", "totp_required", "mfa_required":
		return "AUTH_MFA_REQUIRED"
	case "invalid_totp", "totp_invalid", "invalid_code", "mfa_code_invalid":
		return "AUTH_MFA_CODE_INVALID"
	case "otp_expired", "mfa_code_expired", "invalid_or_expired_2fa_token":
		return "AUTH_MFA_CODE_EXPIRED"
	case "invalid_recovery_code", "recovery_code_invalid":
		return "AUTH_MFA_RECOVERY_CODE_INVALID"
	case "mfa_push_timeout":
		return "AUTH_MFA_PUSH_TIMEOUT"
	case "sms_unavailable":
		return "AUTH_MFA_SMS_UNAVAILABLE"
	}

	lowerMessage := strings.ToLower(strings.TrimSpace(message))
	switch {
	case strings.Contains(lowerMessage, "invalid email or password"):
		return "AUTH_INVALID_CREDENTIALS"
	case strings.Contains(lowerMessage, "invalid email"):
		return "AUTH_INVALID_EMAIL"
	case strings.Contains(lowerMessage, "password") && strings.Contains(lowerMessage, "required"):
		return "AUTH_PASSWORD_REQUIRED"
	case strings.Contains(lowerMessage, "at least 8") || strings.Contains(lowerMessage, "password does not meet"):
		return "AUTH_PASSWORD_TOO_SHORT"
	case strings.Contains(lowerMessage, "too many") || strings.Contains(lowerMessage, "rate"):
		return "AUTH_RATE_LIMITED"
	case strings.Contains(lowerMessage, "redis") || strings.Contains(lowerMessage, "not configured"):
		return "AUTH_SERVICE_UNAVAILABLE"
	case strings.Contains(lowerMessage, "passkey") || strings.Contains(lowerMessage, "webauthn"):
		return "AUTH_PASSKEY_FAILED"
	case strings.Contains(lowerMessage, "totp") || strings.Contains(lowerMessage, "2fa") || strings.Contains(lowerMessage, "mfa"):
		return "AUTH_MFA_REQUIRED"
	}

	if status == http.StatusTooManyRequests {
		return "AUTH_RATE_LIMITED"
	}
	if status == http.StatusUnauthorized {
		return "AUTH_SESSION_EXPIRED"
	}
	if status >= http.StatusInternalServerError {
		return "AUTH_SERVICE_UNAVAILABLE"
	}
	return "AUTH_UNKNOWN"
}

func normalizeLegacyErrorCode(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return value
}

func logAuthError(r *http.Request, status int, payload errorPayload) {
	entry := map[string]interface{}{
		"event":         "auth.error",
		"platform":      "auth-service",
		"app":           "auth-service",
		"component":     "",
		"operation":     authOperationForPath(r),
		"code":          payload.AuthCode,
		"provider_code": payload.Code,
		"status":        status,
		"retryable":     payload.Retryable,
	}
	if r != nil {
		entry["component"] = r.URL.Path
		entry["method"] = r.Method
		if payload.RequestID != "" {
			entry["request_id"] = payload.RequestID
		}
		if strings.TrimSpace(r.UserAgent()) != "" {
			entry["device"] = map[string]string{"user_agent": "[REDACTED_USER_AGENT]"}
		}
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return
	}
	log.Print(string(encoded))
}

func authOperationForPath(r *http.Request) string {
	if r == nil {
		return "unknown"
	}
	path := r.URL.Path
	switch {
	case strings.Contains(path, "/login"):
		return "login"
	case strings.Contains(path, "/signup"):
		return "signup"
	case strings.Contains(path, "/refresh"):
		return "refresh"
	case strings.Contains(path, "/forgot-password"), strings.Contains(path, "/reset-password"):
		return "password_reset"
	case strings.Contains(path, "/oauth"):
		return "oauth"
	case strings.Contains(path, "/totp"), strings.Contains(path, "/recovery-codes"):
		return "mfa"
	case strings.Contains(path, "/passkey"):
		return "passkey"
	case strings.Contains(path, "/me"), strings.Contains(path, "/sessions"):
		return "session"
	default:
		return "unknown"
	}
}

func redactAuthLogString(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = authLogEmailPattern.ReplaceAllString(value, "[REDACTED_EMAIL]")
	value = authLogJWTLikePattern.ReplaceAllString(value, "[REDACTED_TOKEN]")
	value = authLogSixDigitPattern.ReplaceAllString(value, "[REDACTED_CODE]")
	if len(value) > 128 {
		value = value[:128]
	}
	return value
}

func redirectWithLoginAuthError(w http.ResponseWriter, r *http.Request, cfg *HandlerConfig, authCode string) {
	if authCode == "" {
		authCode = "AUTH_UNKNOWN"
	}
	baseURL := ""
	if cfg != nil {
		baseURL = strings.TrimRight(cfg.BaseURL, "/")
	}
	http.Redirect(w, r, baseURL+"/login.html?error="+url.QueryEscape(authCode), http.StatusFound)
}

// clientIP extracts the caller's IP. Currently trusts X-Forwarded-For
// unconditionally for backwards compatibility — note the audit-flagged
// spoofing risk in docs/security/known-issues.md. The fix (trusting XFF
// only from configured proxy IPs) needs paired test updates and a
// TRUSTED_PROXY_IPS env-var contract; landing in a follow-up.
func clientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func setCorsHeaders(w http.ResponseWriter, origin string, allowCredentials bool) {
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Admin-Key, X-Request-ID, X-Step-Up-Token")
	if allowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}
}

func isTokenSessionMode(r *http.Request, requestedMode string) bool {
	mode := strings.ToLower(strings.TrimSpace(requestedMode))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("session_mode")))
	}
	return mode == "token"
}

func tokenTransport(r *http.Request, requestedTransport, requestedSessionMode string) string {
	transport := strings.ToLower(strings.TrimSpace(requestedTransport))
	if transport == "" && r != nil {
		transport = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("token_transport")))
	}
	switch transport {
	case "json", "cookie":
		return transport
	}
	if isTokenSessionMode(r, requestedSessionMode) {
		return "json"
	}
	return "cookie"
}

func isJSONTokenTransport(r *http.Request, requestedTransport, requestedSessionMode string) bool {
	return tokenTransport(r, requestedTransport, requestedSessionMode) == "json"
}

func applyRefreshTransport(w http.ResponseWriter, cfg *HandlerConfig, resp *application.AuthResponse, refreshToken, transport string) {
	if cfg == nil || resp == nil || refreshToken == "" {
		return
	}
	expiresIn := int(cfg.RefreshTTL.Seconds())
	if transport == "json" {
		resp.RefreshToken = refreshToken
		resp.Refresh = &application.RefreshInfo{Transport: "json", ExpiresIn: expiresIn}
		return
	}
	SetRefreshCookie(w, refreshToken, cfg.RefreshTTL, cfg)
	resp.Refresh = &application.RefreshInfo{Transport: "cookie", CookieName: refreshCookieName, ExpiresIn: expiresIn}
}
