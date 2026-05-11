package com.authservice.sdk;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public final class AuthServiceClient {
    private final String baseUrl;
    private final String apiKey;
    private final String sessionMode;
    private final TokenStore tokenStore;

    public AuthServiceClient(String baseUrl, String apiKey) {
        this(baseUrl, apiKey, "token", new MemoryTokenStore());
    }

    public AuthServiceClient(String baseUrl, String apiKey, String sessionMode, TokenStore tokenStore) {
        this.baseUrl = trimRightSlash(baseUrl);
        this.apiKey = apiKey;
        this.sessionMode = sessionMode == null || sessionMode.isEmpty() ? "token" : sessionMode;
        this.tokenStore = tokenStore == null ? new MemoryTokenStore() : tokenStore;
    }

    public AuthServiceResponse signup(String email, String password, String displayName) throws IOException {
        String body = jsonObject(
                "email", email,
                "password", password,
                "display_name", displayName,
                "session_mode", sessionMode,
                "token_transport", tokenTransport()
        );
        AuthServiceResponse response = request("POST", "/api/auth/signup", body, false);
        persist(response);
        return response;
    }

    public AuthServiceResponse login(String email, String password) throws IOException {
        String body = jsonObject(
                "email", email,
                "password", password,
                "session_mode", sessionMode,
                "token_transport", tokenTransport()
        );
        AuthServiceResponse response = request("POST", "/api/auth/login", body, false);
        persist(response);
        return response;
    }

    public AuthServiceResponse refresh() throws IOException {
        String body = jsonObject(
                "refresh_token", tokenStore.getRefreshToken(),
                "session_mode", sessionMode,
                "token_transport", tokenTransport()
        );
        AuthServiceResponse response = request("POST", "/api/auth/refresh", body, false);
        persist(response);
        return response;
    }

    public AuthServiceResponse logout() throws IOException {
        AuthServiceResponse response = request("POST", "/api/auth/logout", jsonObject("refresh_token", tokenStore.getRefreshToken()), false);
        tokenStore.setAccessToken(null);
        tokenStore.setRefreshToken(null);
        return response;
    }

    public AuthServiceResponse forgotPassword(String email) throws IOException {
        return request("POST", "/api/auth/forgot-password", jsonObject("email", email), false);
    }

    public AuthServiceResponse resetPassword(String token, String newPassword) throws IOException {
        return request("POST", "/api/auth/reset-password", jsonObject("token", token, "new_password", newPassword), false);
    }

    public AuthServiceResponse verifyEmail(String token) throws IOException {
        return request("POST", "/api/auth/verify-email", jsonObject("token", token), false);
    }

    public AuthServiceResponse resendVerification() throws IOException {
        return request("POST", "/api/auth/resend-verification", "{}", true);
    }

    public AuthServiceResponse setupTOTP() throws IOException {
        return request("POST", "/api/auth/totp/setup", "{}", true);
    }

    public AuthServiceResponse enableTOTP(String code) throws IOException {
        return request("POST", "/api/auth/totp/enable", jsonObject("code", code), true);
    }

    public AuthServiceResponse disableTOTP(String code) throws IOException {
        return request("POST", "/api/auth/totp/disable", jsonObject("code", code), true);
    }

    public AuthServiceResponse verifyTOTP(String twoFactorToken, String code) throws IOException {
        return verifyTOTP(twoFactorToken, code, false, null);
    }

    public AuthServiceResponse verifyTOTP(String twoFactorToken, String code, boolean rememberDevice, String deviceName) throws IOException {
        String body = jsonObject(
                "two_factor_token", twoFactorToken,
                "code", code,
                "session_mode", sessionMode,
                "token_transport", tokenTransport(),
                "remember_device", rememberDevice,
                "device_name", deviceName
        );
        AuthServiceResponse response = request("POST", "/api/auth/totp/verify", body, false);
        persist(response);
        return response;
    }

    public AuthServiceResponse verifyRecoveryCode(String twoFactorToken, String code) throws IOException {
        return verifyRecoveryCode(twoFactorToken, code, false, null);
    }

    public AuthServiceResponse verifyRecoveryCode(String twoFactorToken, String code, boolean rememberDevice, String deviceName) throws IOException {
        String body = jsonObject(
                "two_factor_token", twoFactorToken,
                "code", code,
                "session_mode", sessionMode,
                "token_transport", tokenTransport(),
                "remember_device", rememberDevice,
                "device_name", deviceName
        );
        AuthServiceResponse response = request("POST", "/api/auth/recovery-codes/verify", body, false);
        persist(response);
        return response;
    }

    public AuthServiceResponse recoveryCodeCount() throws IOException {
        return request("GET", "/api/auth/recovery-codes", null, true);
    }

    public AuthServiceResponse generateRecoveryCodes() throws IOException {
        return request("POST", "/api/auth/recovery-codes", "{}", true);
    }

    public AuthServiceResponse beginPasskeyRegistration() throws IOException {
        return request("POST", "/api/auth/passkey/register/begin", "{}", true);
    }

    public AuthServiceResponse finishPasskeyRegistration(String credentialJson, String friendlyName) throws IOException {
        return request(
                "POST",
                "/api/auth/passkey/register/finish" + queryString("name", friendlyName),
                credentialJson,
                true
        );
    }

    public AuthServiceResponse beginPasskeyLogin() throws IOException {
        return request("POST", "/api/auth/passkey/login/begin", "{}", false);
    }

    public AuthServiceResponse finishPasskeyLogin(String sessionId, String credentialJson) throws IOException {
        AuthServiceResponse response = request(
                "POST",
                "/api/auth/passkey/login/finish" + queryString(
                        "session_id", sessionId,
                        "session_mode", "token".equals(sessionMode) ? "token" : null,
                        "token_transport", tokenTransport()
                ),
                credentialJson,
                false
        );
        persist(response);
        return response;
    }

    public AuthServiceResponse listPasskeys() throws IOException {
        return request("GET", "/api/auth/passkeys", null, true);
    }

    public AuthServiceResponse deletePasskey(String id) throws IOException {
        return request("DELETE", "/api/auth/passkeys/" + urlPath(id), null, true);
    }

    public AuthServiceResponse me() throws IOException {
        return request("GET", "/api/auth/me", null, true);
    }

    public AuthServiceResponse updateProfile(String displayName, String timezone) throws IOException {
        return request("PATCH", "/api/auth/me", jsonObject("display_name", displayName, "timezone", timezone), true);
    }

    public AuthServiceResponse createOrganization(String name, String slug) throws IOException {
        return request("POST", "/api/auth/organizations", jsonObject("name", name, "slug", slug), true);
    }

    public AuthServiceResponse listOrganizations() throws IOException {
        return request("GET", "/api/auth/organizations", null, true);
    }

    public AuthServiceResponse createOrganizationToken(String organizationId, boolean activate) throws IOException {
        AuthServiceResponse response = request("POST", "/api/auth/organizations/" + urlPath(organizationId) + "/token", "{}", true);
        if (activate && response.getAccessToken() != null) {
            tokenStore.setAccessToken(response.getAccessToken());
        }
        return response;
    }

    public String getAccessToken() {
        return tokenStore.getAccessToken();
    }

    public String getRefreshToken() {
        return tokenStore.getRefreshToken();
    }

    public void clearSession() {
        tokenStore.setAccessToken(null);
        tokenStore.setRefreshToken(null);
    }

    private AuthServiceResponse request(String method, String path, String body, boolean authorized) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL(baseUrl + path).openConnection();
        connection.setRequestMethod(method);
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty("X-API-Key", apiKey);
        if (authorized && tokenStore.getAccessToken() != null) {
            connection.setRequestProperty("Authorization", "Bearer " + tokenStore.getAccessToken());
        }
        if (body != null) {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Content-Length", String.valueOf(bytes.length));
            try (OutputStream out = connection.getOutputStream()) {
                out.write(bytes);
            }
        }

        int status = connection.getResponseCode();
        InputStream stream = status >= 200 && status < 400 ? connection.getInputStream() : connection.getErrorStream();
        String responseBody = readAll(stream);
        AuthServiceResponse response = new AuthServiceResponse(status, responseBody);
        if (status < 200 || status >= 300) {
            throw new AuthServiceException(status, response.getUserMessage(), responseBody, response.getAuthCode(), response.isRetryable());
        }
        return response;
    }

    private void persist(AuthServiceResponse response) {
        if (response.getAccessToken() != null) tokenStore.setAccessToken(response.getAccessToken());
        if (response.getRefreshToken() != null) tokenStore.setRefreshToken(response.getRefreshToken());
    }

    private String tokenTransport() {
        return "token".equals(sessionMode) ? "json" : "cookie";
    }

    private static String trimRightSlash(String value) {
        if (value == null) return "";
        while (value.endsWith("/")) value = value.substring(0, value.length() - 1);
        return value;
    }

    private static String urlPath(String value) {
        if (value == null) return "";
        return urlEncode(value).replace("+", "%20");
    }

    private static String queryString(Object... pairs) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            Object value = pairs[i + 1];
            if (value == null) continue;
            String stringValue = String.valueOf(value);
            if (stringValue.isEmpty()) continue;
            builder.append(builder.length() == 0 ? '?' : '&');
            builder.append(urlEncode(String.valueOf(pairs[i])));
            builder.append('=');
            builder.append(urlEncode(stringValue));
        }
        return builder.toString();
    }

    private static String urlEncode(String value) {
        try {
            return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException impossible) {
            throw new IllegalStateException("UTF-8 is not available", impossible);
        }
    }

    private static String readAll(InputStream stream) throws IOException {
        if (stream == null) return "";
        StringBuilder builder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) builder.append(line);
        }
        return builder.toString();
    }

    private static String jsonObject(Object... pairs) {
        StringBuilder builder = new StringBuilder("{");
        boolean wrote = false;
        for (int i = 0; i + 1 < pairs.length; i += 2) {
            Object value = pairs[i + 1];
            if (value == null) continue;
            if (wrote) builder.append(',');
            builder.append('"').append(escape(String.valueOf(pairs[i]))).append('"').append(':');
            appendJsonValue(builder, value);
            wrote = true;
        }
        return builder.append('}').toString();
    }

    private static void appendJsonValue(StringBuilder builder, Object value) {
        if (value instanceof Boolean || value instanceof Number) {
            builder.append(value);
            return;
        }
        builder.append('"').append(escape(String.valueOf(value))).append('"');
    }

    private static String escape(String value) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    builder.append("\\\"");
                    break;
                case '\\':
                    builder.append("\\\\");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    builder.append(c);
            }
        }
        return builder.toString();
    }

    private static String extractJsonString(String json, String key) {
        if (json == null || json.isEmpty()) return null;
        String marker = "\"" + key + "\":";
        int start = json.indexOf(marker);
        if (start < 0) return null;
        start += marker.length();
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        if (start >= json.length() || json.charAt(start) != '"') return null;
        start++;
        StringBuilder value = new StringBuilder();
        boolean escaped = false;
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escaped) {
                value.append(c);
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '"') return value.toString();
            value.append(c);
        }
        return null;
    }

    private static Boolean extractJsonBoolean(String json, String key) {
        if (json == null || json.isEmpty()) return null;
        String marker = "\"" + key + "\":";
        int start = json.indexOf(marker);
        if (start < 0) return null;
        start += marker.length();
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) start++;
        if (json.startsWith("true", start)) return true;
        if (json.startsWith("false", start)) return false;
        return null;
    }

    private static String truncate(String value, int maxLength) {
        if (value.length() <= maxLength) return value;
        return value.substring(0, maxLength);
    }

    public interface TokenStore {
        String getAccessToken();
        void setAccessToken(String token);
        String getRefreshToken();
        void setRefreshToken(String token);
    }

    public static final class MemoryTokenStore implements TokenStore {
        private String accessToken;
        private String refreshToken;

        public String getAccessToken() {
            return accessToken;
        }

        public void setAccessToken(String token) {
            this.accessToken = token;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public void setRefreshToken(String token) {
            this.refreshToken = token;
        }
    }

    public static final class AuthServiceResponse {
        private final int statusCode;
        private final String body;

        AuthServiceResponse(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body == null ? "" : body;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getBody() {
            return body;
        }

        public boolean isSuccessful() {
            return statusCode >= 200 && statusCode < 300;
        }

        public String getAccessToken() {
            return extractJsonString(body, "access_token");
        }

        public String getRefreshToken() {
            return extractJsonString(body, "refresh_token");
        }

        public boolean requires2FA() {
            Boolean value = extractJsonBoolean(body, "requires_2fa");
            return value != null && value;
        }

        public String getTwoFactorToken() {
            return extractJsonString(body, "two_factor_token");
        }

        public String getError() {
            String error = extractJsonString(body, "error");
            if (error != null && !error.isEmpty()) return error;
            String message = extractJsonString(body, "message");
            if (message != null && !message.isEmpty()) return message;
            String fallback = body.trim();
            return fallback.isEmpty() ? "AuthService request failed" : truncate(fallback, 200);
        }

        public String getAuthCode() {
            String authCode = extractJsonString(body, "auth_code");
            if (authCode != null && !authCode.isEmpty()) return authCode;
            String code = extractJsonString(body, "code");
            if (code == null || code.isEmpty()) code = extractJsonString(body, "error");
            return authCodeFor(code, getError(), statusCode);
        }

        public String getUserMessage() {
            String message = extractJsonString(body, "user_message");
            if (message != null && !message.isEmpty()) return message;
            return userMessageForAuthCode(getAuthCode());
        }

        public boolean isRetryable() {
            Boolean retryable = extractJsonBoolean(body, "retryable");
            return retryable != null ? retryable : retryableForAuthCode(getAuthCode());
        }
    }

    public static final class AuthServiceException extends IOException {
        private final int statusCode;
        private final String responseBody;
        private final String authCode;
        private final boolean retryable;

        AuthServiceException(int statusCode, String message, String responseBody) {
            this(statusCode, message, responseBody, authCodeFor(null, message, statusCode), retryableForAuthCode(authCodeFor(null, message, statusCode)));
        }

        AuthServiceException(int statusCode, String message, String responseBody, String authCode, boolean retryable) {
            super(message);
            this.statusCode = statusCode;
            this.responseBody = responseBody;
            this.authCode = authCode;
            this.retryable = retryable;
        }

        public int getStatusCode() {
            return statusCode;
        }

        public String getResponseBody() {
            return responseBody;
        }

        public String getAuthCode() {
            return authCode;
        }

        public boolean isRetryable() {
            return retryable;
        }
    }

    private static String authCodeFor(String providerCode, String message, int statusCode) {
        String normalized = providerCode == null ? "" : providerCode.trim().toLowerCase().replace('-', '_').replace(' ', '_');
        switch (normalized) {
            case "invalid_request":
            case "invalid_request_body":
                return "AUTH_INVALID_REQUEST";
            case "email_required":
                return "AUTH_EMAIL_REQUIRED";
            case "invalid_email":
                return "AUTH_INVALID_EMAIL";
            case "weak_password":
            case "password_too_short":
                return "AUTH_PASSWORD_TOO_SHORT";
            case "invalid_credentials":
            case "user_not_found":
                return "AUTH_INVALID_CREDENTIALS";
            case "account_locked":
                return "AUTH_ACCOUNT_LOCKED";
            case "account_suspended":
            case "account_disabled":
                return "AUTH_ACCOUNT_DISABLED";
            case "rate_limited":
                return "AUTH_RATE_LIMITED";
            case "refresh_token_missing":
            case "missing_authorization_header":
                return "AUTH_TOKEN_MISSING";
            case "invalid_access_token":
                return "AUTH_SESSION_EXPIRED";
            case "invalid_refresh_token":
                return "AUTH_TOKEN_REVOKED";
            case "missing_api_key":
            case "invalid_api_key":
            case "redis_required":
            case "email_not_configured":
            case "internal_error":
                return "AUTH_SERVICE_UNAVAILABLE";
            case "oauth_failed":
                return "AUTH_OAUTH_FAILED";
            case "access_denied":
                return "AUTH_OAUTH_CANCELLED";
            case "invalid_state":
                return "AUTH_OAUTH_STATE_MISMATCH";
            case "oauth_provider_unavailable":
                return "AUTH_OAUTH_PROVIDER_UNAVAILABLE";
            case "sso_required":
                return "AUTH_SSO_FAILED";
            case "passkey_failed":
            case "authentication_failed":
                return "AUTH_PASSKEY_FAILED";
            case "invalid_totp":
            case "invalid_code":
                return "AUTH_MFA_CODE_INVALID";
            case "invalid_recovery_code":
                return "AUTH_MFA_RECOVERY_CODE_INVALID";
            default:
                String lower = message == null ? "" : message.toLowerCase();
                if (lower.contains("invalid email or password")) return "AUTH_INVALID_CREDENTIALS";
                if (lower.contains("too many") || lower.contains("rate")) return "AUTH_RATE_LIMITED";
                if (statusCode == 429) return "AUTH_RATE_LIMITED";
                if (statusCode == 401) return "AUTH_SESSION_EXPIRED";
                if (statusCode >= 500) return "AUTH_SERVICE_UNAVAILABLE";
                return "AUTH_UNKNOWN";
        }
    }

    private static String userMessageForAuthCode(String authCode) {
        switch (authCode) {
            case "AUTH_INVALID_REQUEST": return "We could not process that request. Try again.";
            case "AUTH_EMAIL_REQUIRED": return "Enter your email address.";
            case "AUTH_PASSWORD_REQUIRED": return "Enter your password.";
            case "AUTH_EMAIL_PASSWORD_REQUIRED": return "Enter your email and password.";
            case "AUTH_INVALID_EMAIL": return "Enter a valid email address.";
            case "AUTH_PASSWORD_TOO_SHORT": return "Use at least 8 characters for your password.";
            case "AUTH_INVALID_CREDENTIALS": return "The email or password is incorrect.";
            case "AUTH_ACCOUNT_LOCKED": return "This account is locked. Check your email for next steps.";
            case "AUTH_ACCOUNT_DISABLED": return "This account cannot sign in right now.";
            case "AUTH_RATE_LIMITED": return "Too many attempts. Try again in a few minutes.";
            case "AUTH_SESSION_EXPIRED": return "Your session expired. Sign in again.";
            case "AUTH_TOKEN_MISSING": return "Sign in again to continue.";
            case "AUTH_TOKEN_REVOKED": return "Your session is no longer active. Sign in again.";
            case "AUTH_SERVICE_UNAVAILABLE": return "We could not sign you in right now. Try again later.";
            case "AUTH_OAUTH_FAILED": return "We could not complete sign-in with that provider.";
            case "AUTH_OAUTH_CANCELLED": return "Sign-in was cancelled.";
            case "AUTH_OAUTH_STATE_MISMATCH": return "We could not verify that sign-in. Try again.";
            case "AUTH_OAUTH_PROVIDER_UNAVAILABLE": return "That sign-in provider is unavailable. Try again later.";
            case "AUTH_SSO_FAILED": return "We could not complete single sign-on. Try again.";
            case "AUTH_PASSKEY_FAILED": return "We could not complete passkey sign-in. Try again.";
            case "AUTH_PASSKEY_CANCELLED": return "Passkey sign-in was cancelled.";
            case "AUTH_MFA_REQUIRED": return "Enter the code from your authenticator app.";
            case "AUTH_MFA_CODE_INVALID": return "That code is incorrect. Try again.";
            case "AUTH_MFA_CODE_EXPIRED": return "That code expired. Request a new one.";
            case "AUTH_MFA_RECOVERY_CODE_INVALID": return "That recovery code is incorrect.";
            default: return "Something went wrong. Try again.";
        }
    }

    private static boolean retryableForAuthCode(String authCode) {
        return "AUTH_RATE_LIMITED".equals(authCode)
                || "AUTH_STORAGE_WRITE_FAILED".equals(authCode)
                || "AUTH_NETWORK_UNAVAILABLE".equals(authCode)
                || "AUTH_SERVICE_UNAVAILABLE".equals(authCode)
                || "AUTH_OAUTH_FAILED".equals(authCode)
                || "AUTH_OAUTH_PROVIDER_UNAVAILABLE".equals(authCode)
                || "AUTH_SSO_FAILED".equals(authCode)
                || "AUTH_PASSKEY_FAILED".equals(authCode)
                || "AUTH_MFA_CODE_EXPIRED".equals(authCode)
                || "AUTH_MFA_PUSH_TIMEOUT".equals(authCode)
                || "AUTH_MFA_SMS_UNAVAILABLE".equals(authCode)
                || "AUTH_UNKNOWN".equals(authCode);
    }
}
