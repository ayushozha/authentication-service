import Foundation

public protocol AuthServiceTokenStore: AnyObject {
    var accessToken: String? { get set }
    var refreshToken: String? { get set }
}

public final class InMemoryAuthServiceTokenStore: AuthServiceTokenStore {
    public var accessToken: String?
    public var refreshToken: String?

    public init() {}
}

public struct AuthServiceConfig {
    public let baseURL: URL
    public let apiKey: String
    public let sessionMode: String

    public init(baseURL: URL, apiKey: String, sessionMode: String = "token") {
        self.baseURL = baseURL
        self.apiKey = apiKey
        self.sessionMode = sessionMode
    }
}

public struct AuthServiceAPIError: Error, Decodable, LocalizedError {
    public let statusCode: Int
    public let error: String
    public let code: String?
    public let authCode: String
    public let userMessage: String
    public let retryable: Bool

    public init(statusCode: Int, error: String, code: String? = nil, authCode: String? = nil, userMessage: String? = nil, retryable: Bool? = nil) {
        self.statusCode = statusCode
        self.error = error
        self.code = code
        let mappedAuthCode = authCode ?? Self.mapAuthCode(providerCode: code, message: error, statusCode: statusCode)
        self.authCode = mappedAuthCode
        self.userMessage = userMessage ?? Self.userMessage(for: mappedAuthCode)
        self.retryable = retryable ?? Self.retryable(for: mappedAuthCode)
    }

    public var errorDescription: String? {
        userMessage
    }

    enum CodingKeys: String, CodingKey {
        case statusCode = "status_code"
        case error
        case message
        case code
        case authCode = "auth_code"
        case userMessage = "user_message"
        case retryable
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        statusCode = try container.decodeIfPresent(Int.self, forKey: .statusCode) ?? 0
        code = try container.decodeIfPresent(String.self, forKey: .code)
        error = try container.decodeIfPresent(String.self, forKey: .error)
            ?? container.decodeIfPresent(String.self, forKey: .message)
            ?? "AuthService request failed"
        let mappedAuthCode = try container.decodeIfPresent(String.self, forKey: .authCode)
            ?? Self.mapAuthCode(providerCode: code ?? error, message: error, statusCode: statusCode)
        authCode = mappedAuthCode
        userMessage = try container.decodeIfPresent(String.self, forKey: .userMessage)
            ?? Self.userMessage(for: mappedAuthCode)
        retryable = try container.decodeIfPresent(Bool.self, forKey: .retryable)
            ?? Self.retryable(for: mappedAuthCode)
    }

    private static func mapAuthCode(providerCode: String?, message: String, statusCode: Int) -> String {
        let normalized = (providerCode ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: "-", with: "_")
            .replacingOccurrences(of: " ", with: "_")
        switch normalized {
        case "invalid_request", "invalid_request_body":
            return "AUTH_INVALID_REQUEST"
        case "email_required":
            return "AUTH_EMAIL_REQUIRED"
        case "invalid_email":
            return "AUTH_INVALID_EMAIL"
        case "weak_password", "password_too_short":
            return "AUTH_PASSWORD_TOO_SHORT"
        case "invalid_credentials", "user_not_found":
            return "AUTH_INVALID_CREDENTIALS"
        case "account_locked":
            return "AUTH_ACCOUNT_LOCKED"
        case "account_suspended", "account_disabled":
            return "AUTH_ACCOUNT_DISABLED"
        case "rate_limited":
            return "AUTH_RATE_LIMITED"
        case "refresh_token_missing", "missing_authorization_header":
            return "AUTH_TOKEN_MISSING"
        case "invalid_access_token":
            return "AUTH_SESSION_EXPIRED"
        case "invalid_refresh_token":
            return "AUTH_TOKEN_REVOKED"
        case "missing_api_key", "invalid_api_key", "redis_required", "email_not_configured", "internal_error":
            return "AUTH_SERVICE_UNAVAILABLE"
        case "oauth_failed":
            return "AUTH_OAUTH_FAILED"
        case "access_denied":
            return "AUTH_OAUTH_CANCELLED"
        case "invalid_state":
            return "AUTH_OAUTH_STATE_MISMATCH"
        case "oauth_provider_unavailable":
            return "AUTH_OAUTH_PROVIDER_UNAVAILABLE"
        case "sso_required":
            return "AUTH_SSO_FAILED"
        case "passkey_failed", "authentication_failed":
            return "AUTH_PASSKEY_FAILED"
        case "invalid_totp", "invalid_code":
            return "AUTH_MFA_CODE_INVALID"
        case "invalid_recovery_code":
            return "AUTH_MFA_RECOVERY_CODE_INVALID"
        default:
            let lowerMessage = message.lowercased()
            if lowerMessage.contains("invalid email or password") { return "AUTH_INVALID_CREDENTIALS" }
            if lowerMessage.contains("too many") || lowerMessage.contains("rate") { return "AUTH_RATE_LIMITED" }
            if statusCode == 429 { return "AUTH_RATE_LIMITED" }
            if statusCode == 401 { return "AUTH_SESSION_EXPIRED" }
            if statusCode >= 500 { return "AUTH_SERVICE_UNAVAILABLE" }
            return "AUTH_UNKNOWN"
        }
    }

    private static func userMessage(for authCode: String) -> String {
        switch authCode {
        case "AUTH_INVALID_REQUEST": return "We could not process that request. Try again."
        case "AUTH_EMAIL_REQUIRED": return "Enter your email address."
        case "AUTH_PASSWORD_REQUIRED": return "Enter your password."
        case "AUTH_EMAIL_PASSWORD_REQUIRED": return "Enter your email and password."
        case "AUTH_INVALID_EMAIL": return "Enter a valid email address."
        case "AUTH_PASSWORD_TOO_SHORT": return "Use at least 8 characters for your password."
        case "AUTH_INVALID_CREDENTIALS": return "The email or password is incorrect."
        case "AUTH_ACCOUNT_LOCKED": return "This account is locked. Check your email for next steps."
        case "AUTH_ACCOUNT_DISABLED": return "This account cannot sign in right now."
        case "AUTH_RATE_LIMITED": return "Too many attempts. Try again in a few minutes."
        case "AUTH_SESSION_EXPIRED": return "Your session expired. Sign in again."
        case "AUTH_TOKEN_MISSING": return "Sign in again to continue."
        case "AUTH_TOKEN_REVOKED": return "Your session is no longer active. Sign in again."
        case "AUTH_SERVICE_UNAVAILABLE": return "We could not sign you in right now. Try again later."
        case "AUTH_OAUTH_FAILED": return "We could not complete sign-in with that provider."
        case "AUTH_OAUTH_CANCELLED": return "Sign-in was cancelled."
        case "AUTH_OAUTH_STATE_MISMATCH": return "We could not verify that sign-in. Try again."
        case "AUTH_OAUTH_PROVIDER_UNAVAILABLE": return "That sign-in provider is unavailable. Try again later."
        case "AUTH_SSO_FAILED": return "We could not complete single sign-on. Try again."
        case "AUTH_PASSKEY_FAILED": return "We could not complete passkey sign-in. Try again."
        case "AUTH_PASSKEY_CANCELLED": return "Passkey sign-in was cancelled."
        case "AUTH_MFA_REQUIRED": return "Enter the code from your authenticator app."
        case "AUTH_MFA_CODE_INVALID": return "That code is incorrect. Try again."
        case "AUTH_MFA_CODE_EXPIRED": return "That code expired. Request a new one."
        case "AUTH_MFA_RECOVERY_CODE_INVALID": return "That recovery code is incorrect."
        default: return "Something went wrong. Try again."
        }
    }

    private static func retryable(for authCode: String) -> Bool {
        switch authCode {
        case "AUTH_RATE_LIMITED", "AUTH_STORAGE_WRITE_FAILED", "AUTH_NETWORK_UNAVAILABLE", "AUTH_SERVICE_UNAVAILABLE", "AUTH_OAUTH_FAILED", "AUTH_OAUTH_PROVIDER_UNAVAILABLE", "AUTH_SSO_FAILED", "AUTH_PASSKEY_FAILED", "AUTH_MFA_CODE_EXPIRED", "AUTH_MFA_PUSH_TIMEOUT", "AUTH_MFA_SMS_UNAVAILABLE", "AUTH_UNKNOWN":
            return true
        default:
            return false
        }
    }
}

public struct AuthServiceUser: Codable {
    public let id: String
    public let clientID: String?
    public let email: String
    public let emailVerified: Bool?
    public let displayName: String?
    public let avatarURL: String?
    public let timezone: String?
    public let locale: String?
    public let role: String?
    public let status: String?
    public let totpEnabled: Bool?

    enum CodingKeys: String, CodingKey {
        case id
        case clientID = "client_id"
        case email
        case emailVerified = "email_verified"
        case displayName = "display_name"
        case avatarURL = "avatar_url"
        case timezone
        case locale
        case role
        case status
        case totpEnabled = "totp_enabled"
    }
}

public struct AuthServiceAuthResponse: Codable {
    public let accessToken: String?
    public let refreshToken: String?
    public let refresh: AuthServiceRefreshInfo?
    public let tokenType: String?
    public let expiresIn: Int?
    public let user: AuthServiceUser?
    public let requires2FA: Bool?
    public let twoFactorToken: String?
    public let twoFactorMethods: [String]?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case refresh
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case user
        case requires2FA = "requires_2fa"
        case twoFactorToken = "two_factor_token"
        case twoFactorMethods = "two_factor_methods"
    }
}

public struct AuthServiceRefreshInfo: Codable {
    public let transport: String
    public let cookieName: String?
    public let expiresIn: Int

    enum CodingKeys: String, CodingKey {
        case transport
        case cookieName = "cookie_name"
        case expiresIn = "expires_in"
    }
}

public struct AuthServiceTOTPSetupResponse: Codable {
    public let secret: String
    public let uri: String
    public let qr: String
}

public struct AuthServiceRecoveryCodesResponse: Codable {
    public let recoveryCodes: [String]?
    public let unusedCount: Int

    enum CodingKeys: String, CodingKey {
        case recoveryCodes = "recovery_codes"
        case unusedCount = "unused_count"
    }
}

public enum AuthServiceJSONValue: Codable, Equatable {
    case null
    case bool(Bool)
    case number(Double)
    case string(String)
    case array([AuthServiceJSONValue])
    case object([String: AuthServiceJSONValue])

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([AuthServiceJSONValue].self) {
            self = .array(value)
        } else {
            self = .object(try container.decode([String: AuthServiceJSONValue].self))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null:
            try container.encodeNil()
        case .bool(let value):
            try container.encode(value)
        case .number(let value):
            try container.encode(value)
        case .string(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        }
    }
}

public struct AuthServicePasskeyChallenge: Codable, Equatable {
    public let publicKey: [String: AuthServiceJSONValue]
    public let sessionID: String?

    enum CodingKeys: String, CodingKey {
        case publicKey
        case sessionID = "session_id"
    }
}

public struct AuthServiceOrganization: Codable {
    public let id: String
    public let name: String
    public let slug: String
}

public struct AuthServiceOrganizationMembership: Codable {
    public let id: String
    public let organizationID: String
    public let userID: String
    public let role: String
    public let permissions: [String]

    enum CodingKeys: String, CodingKey {
        case id
        case organizationID = "organization_id"
        case userID = "user_id"
        case role
        case permissions
    }
}

public struct AuthServiceOrganizationDetails: Codable {
    public let organization: AuthServiceOrganization
    public let membership: AuthServiceOrganizationMembership
}

public struct AuthServiceOrganizationList: Codable {
    public let organizations: [AuthServiceOrganizationDetails]
}

public struct AuthServiceOrganizationToken: Codable {
    public let accessToken: String
    public let tokenType: String
    public let expiresIn: Int

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
    }
}

public final class AuthServiceClient {
    private let config: AuthServiceConfig
    private let urlSession: URLSession
    private let tokenStore: AuthServiceTokenStore
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(config: AuthServiceConfig, tokenStore: AuthServiceTokenStore = InMemoryAuthServiceTokenStore(), urlSession: URLSession = .shared) {
        self.config = config
        self.tokenStore = tokenStore
        self.urlSession = urlSession
    }

    @discardableResult
    public func signup(email: String, password: String, displayName: String? = nil) async throws -> AuthServiceAuthResponse {
        let body = SignupRequest(email: email, password: password, displayName: displayName, sessionMode: config.sessionMode, tokenTransport: tokenTransport)
        let response: AuthServiceAuthResponse = try await send("/api/auth/signup", method: "POST", body: body, authorized: false)
        persist(response)
        return response
    }

    @discardableResult
    public func login(email: String, password: String) async throws -> AuthServiceAuthResponse {
        let body = LoginRequest(email: email, password: password, sessionMode: config.sessionMode, tokenTransport: tokenTransport)
        let response: AuthServiceAuthResponse = try await send("/api/auth/login", method: "POST", body: body, authorized: false)
        persist(response)
        return response
    }

    @discardableResult
    public func refresh() async throws -> AuthServiceAuthResponse {
        let body = RefreshRequest(refreshToken: tokenStore.refreshToken, sessionMode: config.sessionMode, tokenTransport: tokenTransport)
        let response: AuthServiceAuthResponse = try await send("/api/auth/refresh", method: "POST", body: body, authorized: false)
        persist(response)
        return response
    }

    public func logout() async throws {
        let body = LogoutRequest(refreshToken: tokenStore.refreshToken)
        let _: EmptyResponse = try await send("/api/auth/logout", method: "POST", body: body, authorized: false)
        tokenStore.accessToken = nil
        tokenStore.refreshToken = nil
    }

    public func forgotPassword(email: String) async throws {
        let body = ForgotPasswordRequest(email: email)
        let _: EmptyResponse = try await send("/api/auth/forgot-password", method: "POST", body: body, authorized: false)
    }

    public func resetPassword(token: String, newPassword: String) async throws {
        let body = ResetPasswordRequest(token: token, newPassword: newPassword)
        let _: EmptyResponse = try await send("/api/auth/reset-password", method: "POST", body: body, authorized: false)
    }

    public func verifyEmail(token: String) async throws {
        let body = VerifyEmailRequest(token: token)
        let _: EmptyResponse = try await send("/api/auth/verify-email", method: "POST", body: body, authorized: false)
    }

    public func resendVerification() async throws {
        let _: EmptyResponse = try await send("/api/auth/resend-verification", method: "POST", body: EmptyRequest(), authorized: true)
    }

    public func setupTOTP() async throws -> AuthServiceTOTPSetupResponse {
        try await send("/api/auth/totp/setup", method: "POST", body: EmptyRequest(), authorized: true)
    }

    public func enableTOTP(code: String) async throws {
        let body = TOTPCodeRequest(code: code)
        let _: EmptyResponse = try await send("/api/auth/totp/enable", method: "POST", body: body, authorized: true)
    }

    public func disableTOTP(code: String) async throws {
        let body = TOTPCodeRequest(code: code)
        let _: EmptyResponse = try await send("/api/auth/totp/disable", method: "POST", body: body, authorized: true)
    }

    @discardableResult
    public func verifyTOTP(twoFactorToken: String, code: String, rememberDevice: Bool = false, deviceName: String? = nil) async throws -> AuthServiceAuthResponse {
        let body = TwoFactorVerifyRequest(twoFactorToken: twoFactorToken, code: code, sessionMode: config.sessionMode, tokenTransport: tokenTransport, rememberDevice: rememberDevice, deviceName: deviceName)
        let response: AuthServiceAuthResponse = try await send("/api/auth/totp/verify", method: "POST", body: body, authorized: false)
        persist(response)
        return response
    }

    @discardableResult
    public func verifyRecoveryCode(twoFactorToken: String, code: String, rememberDevice: Bool = false, deviceName: String? = nil) async throws -> AuthServiceAuthResponse {
        let body = TwoFactorVerifyRequest(twoFactorToken: twoFactorToken, code: code, sessionMode: config.sessionMode, tokenTransport: tokenTransport, rememberDevice: rememberDevice, deviceName: deviceName)
        let response: AuthServiceAuthResponse = try await send("/api/auth/recovery-codes/verify", method: "POST", body: body, authorized: false)
        persist(response)
        return response
    }

    public func recoveryCodeCount() async throws -> AuthServiceRecoveryCodesResponse {
        try await send("/api/auth/recovery-codes", method: "GET", body: Optional<EmptyRequest>.none, authorized: true)
    }

    public func generateRecoveryCodes() async throws -> AuthServiceRecoveryCodesResponse {
        try await send("/api/auth/recovery-codes", method: "POST", body: EmptyRequest(), authorized: true)
    }

    public func beginPasskeyRegistration() async throws -> AuthServicePasskeyChallenge {
        try await send("/api/auth/passkey/register/begin", method: "POST", body: EmptyRequest(), authorized: true)
    }

    public func finishPasskeyRegistration(credentialJSON: Data, friendlyName: String? = nil) async throws {
        let path = "/api/auth/passkey/register/finish" + queryString(["name": friendlyName])
        let _: EmptyResponse = try await sendRawJSON(path, method: "POST", body: credentialJSON, authorized: true)
    }

    public func beginPasskeyLogin() async throws -> AuthServicePasskeyChallenge {
        try await send("/api/auth/passkey/login/begin", method: "POST", body: EmptyRequest(), authorized: false)
    }

    @discardableResult
    public func finishPasskeyLogin(sessionID: String, credentialJSON: Data) async throws -> AuthServiceAuthResponse {
        let path = "/api/auth/passkey/login/finish" + queryString([
            "session_id": sessionID,
            "session_mode": config.sessionMode == "token" ? "token" : nil,
            "token_transport": tokenTransport
        ])
        let response: AuthServiceAuthResponse = try await sendRawJSON(path, method: "POST", body: credentialJSON, authorized: false)
        persist(response)
        return response
    }

    public func listPasskeys() async throws -> [AuthServiceJSONValue] {
        try await send("/api/auth/passkeys", method: "GET", body: Optional<EmptyRequest>.none, authorized: true)
    }

    public func deletePasskey(id: String) async throws {
        let _: EmptyResponse = try await send("/api/auth/passkeys/\(urlPath(id))", method: "DELETE", body: Optional<EmptyRequest>.none, authorized: true)
    }

    public func me() async throws -> AuthServiceUser {
        try await send("/api/auth/me", method: "GET", body: Optional<EmptyRequest>.none, authorized: true)
    }

    public func updateProfile(displayName: String? = nil, timezone: String? = nil) async throws -> AuthServiceUser {
        let body = UpdateProfileRequest(displayName: displayName, timezone: timezone)
        return try await send("/api/auth/me", method: "PATCH", body: body, authorized: true)
    }

    public func createOrganization(name: String, slug: String? = nil) async throws -> AuthServiceOrganizationDetails {
        let body = CreateOrganizationRequest(name: name, slug: slug)
        return try await send("/api/auth/organizations", method: "POST", body: body, authorized: true)
    }

    public func listOrganizations() async throws -> AuthServiceOrganizationList {
        try await send("/api/auth/organizations", method: "GET", body: Optional<EmptyRequest>.none, authorized: true)
    }

    public func createOrganizationToken(organizationID: String, activate: Bool = false) async throws -> AuthServiceOrganizationToken {
        let token: AuthServiceOrganizationToken = try await send("/api/auth/organizations/\(organizationID)/token", method: "POST", body: EmptyRequest(), authorized: true)
        if activate {
            tokenStore.accessToken = token.accessToken
        }
        return token
    }

    private func send<Response: Decodable, Body: Encodable>(_ path: String, method: String, body: Body?, authorized: Bool) async throws -> Response {
        var request = URLRequest(url: makeURL(path))
        request.httpMethod = method
        request.setValue(config.apiKey, forHTTPHeaderField: "X-API-Key")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if authorized, let accessToken = tokenStore.accessToken {
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = try encoder.encode(body)
        }
        return try await execute(request)
    }

    private func sendRawJSON<Response: Decodable>(_ path: String, method: String, body: Data, authorized: Bool) async throws -> Response {
        var request = URLRequest(url: makeURL(path))
        request.httpMethod = method
        request.setValue(config.apiKey, forHTTPHeaderField: "X-API-Key")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if authorized, let accessToken = tokenStore.accessToken {
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }
        request.httpBody = body
        return try await execute(request)
    }

    private func execute<Response: Decodable>(_ request: URLRequest) async throws -> Response {
        let (data, response) = try await urlSession.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw AuthServiceAPIError(statusCode: 0, error: "invalid HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let decodedError = try? decoder.decode(AuthServiceAPIError.self, from: data)
            let apiError = AuthServiceAPIError(
                statusCode: http.statusCode,
                error: decodedError?.error ?? responseErrorFallback(data: data, statusCode: http.statusCode),
                code: decodedError?.code,
                authCode: decodedError?.authCode,
                userMessage: decodedError?.userMessage,
                retryable: decodedError?.retryable
            )
            throw apiError
        }
        if data.isEmpty {
            guard let empty = EmptyResponse() as? Response else {
                throw AuthServiceAPIError(statusCode: http.statusCode, error: "empty response body")
            }
            return empty
        }
        do {
            return try decoder.decode(Response.self, from: data)
        } catch {
            throw AuthServiceAPIError(statusCode: http.statusCode, error: "AuthService returned a response this SDK could not decode")
        }
    }

    private func persist(_ response: AuthServiceAuthResponse) {
        if let accessToken = response.accessToken {
            tokenStore.accessToken = accessToken
        }
        if let refreshToken = response.refreshToken {
            tokenStore.refreshToken = refreshToken
        }
    }

    private var tokenTransport: String {
        config.sessionMode == "token" ? "json" : "cookie"
    }

    private func makeURL(_ path: String) -> URL {
        let base = config.baseURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let suffix = path.hasPrefix("/") ? path : "/" + path
        return URL(string: base + suffix)!
    }

    private func queryString(_ values: [String: String?]) -> String {
        var components = URLComponents()
        components.queryItems = values.compactMap { key, value in
            guard let value, !value.isEmpty else { return nil }
            return URLQueryItem(name: key, value: value)
        }
        guard let query = components.percentEncodedQuery, !query.isEmpty else {
            return ""
        }
        return "?" + query
    }

    private func urlPath(_ value: String) -> String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: "/")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }

    private func responseErrorFallback(data: Data, statusCode: Int) -> String {
        let fallback = HTTPURLResponse.localizedString(forStatusCode: statusCode)
        guard let text = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty else {
            return fallback
        }
        return String(text.prefix(200))
    }
}

private struct EmptyRequest: Encodable {}
private struct EmptyResponse: Codable {}

private struct SignupRequest: Encodable {
    let email: String
    let password: String
    let displayName: String?
    let sessionMode: String
    let tokenTransport: String

    enum CodingKeys: String, CodingKey {
        case email
        case password
        case displayName = "display_name"
        case sessionMode = "session_mode"
        case tokenTransport = "token_transport"
    }
}

private struct LoginRequest: Encodable {
    let email: String
    let password: String
    let sessionMode: String
    let tokenTransport: String

    enum CodingKeys: String, CodingKey {
        case email
        case password
        case sessionMode = "session_mode"
        case tokenTransport = "token_transport"
    }
}

private struct RefreshRequest: Encodable {
    let refreshToken: String?
    let sessionMode: String
    let tokenTransport: String

    enum CodingKeys: String, CodingKey {
        case refreshToken = "refresh_token"
        case sessionMode = "session_mode"
        case tokenTransport = "token_transport"
    }
}

private struct LogoutRequest: Encodable {
    let refreshToken: String?

    enum CodingKeys: String, CodingKey {
        case refreshToken = "refresh_token"
    }
}

private struct ForgotPasswordRequest: Encodable {
    let email: String
}

private struct ResetPasswordRequest: Encodable {
    let token: String
    let newPassword: String

    enum CodingKeys: String, CodingKey {
        case token
        case newPassword = "new_password"
    }
}

private struct VerifyEmailRequest: Encodable {
    let token: String
}

private struct TOTPCodeRequest: Encodable {
    let code: String
}

private struct TwoFactorVerifyRequest: Encodable {
    let twoFactorToken: String
    let code: String
    let sessionMode: String
    let tokenTransport: String
    let rememberDevice: Bool
    let deviceName: String?

    enum CodingKeys: String, CodingKey {
        case twoFactorToken = "two_factor_token"
        case code
        case sessionMode = "session_mode"
        case tokenTransport = "token_transport"
        case rememberDevice = "remember_device"
        case deviceName = "device_name"
    }
}

private struct UpdateProfileRequest: Encodable {
    let displayName: String?
    let timezone: String?

    enum CodingKeys: String, CodingKey {
        case displayName = "display_name"
        case timezone
    }
}

private struct CreateOrganizationRequest: Encodable {
    let name: String
    let slug: String?
}
