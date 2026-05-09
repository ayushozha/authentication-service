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

public struct AuthServiceAPIError: Error, Decodable {
    public let statusCode: Int
    public let error: String

    public init(statusCode: Int, error: String) {
        self.statusCode = statusCode
        self.error = error
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
    public let tokenType: String?
    public let expiresIn: Int?
    public let user: AuthServiceUser?
    public let requires2FA: Bool?
    public let twoFactorToken: String?
    public let twoFactorMethods: [String]?

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case refreshToken = "refresh_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case user
        case requires2FA = "requires_2fa"
        case twoFactorToken = "two_factor_token"
        case twoFactorMethods = "two_factor_methods"
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
        let body = SignupRequest(email: email, password: password, displayName: displayName, sessionMode: config.sessionMode)
        let response: AuthServiceAuthResponse = try await send("/api/auth/signup", method: "POST", body: body, authorized: false)
        persist(response)
        return response
    }

    @discardableResult
    public func login(email: String, password: String) async throws -> AuthServiceAuthResponse {
        let body = LoginRequest(email: email, password: password, sessionMode: config.sessionMode)
        let response: AuthServiceAuthResponse = try await send("/api/auth/login", method: "POST", body: body, authorized: false)
        persist(response)
        return response
    }

    @discardableResult
    public func refresh() async throws -> AuthServiceAuthResponse {
        let body = RefreshRequest(refreshToken: tokenStore.refreshToken, sessionMode: config.sessionMode)
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

        let (data, response) = try await urlSession.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw AuthServiceAPIError(statusCode: 0, error: "invalid HTTP response")
        }
        guard (200..<300).contains(http.statusCode) else {
            let apiError = (try? decoder.decode(AuthServiceAPIError.self, from: data)) ?? AuthServiceAPIError(statusCode: http.statusCode, error: HTTPURLResponse.localizedString(forStatusCode: http.statusCode))
            throw apiError
        }
        if data.isEmpty {
            guard let empty = EmptyResponse() as? Response else {
                throw AuthServiceAPIError(statusCode: http.statusCode, error: "empty response body")
            }
            return empty
        }
        return try decoder.decode(Response.self, from: data)
    }

    private func persist(_ response: AuthServiceAuthResponse) {
        if let accessToken = response.accessToken {
            tokenStore.accessToken = accessToken
        }
        if let refreshToken = response.refreshToken {
            tokenStore.refreshToken = refreshToken
        }
    }

    private func makeURL(_ path: String) -> URL {
        let base = config.baseURL.absoluteString.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let suffix = path.hasPrefix("/") ? path : "/" + path
        return URL(string: base + suffix)!
    }
}

private struct EmptyRequest: Encodable {}
private struct EmptyResponse: Codable {}

private struct SignupRequest: Encodable {
    let email: String
    let password: String
    let displayName: String?
    let sessionMode: String

    enum CodingKeys: String, CodingKey {
        case email
        case password
        case displayName = "display_name"
        case sessionMode = "session_mode"
    }
}

private struct LoginRequest: Encodable {
    let email: String
    let password: String
    let sessionMode: String

    enum CodingKeys: String, CodingKey {
        case email
        case password
        case sessionMode = "session_mode"
    }
}

private struct RefreshRequest: Encodable {
    let refreshToken: String?
    let sessionMode: String

    enum CodingKeys: String, CodingKey {
        case refreshToken = "refresh_token"
        case sessionMode = "session_mode"
    }
}

private struct LogoutRequest: Encodable {
    let refreshToken: String?

    enum CodingKeys: String, CodingKey {
        case refreshToken = "refresh_token"
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
