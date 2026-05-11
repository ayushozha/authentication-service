import XCTest
@testable import AuthService

final class AuthServiceClientTests: XCTestCase {
    override func tearDown() {
        MockURLProtocol.requestHandler = nil
        super.tearDown()
    }

    func testConfigDefaultsToTokenMode() throws {
        let config = AuthServiceConfig(
            baseURL: try XCTUnwrap(URL(string: "https://auth.example.com")),
            apiKey: "api-key"
        )

        XCTAssertEqual(config.sessionMode, "token")
    }

    func testInMemoryTokenStorePersistsTokens() {
        let store = InMemoryAuthServiceTokenStore()

        store.accessToken = "access"
        store.refreshToken = "refresh"

        XCTAssertEqual(store.accessToken, "access")
        XCTAssertEqual(store.refreshToken, "refresh")
    }

    func testSignupPersistsTokenResponse() async throws {
        let tokenStore = InMemoryAuthServiceTokenStore()
        let client = try makeClient(tokenStore: tokenStore)

        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/signup")
            XCTAssertEqual(request.value(forHTTPHeaderField: "X-API-Key"), "api-key")
            let requestBody = try XCTUnwrap(Self.requestBodyData(from: request))
            let payload = try JSONSerialization.jsonObject(with: requestBody) as? [String: String]
            XCTAssertEqual(payload?["session_mode"], "token")
            XCTAssertEqual(payload?["token_transport"], "json")
            let body = """
            {
              "access_token": "access",
              "refresh_token": "refresh",
              "refresh": { "transport": "json", "expires_in": 604800 },
              "token_type": "Bearer",
              "expires_in": 900,
              "user": {
                "id": "user-1",
                "client_id": "client-1",
                "email": "user@example.com",
                "email_verified": false,
                "display_name": "User Example",
                "timezone": "",
                "locale": "",
                "role": "user",
                "status": "active",
                "totp_enabled": false
              }
            }
            """
            return Self.jsonResponse(status: 201, body: body, request: request)
        }

        let response = try await client.signup(email: "user@example.com", password: "Password123!", displayName: "User Example")

        XCTAssertEqual(response.accessToken, "access")
        XCTAssertEqual(response.refreshToken, "refresh")
        XCTAssertEqual(response.refresh?.transport, "json")
        XCTAssertEqual(response.user?.email, "user@example.com")
        XCTAssertEqual(tokenStore.accessToken, "access")
        XCTAssertEqual(tokenStore.refreshToken, "refresh")
    }

    func testRefreshUsesJsonTokenTransport() async throws {
        let tokenStore = InMemoryAuthServiceTokenStore()
        tokenStore.refreshToken = "refresh"
        let client = try makeClient(tokenStore: tokenStore)

        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/refresh")
            let requestBody = try XCTUnwrap(Self.requestBodyData(from: request))
            let payload = try JSONSerialization.jsonObject(with: requestBody) as? [String: String]
            XCTAssertEqual(payload?["refresh_token"], "refresh")
            XCTAssertEqual(payload?["token_transport"], "json")
            let body = """
            {
              "access_token": "new-access",
              "refresh_token": "new-refresh",
              "refresh": { "transport": "json", "expires_in": 604800 },
              "token_type": "Bearer",
              "expires_in": 900
            }
            """
            return Self.jsonResponse(status: 200, body: body, request: request)
        }

        let response = try await client.refresh()

        XCTAssertEqual(response.refresh?.transport, "json")
        XCTAssertEqual(tokenStore.accessToken, "new-access")
        XCTAssertEqual(tokenStore.refreshToken, "new-refresh")
    }

    func testAPIErrorUsesServerMessage() async throws {
        let client = try makeClient()
        MockURLProtocol.requestHandler = { request in
            Self.jsonResponse(status: 400, body: #"{"error":"invalid email"}"#, request: request)
        }

        do {
            _ = try await client.signup(email: "mail", password: "Password123!")
            XCTFail("Expected signup to throw")
        } catch let error as AuthServiceAPIError {
            XCTAssertEqual(error.statusCode, 400)
            XCTAssertEqual(error.error, "invalid email")
            XCTAssertEqual(error.localizedDescription, "invalid email")
        }
    }

    func testForgotPasswordPostsEmail() async throws {
        let client = try makeClient()
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/forgot-password")
            let body = try XCTUnwrap(Self.requestBodyData(from: request))
            let payload = try JSONSerialization.jsonObject(with: body) as? [String: String]
            XCTAssertEqual(payload?["email"], "user@example.com")
            return Self.jsonResponse(status: 200, body: #"{"ok":"true"}"#, request: request)
        }

        try await client.forgotPassword(email: "user@example.com")
    }

    func testVerifyEmailPostsToken() async throws {
        let client = try makeClient()
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/verify-email")
            let body = try XCTUnwrap(Self.requestBodyData(from: request))
            let payload = try JSONSerialization.jsonObject(with: body) as? [String: String]
            XCTAssertEqual(payload?["token"], "verify-token")
            return Self.jsonResponse(status: 200, body: #"{"ok":"true"}"#, request: request)
        }

        try await client.verifyEmail(token: "verify-token")
    }

    func testResendVerificationUsesBearerSession() async throws {
        let tokenStore = InMemoryAuthServiceTokenStore()
        tokenStore.accessToken = "access"
        let client = try makeClient(tokenStore: tokenStore)
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/resend-verification")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer access")
            return Self.jsonResponse(status: 200, body: #"{"ok":"true"}"#, request: request)
        }

        try await client.resendVerification()
    }

    func testVerifyTOTPPersistsTokenSession() async throws {
        let tokenStore = InMemoryAuthServiceTokenStore()
        let client = try makeClient(tokenStore: tokenStore)

        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/totp/verify")
            let body = try XCTUnwrap(Self.requestBodyData(from: request))
            let payload = try JSONSerialization.jsonObject(with: body) as? [String: Any]
            XCTAssertEqual(payload?["two_factor_token"] as? String, "challenge")
            XCTAssertEqual(payload?["code"] as? String, "123456")
            XCTAssertEqual(payload?["session_mode"] as? String, "token")
            XCTAssertEqual(payload?["token_transport"] as? String, "json")
            let responseBody = """
            {
              "access_token": "mfa-access",
              "refresh_token": "mfa-refresh",
              "token_type": "Bearer",
              "expires_in": 900
            }
            """
            return Self.jsonResponse(status: 200, body: responseBody, request: request)
        }

        let response = try await client.verifyTOTP(twoFactorToken: "challenge", code: "123456")

        XCTAssertEqual(response.accessToken, "mfa-access")
        XCTAssertEqual(tokenStore.accessToken, "mfa-access")
        XCTAssertEqual(tokenStore.refreshToken, "mfa-refresh")
    }

    func testPasskeyLoginBeginDecodesChallenge() async throws {
        let client = try makeClient()
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/passkey/login/begin")
            let body = """
            {
              "session_id": "session-1",
              "publicKey": {
                "challenge": "abc",
                "timeout": 60000,
                "userVerification": "required"
              }
            }
            """
            return Self.jsonResponse(status: 200, body: body, request: request)
        }

        let challenge = try await client.beginPasskeyLogin()

        XCTAssertEqual(challenge.sessionID, "session-1")
        XCTAssertEqual(challenge.publicKey["challenge"], .string("abc"))
        XCTAssertEqual(challenge.publicKey["timeout"], .number(60000))
    }

    func testFinishPasskeyLoginRequestsJsonTokenTransport() async throws {
        let tokenStore = InMemoryAuthServiceTokenStore()
        let client = try makeClient(tokenStore: tokenStore)
        MockURLProtocol.requestHandler = { request in
            XCTAssertEqual(request.url?.path, "/api/auth/passkey/login/finish")
            XCTAssertEqual(request.url?.query?.contains("session_id=session-1"), true)
            XCTAssertEqual(request.url?.query?.contains("session_mode=token"), true)
            XCTAssertEqual(request.url?.query?.contains("token_transport=json"), true)
            let body = try XCTUnwrap(Self.requestBodyData(from: request))
            XCTAssertEqual(String(data: body, encoding: .utf8), #"{"id":"credential"}"#)
            return Self.jsonResponse(status: 200, body: #"{"access_token":"passkey-access","refresh_token":"passkey-refresh"}"#, request: request)
        }

        let response = try await client.finishPasskeyLogin(sessionID: "session-1", credentialJSON: Data(#"{"id":"credential"}"#.utf8))

        XCTAssertEqual(response.accessToken, "passkey-access")
        XCTAssertEqual(tokenStore.accessToken, "passkey-access")
        XCTAssertEqual(tokenStore.refreshToken, "passkey-refresh")
    }

    private func makeClient(tokenStore: AuthServiceTokenStore = InMemoryAuthServiceTokenStore()) throws -> AuthServiceClient {
        let config = AuthServiceConfig(
            baseURL: try XCTUnwrap(URL(string: "https://auth.example.com")),
            apiKey: "api-key"
        )
        let urlSessionConfig = URLSessionConfiguration.ephemeral
        urlSessionConfig.protocolClasses = [MockURLProtocol.self]
        let session = URLSession(configuration: urlSessionConfig)
        return AuthServiceClient(config: config, tokenStore: tokenStore, urlSession: session)
    }

    private static func jsonResponse(status: Int, body: String, request: URLRequest) -> (HTTPURLResponse, Data) {
        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: status,
            httpVersion: nil,
            headerFields: ["Content-Type": "application/json"]
        )!
        return (response, Data(body.utf8))
    }

    private static func requestBodyData(from request: URLRequest) -> Data? {
        if let body = request.httpBody {
            return body
        }
        guard let stream = request.httpBodyStream else {
            return nil
        }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 1024)
        while stream.hasBytesAvailable {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count > 0 {
                data.append(buffer, count: count)
            } else {
                break
            }
        }
        return data
    }
}

final class MockURLProtocol: URLProtocol {
    static var requestHandler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool {
        true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let requestHandler = Self.requestHandler else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        do {
            let (response, data) = try requestHandler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
