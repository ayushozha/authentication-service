import XCTest
@testable import AuthService

final class AuthServiceClientTests: XCTestCase {
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
}
