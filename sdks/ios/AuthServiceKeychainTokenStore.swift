import Foundation

#if canImport(Security)
import Security

public final class KeychainAuthServiceTokenStore: AuthServiceTokenStore {
    private let service: String
    private let accessAccount: String
    private let refreshAccount: String

    public init(service: String = "AuthService", namespace: String = "default") {
        self.service = service
        self.accessAccount = namespace + ".access_token"
        self.refreshAccount = namespace + ".refresh_token"
    }

    public var accessToken: String? {
        get { read(account: accessAccount) }
        set { write(newValue, account: accessAccount) }
    }

    public var refreshToken: String? {
        get { read(account: refreshAccount) }
        set { write(newValue, account: refreshAccount) }
    }

    private func read(account: String) -> String? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    private func write(_ value: String?, account: String) {
        let query = baseQuery(account: account)
        guard let value else {
            SecItemDelete(query as CFDictionary)
            return
        }

        let data = Data(value.utf8)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            SecItemAdd(addQuery as CFDictionary, nil)
        }
    }

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }
}
#endif
