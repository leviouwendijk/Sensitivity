#if canImport(Security)
import Foundation
import Security

public extension Sensitivity {
    /// Keeps a vault in the login Keychain as one generic-password item,
    /// outside every session directory. Entries carry their own expiry; the
    /// vault drops expired ones when it loads.
    struct KeychainVaultStore: VaultStore {
        public enum Failure: Error, Sendable, Equatable {
            case keychain(OSStatus)
        }

        public let service: String
        public let account: String

        /// `account` names the vault, such as a session id.
        public init(service: String = "agentic.sensitivity.vault", account: String) {
            self.service = service
            self.account = account
        }

        private var query: [String: Any] {
            [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
            ]
        }

        public func load() throws -> [Vault.Entry] {
            var search = query
            search[kSecReturnData as String] = true
            search[kSecMatchLimit as String] = kSecMatchLimitOne
            var item: CFTypeRef?
            let status = SecItemCopyMatching(search as CFDictionary, &item)
            if status == errSecItemNotFound {
                return []
            }
            guard status == errSecSuccess, let data = item as? Data else {
                throw Failure.keychain(status)
            }
            return try JSONDecoder().decode([Vault.Entry].self, from: data)
        }

        public func save(_ entries: [Vault.Entry]) throws {
            let data = try JSONEncoder().encode(entries)
            let update = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
            if update == errSecItemNotFound {
                var add = query
                add[kSecValueData as String] = data
                add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                let status = SecItemAdd(add as CFDictionary, nil)
                guard status == errSecSuccess else { throw Failure.keychain(status) }
            } else if update != errSecSuccess {
                throw Failure.keychain(update)
            }
        }

        public func clear() throws {
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw Failure.keychain(status)
            }
        }
    }
}
#endif
