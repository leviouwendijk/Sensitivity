public extension Sensitivity {
    /// A named set of detectors for data that is sensitive anywhere,
    /// switched on by name (`presets: [.secrets, .contacts]`).
    struct Preset: Sendable {
        public let name: String
        public let detectors: [any Detector]

        public init(_ name: String, detectors: [any Detector]) {
            self.name = name
            self.detectors = detectors
        }

        public static let all: [Preset] = [.secrets, .contacts, .financial, .network, .links]

        /// The preset called `name`, of `all`.
        public static func named(_ name: String) -> Preset? {
            all.first { $0.name == name }
        }
    }
}

public extension Sensitivity.Preset {
    /// Keys, tokens, passwords and private keys.
    static let secrets = Self("secrets", detectors: [
        Sensitivity.Pattern(
            "secrets.pem",
            kind: .secret,
            pattern: "-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE)-----",
            score: 98,
            reason: "PEM key or certificate block"
        ),
        Sensitivity.Pattern(
            "secrets.assignment",
            kind: .secret,
            // The value only, so the name stays readable after replacing.
            pattern: "(?<=(?:api[_-]?key|apikey|secret|token|password|passwd|client[_-]?secret|access[_-]?token|refresh[_-]?token|private[_-]?key)[\"']?\\s{0,3}[:=]\\s{0,3}[\"']?)[^\\s\"',;]{8,}",
            score: 90,
            reason: "value assigned to a key, token or password"
        ),
        Sensitivity.Pattern(
            "secrets.aws-access-key",
            kind: .secret,
            pattern: "\\bAKIA[0-9A-Z]{16}\\b",
            score: 95,
            reason: "AWS access key id",
            caseSensitive: true
        ),
        Sensitivity.Pattern(
            "secrets.long-token",
            kind: .secret,
            pattern: "(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])",
            score: 65,
            reason: "long random-looking token",
            caseSensitive: true,
            // Mixed case and digits; plain hex (commit hashes, digests) is not a secret.
            assess: { token in
                let upper = token.contains { $0.isUppercase }
                let lower = token.contains { $0.isLowercase }
                let digit = token.contains { $0.isNumber }
                return upper && lower && digit ? Sensitivity.Score(clamping: 65) : nil
            }
        ),
    ])

    /// Mail addresses, phone numbers and Dutch postcodes.
    static let contacts = Self("contacts", detectors: [
        Sensitivity.Pattern(
            "contacts.email",
            kind: .contact,
            pattern: "(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
            score: 90,
            reason: "mail address"
        ),
        Sensitivity.Pattern(
            "contacts.phone-nl-mobile",
            kind: .contact,
            pattern: "(?<![\\d+])(?:\\+31[\\s-]?6|0031[\\s-]?6|06)[\\s-]?\\d(?:[\\s-]?\\d){7}(?!\\d)",
            score: 88,
            reason: "Dutch mobile number"
        ),
        Sensitivity.Pattern(
            "contacts.phone-international",
            kind: .contact,
            pattern: "(?<![\\d+])\\+\\d{1,3}[\\s-]?\\d(?:[\\s-]?\\d){6,12}(?!\\d)",
            score: 75,
            reason: "international phone number"
        ),
        Sensitivity.Pattern(
            "contacts.postcode-nl",
            kind: .contact,
            pattern: "\\b[1-9]\\d{3}\\s?[A-Z]{2}\\b",
            score: 50,
            reason: "Dutch postcode",
            caseSensitive: true
        ),
    ])

    /// IBANs; a valid checksum makes a finding near certain.
    static let financial = Self("financial", detectors: [
        Sensitivity.Pattern(
            "financial.iban",
            kind: .financial,
            pattern: "\\b[A-Z]{2}\\d{2}(?:\\s?[A-Z0-9]{4}){2,7}(?:\\s?[A-Z0-9]{1,3})?\\b",
            score: 45,
            reason: "IBAN",
            caseSensitive: true,
            assess: { candidate in
                (try? Sensitivity.IBAN(candidate)) != nil ? Sensitivity.Score(clamping: 97) : Sensitivity.Score(clamping: 45)
            }
        ),
    ])

    /// Private IPv4 addresses and MAC addresses.
    static let network = Self("network", detectors: [
        Sensitivity.Pattern(
            "network.private-ipv4",
            kind: .network,
            pattern: "\\b(?:10\\.\\d{1,3}|192\\.168|172\\.(?:1[6-9]|2\\d|3[01]))\\.\\d{1,3}\\.\\d{1,3}\\b",
            score: 80,
            reason: "private IPv4 address"
        ),
        Sensitivity.Pattern(
            "network.mac",
            kind: .network,
            pattern: "\\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\\b",
            score: 70,
            reason: "MAC address"
        ),
    ])

    /// URLs that carry access in their query.
    static let links = Self("links", detectors: [
        Sensitivity.Pattern(
            "links.token-url",
            kind: .link,
            pattern: "https?://[^\\s\"'<>]*[?&](?:token|key|sig|signature|code|auth|access_token)=[^\\s\"'<>&]+[^\\s\"'<>]*",
            score: 85,
            reason: "URL carrying a token or signature"
        ),
    ])
}
