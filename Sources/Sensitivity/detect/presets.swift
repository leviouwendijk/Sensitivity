import Matching

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

        public static let all: [Preset] = [.secrets, .contacts, .financial, .payments, .network, .links]

        /// The preset called `name`, of `all`.
        public static func named(_ name: String) -> Preset? {
            all.first { $0.name == name }
        }
    }
}

public extension Sensitivity.Preset {
    /// Keys, tokens, passwords and private keys. Values are found by what
    /// names them (an assignment, an env variable, a header), so hex tokens
    /// are caught there while bare commit hashes are not.
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
            // Any name containing a credential word, as in api_key=, "access_token": or
            // MAIL_PASSWORD_LEVI_HM=; the value only, so the name stays readable.
            pattern: "(?<![A-Za-z0-9])[A-Za-z0-9_.-]*(?:api[_-]?key|apikey|secret|token|password|passwd|credential|private[_-]?key|auth[_-]?key)[A-Za-z0-9_.-]*[\"']?\\s{0,3}[:=]\\s{0,3}[\"']?(?<value>[^\\s\"',;]{6,})",
            score: 92,
            reason: "value assigned to a key, token or password",
            group: .named("value")
        ),
        Sensitivity.Pattern(
            "secrets.header",
            kind: .secret,
            // Authorization schemes and X-…-Authentication/Token/Key/Signature headers.
            pattern: "(?:authorization:\\s*(?:bearer|basic|token|digest)\\s+|\\bx-[a-z0-9-]*(?:auth|authentication|token|key|signature|secret)[a-z0-9-]*:\\s*)(?<value>[^\\s\"']{8,})",
            score: 94,
            reason: "credential in an HTTP header",
            group: .named("value")
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
            // Mixed case and digits; plain hex (commit hashes, digests) is not a secret on its own.
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
        Sensitivity.Pattern(
            "financial.bic",
            kind: .financial,
            // Only where it is labelled: a bare BIC looks like any 8-letter word.
            // The label in any case, the code itself upper case.
            pattern: "\\b(?i:bic|swift)(?:[\\s_-]?(?i:code))?[\"']?\\s{0,3}[:=]?\\s{0,3}[\"']?(?<value>[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\\b",
            score: 70,
            reason: "BIC",
            caseSensitive: true,
            group: .named("value")
        ),
    ])

    /// Payment provider credentials and identifiers (PAY.: AT codes, service
    /// ids).
    static let payments = Self("payments", detectors: [
        Sensitivity.Pattern(
            "payments.paynl-at-code",
            kind: .secret,
            pattern: "\\bAT-\\d{4}-\\d{4}\\b",
            score: 88,
            reason: "PAY. AT code (half of an API credential)",
            caseSensitive: true
        ),
        Sensitivity.Pattern(
            "payments.paynl-service-id",
            kind: .identifier,
            pattern: "\\bSL-\\d{4}-\\d{4}\\b",
            score: 40,
            reason: "PAY. service id",
            caseSensitive: true
        ),
    ])

    /// Private and link-local addresses, CIDR ranges and MAC addresses.
    static let network = Self("network", detectors: [
        Sensitivity.Pattern(
            "network.cidr",
            kind: .network,
            pattern: "\\b(?:\\d{1,3}\\.){3}\\d{1,3}/(?:3[0-2]|[12]?\\d)\\b",
            score: 82,
            reason: "IPv4 range"
        ),
        Sensitivity.Pattern(
            "network.private-ipv4",
            kind: .network,
            pattern: "\\b(?:10\\.\\d{1,3}|192\\.168|172\\.(?:1[6-9]|2\\d|3[01]))\\.\\d{1,3}\\.\\d{1,3}\\b",
            score: 80,
            reason: "private IPv4 address"
        ),
        Sensitivity.Pattern(
            "network.private-ipv6",
            kind: .network,
            pattern: "\\b(?:fd[0-9a-f]{2}|fe80):[0-9a-f:]*[0-9a-f](?:/\\d{1,3})?",
            score: 75,
            reason: "unique-local or link-local IPv6 address"
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
