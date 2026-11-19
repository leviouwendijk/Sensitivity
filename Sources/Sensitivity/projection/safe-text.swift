import Primitives

public extension Sensitivity {
    /// An allowlist for text that leaves a tool as-is: which characters, how
    /// long, and whether any preset may find something in it. The opposite of
    /// detection: what is not allowed does not pass, whatever it is.
    struct TextPolicy: Sendable, Hashable {
        public let maximumLength: Int
        public let allowsSpace: Bool
        /// Allowed besides ASCII letters and digits.
        public let punctuation: Set<Character>
        /// Rejects text in which these presets find anything.
        public let screenedBy: [String]

        public init(maximumLength: Int, allowsSpace: Bool, punctuation: Set<Character>, screenedBy: [String] = []) {
            self.maximumLength = maximumLength
            self.allowsSpace = allowsSpace
            self.punctuation = punctuation
            self.screenedBy = screenedBy
        }

        /// Display names: letters, digits, space, `-` and `_`, up to 64.
        /// Rules out addresses, URLs, hosts and CIDR by construction.
        public static let label = Self(maximumLength: 64, allowsSpace: true, punctuation: ["-", "_"])

        /// Enum-like values (`firewall_policy`, `DENY`): letters, digits and
        /// `_`, up to 48.
        public static let token = Self(maximumLength: 48, allowsSpace: false, punctuation: ["_"])

        /// Why `text` does not pass, or nil when it does.
        public func violation(_ text: String) -> String? {
            guard !text.trimmingWhitespace.isEmpty else { return "blank" }
            guard text.count <= maximumLength else { return "longer than \(maximumLength)" }
            for character in text {
                let allowed = (character.isASCII && (character.isLetter || character.isNumber))
                    || (allowsSpace && character == " ")
                    || punctuation.contains(character)
                guard allowed else { return "contains a character outside the policy" }
            }
            let presets = screenedBy.compactMap(Preset.named)
            if !presets.isEmpty, let finding = Sensitivity.scan(text, presets: presets).first {
                return "holds a \(finding.kind.rawValue) (\(finding.detector))"
            }
            return nil
        }
    }

    /// Text that passed `TextPolicy.label`: safe to show as a name.
    struct SafeLabel: CodableInvariant, Sendable, Hashable {
        public struct Rejected: InvarianceReason {
            public let detail: String
            public var code: InvarianceCode { .custom("unsafe_label") }
            public var message: String { "not a safe label: \(detail)" }
        }

        public let raw: String

        public init(_ raw: String) throws(InvarianceFailure) {
            if let detail = TextPolicy.label.violation(raw) {
                throw InvarianceFailure(.init(Rejected(detail: detail), path: [.field("label")]))
            }
            self.raw = raw
        }

        /// `raw` when it is safe, otherwise `fallback` (which should be safe
        /// by construction, such as "network 3").
        public static func or(_ raw: String?, fallback: String) -> String {
            guard let raw, let label = try? SafeLabel(raw) else { return fallback }
            return label.raw
        }
    }

    /// Text that passed `TextPolicy.token`: an enum-like value.
    struct SafeToken: CodableInvariant, Sendable, Hashable {
        public struct Rejected: InvarianceReason {
            public let detail: String
            public var code: InvarianceCode { .custom("unsafe_token") }
            public var message: String { "not a safe token: \(detail)" }
        }

        public let raw: String

        public init(_ raw: String) throws(InvarianceFailure) {
            if let detail = TextPolicy.token.violation(raw) {
                throw InvarianceFailure(.init(Rejected(detail: detail), path: [.field("token")]))
            }
            self.raw = raw
        }

        /// `raw` when it is safe, otherwise nil.
        public static func or(_ raw: String?) -> String? {
            guard let raw else { return nil }
            return (try? SafeToken(raw))?.raw
        }
    }

    /// Whether the presets find nothing in `text`.
    static func isClean(_ text: String, presets: [Preset] = Preset.all, known: [Known] = []) -> Bool {
        scan(text, presets: presets, known: known).isEmpty
    }
}

private extension String {
    var trimmingWhitespace: Substring {
        let start = firstIndex { !$0.isWhitespace } ?? endIndex
        let end = lastIndex { !$0.isWhitespace }.map(index(after:)) ?? start
        return self[start..<end]
    }
}
