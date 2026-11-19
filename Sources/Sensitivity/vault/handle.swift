import Foundation
import Matching

public extension Sensitivity {
    /// Stands in for a sensitive value wherever a model reads or a session
    /// records it: `⟦contact:7f3a91c2⟧`. The value stays in a `Vault`; tools
    /// that may use it get it back inside their own call.
    struct Handle: Sendable, Codable, Hashable, CustomStringConvertible {
        public let kind: Kind
        /// Eight lowercase hex digits, unique in its vault.
        public let id: String

        public init(kind: Kind, id: String) {
            self.kind = kind
            self.id = id
        }

        /// The form in text.
        public var token: String {
            "⟦\(kind.rawValue):\(id)⟧"
        }

        public var description: String {
            token
        }

        static let pattern = "⟦([a-z]+):([0-9a-f]{8})⟧"
        private static let expression = CompiledRegex(pattern, case: .init(sensitivity: .sensitive))

        /// Every handle written in `text`, with its character range.
        public static func occurrences(in text: String) -> [(handle: Handle, range: MatchRange)] {
            guard text.contains("⟦"), let expression else { return [] }
            return expression.matches(in: text).compactMap { match in
                // "⟦kind:id⟧": the kind and id lie between the brackets.
                let inner = match.text.dropFirst().dropLast()
                guard let colon = inner.firstIndex(of: ":"),
                      let kind = Kind(rawValue: String(inner[..<colon]))
                else {
                    return nil
                }
                return (Handle(kind: kind, id: String(inner[inner.index(after: colon)...])), match.range)
            }
        }
    }

    /// A handle as the owner may see it: what is known about it and its value.
    struct DisplayEntry: Sendable, Hashable {
        public let description: HandleDescription
        public let value: String
        public let expires: Date?

        public init(description: HandleDescription, value: String, expires: Date?) {
            self.description = description
            self.value = value
            self.expires = expires
        }
    }

    /// How a handle may be used. Decided per kind by a `ShieldPolicy`.
    enum Tier: String, Sendable, Codable, Hashable, CaseIterable {
        /// A handle any tool may resolve: identifiers, private addresses.
        case soft
        /// A handle only related tools may resolve, or one the owner granted.
        case handle
        /// Left in the text, listed for review; too uncertain to replace.
        case flag
    }

    /// What may be known about a handle without its value.
    struct HandleDescription: Sendable, Codable, Hashable {
        public let handle: Handle
        public let tier: Tier
        /// Masked, as in `**** 4300`.
        public let preview: String
        public let detector: String
        public let reason: String
        public let score: Int
        /// Where it was seen: tool and field path, first sighting first.
        public let sources: [String]
        /// Tools the owner allowed to use it.
        public let grants: [String]
    }
}
