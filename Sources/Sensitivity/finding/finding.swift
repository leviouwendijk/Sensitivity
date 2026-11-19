import Matching
import Primitives

public extension Sensitivity {
    /// What a finding is.
    enum Kind: String, Sendable, Codable, Hashable, CaseIterable {
        /// Keys, tokens, passwords, private keys.
        case secret
        /// Mail addresses, phone numbers, postcodes.
        case contact
        /// IBANs and other payment details.
        case financial
        /// Private IP and MAC addresses.
        case network
        /// URLs that carry access (tokens, signatures).
        case link
        /// Account, customer, merchant and service identifiers.
        case identifier
        /// A person, animal or organization named in context.
        case identity
    }

    /// How sure a detector is that a finding is sensitive: 0 (a guess) to
    /// 100 (certain).
    struct Score: CodableInvariant, Sendable, Hashable, Comparable {
        public static let range = 0...100

        public let raw: Int

        public init(_ raw: Int) throws(InvarianceFailure) {
            guard raw >= Self.range.lowerBound else {
                throw InvarianceFailure(.init(InvarianceBelowMinimum(minimum: Self.range.lowerBound, actual: raw), path: [.field("score")]))
            }
            guard raw <= Self.range.upperBound else {
                throw InvarianceFailure(.init(InvarianceAboveMaximum(maximum: Self.range.upperBound, actual: raw), path: [.field("score")]))
            }
            self.raw = raw
        }

        /// For scores written in code: clamps instead of throwing.
        public init(clamping raw: Int) {
            self.raw = min(max(raw, Self.range.lowerBound), Self.range.upperBound)
        }

        public static func < (lhs: Self, rhs: Self) -> Bool {
            lhs.raw < rhs.raw
        }
    }

    /// One piece of sensitive data in a text.
    struct Finding: Sendable, Codable, Hashable {
        public let kind: Kind
        /// Character offsets in the scanned text.
        public let range: MatchRange
        public let text: String
        public let score: Score
        /// The detector that found it, such as `contacts.email`.
        public let detector: String
        /// Why it counts, for a reviewer.
        public let reason: String

        public init(kind: Kind, range: MatchRange, text: String, score: Score, detector: String, reason: String) {
            self.kind = kind
            self.range = range
            self.text = text
            self.score = score
            self.detector = detector
            self.reason = reason
        }
    }
}
