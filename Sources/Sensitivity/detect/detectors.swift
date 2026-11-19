import Foundation
import Matching
import Tokens

public extension Sensitivity {
    /// Finds one kind of sensitive data.
    protocol Detector: Sendable {
        var name: String { get }
        func findings(in text: String) -> [Finding]
    }

    /// A regular expression (ICU) with a kind and a score; `assess` may
    /// rescore a match or drop it (nil), for checks a pattern cannot make.
    struct Pattern: Detector {
        public let name: String
        public let kind: Kind
        public let pattern: String
        public let score: Score
        public let reason: String
        public let caseSensitive: Bool
        public let assess: (@Sendable (String) -> Score?)?

        public init(
            _ name: String,
            kind: Kind,
            pattern: String,
            score: Int,
            reason: String,
            caseSensitive: Bool = false,
            assess: (@Sendable (String) -> Score?)? = nil
        ) {
            self.name = name
            self.kind = kind
            self.pattern = pattern
            self.score = Score(clamping: score)
            self.reason = reason
            self.caseSensitive = caseSensitive
            self.assess = assess
        }

        public func findings(in text: String) -> [Finding] {
            let options = TokenCaseOptions(sensitivity: caseSensitive ? .sensitive : .insensitive)
            return RegexPattern.ranges(pattern, in: text, case: options).compactMap { range in
                let matched = text.text(at: range)
                let score: Score
                if let assess {
                    guard let assessed = assess(matched) else { return nil }
                    score = assessed
                } else {
                    score = self.score
                }
                return Finding(kind: kind, range: range, text: matched, score: score, detector: name, reason: reason)
            }
        }
    }

    /// A value that is sensitive in context: a client's or teammate's name,
    /// a dog's name, an address. Matched as a whole word, ignoring case.
    struct Known: Sendable, Codable, Hashable {
        public let value: String
        public let kind: Kind
        /// Why it is sensitive, such as "client" or "team".
        public let reason: String

        public init(_ value: String, kind: Kind = .identity, reason: String) {
            self.value = value
            self.kind = kind
            self.reason = reason
        }
    }

    /// Finds known values.
    struct KnownValues: Detector {
        public let name = "known"
        public let values: [Known]

        public init(_ values: [Known]) {
            self.values = values
        }

        public func findings(in text: String) -> [Finding] {
            values.flatMap { known -> [Finding] in
                let value = known.value.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !value.isEmpty else { return [] }
                // Letters and digits on either side mean another word.
                let pattern = "(?<![\\p{L}\\p{N}])" + RegexPattern.escaped(value) + "(?![\\p{L}\\p{N}])"
                return RegexPattern.ranges(pattern, in: text).map { range in
                    Finding(
                        kind: known.kind,
                        range: range,
                        text: text.text(at: range),
                        score: Score(clamping: 90),
                        detector: name,
                        reason: known.reason
                    )
                }
            }
        }
    }
}
