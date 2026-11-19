import Foundation
import Matching
import Tokens

public extension Sensitivity {
    /// Finds one kind of sensitive data.
    protocol Detector: Sendable {
        var name: String { get }
        /// Characters every match contains; a scan skips the detector for a
        /// text without them.
        var requires: Features { get }
        func findings(in subject: RegexSubject) -> [Finding]
    }

    /// A regular expression (ICU), compiled once, with a kind and a score;
    /// `assess` may rescore a match or drop it (nil), for checks a pattern
    /// cannot make (a checksum, octet ranges, character mix).
    struct Pattern: Detector {
        public let name: String
        public let kind: Kind
        public let pattern: String
        public let score: Score
        public let reason: String
        public let caseSensitive: Bool
        /// The part of the match that is sensitive: `.named("value")` for
        /// `name = (?<value>…)`, so the name stays readable.
        public let group: RegexGroup
        public let requires: Features
        public let assess: (@Sendable (String) -> Score?)?
        private let compiled: CompiledRegex?

        public init(
            _ name: String,
            kind: Kind,
            pattern: String,
            score: Int,
            reason: String,
            caseSensitive: Bool = false,
            group: RegexGroup = .whole,
            requires: Features = [],
            assess: (@Sendable (String) -> Score?)? = nil
        ) {
            self.name = name
            self.kind = kind
            self.pattern = pattern
            self.score = Score(clamping: score)
            self.reason = reason
            self.caseSensitive = caseSensitive
            self.group = group
            self.requires = requires
            self.assess = assess
            self.compiled = CompiledRegex(pattern, case: TokenCaseOptions(sensitivity: caseSensitive ? .sensitive : .insensitive))
        }

        /// Whether the pattern compiles; one that does not finds nothing.
        public var isValid: Bool {
            compiled != nil
        }

        public func findings(in subject: RegexSubject) -> [Finding] {
            guard let compiled else { return [] }
            return compiled.matches(in: subject, group: group).compactMap { match in
                let score: Score
                if let assess {
                    guard let assessed = assess(match.text) else { return nil }
                    score = assessed
                } else {
                    score = self.score
                }
                return Finding(kind: kind, range: match.range, text: match.text, score: score, detector: name, reason: reason)
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

    /// Finds known values with one expression for all of them (longest
    /// first, so "Noor de Vries" wins over "Noor").
    struct KnownValues: Detector {
        public let name = "known"
        public let requires: Features = []
        public let values: [Known]
        private let compiled: CompiledRegex?
        private let byValue: [String: Known]

        public init(_ values: [Known]) {
            self.values = values
            var byValue: [String: Known] = [:]
            for known in values {
                let value = known.value.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !value.isEmpty else { continue }
                // The first declaration of a value wins.
                if byValue[value.lowercased()] == nil {
                    byValue[value.lowercased()] = known
                }
            }
            self.byValue = byValue
            let alternatives = byValue.keys
                .sorted { $0.count != $1.count ? $0.count > $1.count : $0 < $1 }
                .map(RegexPattern.escaped)
            // Letters and digits on either side mean another word.
            self.compiled = alternatives.isEmpty
                ? nil
                : CompiledRegex("(?<![\\p{L}\\p{N}])(?:" + alternatives.joined(separator: "|") + ")(?![\\p{L}\\p{N}])")
        }

        public func findings(in subject: RegexSubject) -> [Finding] {
            guard let compiled else { return [] }
            return compiled.matches(in: subject).compactMap { match in
                guard let known = byValue[match.text.lowercased()] else { return nil }
                return Finding(
                    kind: known.kind,
                    range: match.range,
                    text: match.text,
                    score: Score(clamping: 90),
                    detector: name,
                    reason: known.reason
                )
            }
        }
    }
}

public extension Sensitivity.Detector {
    func findings(in text: String) -> [Sensitivity.Finding] {
        findings(in: RegexSubject(text))
    }
}
