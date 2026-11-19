public extension Sensitivity {
    /// How a finding is replaced.
    enum Method: String, Sendable, Codable, Hashable, CaseIterable {
        /// Keeps the shape: digits become 0, letters a, the rest stays.
        case preserve
        /// Names the kind: `[CONTACT]`, `[SECRET]`.
        case verbose
        /// `[REDACTED]`.
        case redact
        /// A consistent stand-in per value and kind: the same mail address
        /// is `Contact A` wherever it occurs, in every text this redactor
        /// handles.
        case pseudonym
    }

    /// A replaced finding: what stood there and what stands there now.
    /// The mapping is for the owner; it never leaves with the text.
    struct Replacement: Sendable, Codable, Hashable {
        public let kind: Kind
        public let original: String
        public let standIn: String
    }

    struct Redaction: Sendable, Codable, Hashable {
        public let text: String
        public let replacements: [Replacement]
    }

    /// Replaces findings. Keep one redactor for texts that belong together
    /// (a session, a set of files), so pseudonyms stay consistent.
    struct Redactor: Sendable {
        public let method: Method
        private var standIns: [String: String] = [:]
        private var counts: [Kind: Int] = [:]

        public init(method: Method = .pseudonym) {
            self.method = method
        }

        /// `text` with `findings` (from a scan of this text) replaced.
        /// Overlapping findings are resolved first.
        public mutating func apply(_ findings: [Finding], to text: String) -> Redaction {
            let resolved = Sensitivity.resolvingOverlaps(findings)
            var output = ""
            var replacements: [Replacement] = []
            var offset = 0
            var index = text.startIndex
            for finding in resolved {
                let start = text.index(index, offsetBy: finding.range.startOffset - offset)
                let end = text.index(start, offsetBy: finding.range.offsetRange.count)
                output += text[index..<start]
                let original = String(text[start..<end])
                let standIn = standIn(for: original, kind: finding.kind)
                output += standIn
                replacements.append(.init(kind: finding.kind, original: original, standIn: standIn))
                index = end
                offset = finding.range.endOffset
            }
            output += text[index...]
            return Redaction(text: output, replacements: replacements)
        }

        private mutating func standIn(for original: String, kind: Kind) -> String {
            switch method {
            case .preserve:
                return String(original.map { $0.isNumber ? "0" : $0.isLetter ? "a" : $0 })
            case .verbose:
                return "[\(kind.rawValue.uppercased())]"
            case .redact:
                return "[REDACTED]"
            case .pseudonym:
                let key = "\(kind.rawValue)\u{0}\(original.lowercased())"
                if let existing = standIns[key] {
                    return existing
                }
                let number = counts[kind, default: 0]
                counts[kind] = number + 1
                let standIn = "\(kind.rawValue.prefix(1).uppercased())\(kind.rawValue.dropFirst()) \(Self.label(number))"
                standIns[key] = standIn
                return standIn
            }
        }

        /// A, B, ..., Z, AA, AB, ...
        private static func label(_ number: Int) -> String {
            let letters = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            var number = number
            var label = ""
            repeat {
                label = String(letters[number % 26]) + label
                number = number / 26 - 1
            } while number >= 0
            return label
        }
    }
}
