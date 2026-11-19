import Matching

public extension Sensitivity {
    /// A detector that walks the text's UTF-8 bytes itself instead of
    /// running a regular expression: for shapes that anchor on one byte
    /// (`@` for mail) or are plain runs (tokens), where a regex would retry
    /// from every position. `scan` returns ascending, non-overlapping byte
    /// ranges.
    struct Scanner: Detector {
        public typealias Scan = @Sendable (UnsafeBufferPointer<UInt8>) -> [Range<Int>]

        public let name: String
        public let kind: Kind
        public let score: Score
        public let reason: String
        public let requires: Features
        public let scan: Scan
        public let assess: (@Sendable (String) -> Score?)?

        public init(
            _ name: String,
            kind: Kind,
            score: Int,
            reason: String,
            requires: Features = [],
            assess: (@Sendable (String) -> Score?)? = nil,
            scan: @escaping Scan
        ) {
            self.name = name
            self.kind = kind
            self.score = Score(clamping: score)
            self.reason = reason
            self.requires = requires
            self.assess = assess
            self.scan = scan
        }

        public func findings(in subject: RegexSubject) -> [Finding] {
            let text = subject.text
            let ranges = text.utf8.withContiguousStorageIfAvailable(scan) ?? Array(text.utf8).withUnsafeBufferPointer(scan)
            var walk = UTF8Walk(text)
            return ranges.compactMap { bytes in
                let (range, matched) = walk.advance(to: bytes)
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
}

/// Converts ascending UTF-8 byte ranges of a text to character offsets and
/// text in one forward walk.
struct UTF8Walk {
    let text: String
    private var index: String.Index
    private var byte = 0
    private var offset = 0

    init(_ text: String) {
        self.text = text
        self.index = text.startIndex
    }

    mutating func advance(to bytes: Range<Int>) -> (MatchRange, String) {
        let lower = text.utf8.index(index, offsetBy: bytes.lowerBound - byte)
        let upper = text.utf8.index(lower, offsetBy: bytes.count)
        let start = offset + text.distance(from: index, to: lower)
        let length = text.distance(from: lower, to: upper)
        index = upper
        byte = bytes.upperBound
        offset = start + length
        return (MatchRange(uncheckedStart: start, uncheckedEnd: start + length), String(text[lower..<upper]))
    }
}

/// Byte scanners for the presets.
enum ByteScan {
    @inline(__always)
    static func isAlphanumeric(_ byte: UInt8) -> Bool {
        (0x30...0x39).contains(byte) || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
    }

    @inline(__always)
    static func isLetter(_ byte: UInt8) -> Bool {
        (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
    }

    /// `local@domain.tld`: the local part of letters, digits and `._%+-`,
    /// the domain of letters, digits, `.` and `-`, ending in a label of at
    /// least two letters. Only `@` bytes start a look.
    static func mailAddresses(_ bytes: UnsafeBufferPointer<UInt8>) -> [Range<Int>] {
        func isLocal(_ byte: UInt8) -> Bool {
            isAlphanumeric(byte) || byte == 0x2E || byte == 0x5F || byte == 0x25 || byte == 0x2B || byte == 0x2D
        }
        func isDomain(_ byte: UInt8) -> Bool {
            isAlphanumeric(byte) || byte == 0x2E || byte == 0x2D
        }
        // The domain `from..<end` ends in `.` and two or more letters.
        func endsInTLD(_ from: Int, _ end: Int) -> Bool {
            var letters = 0
            var position = end - 1
            while position >= from, isLetter(bytes[position]) {
                letters += 1
                position -= 1
            }
            return letters >= 2 && position > from && bytes[position] == 0x2E
        }

        var found: [Range<Int>] = []
        var previousEnd = 0
        var at = 0
        while at < bytes.count {
            guard bytes[at] == 0x40 else {
                at += 1
                continue
            }
            var start = at
            while start > previousEnd, isLocal(bytes[start - 1]) {
                start -= 1
            }
            var end = at + 1
            while end < bytes.count, isDomain(bytes[end]) {
                end += 1
            }
            // Back off to the longest domain that ends in a top-level label.
            while end > at + 1, !endsInTLD(at + 1, end) {
                end -= 1
            }
            if start < at, end > at + 1 {
                found.append(start..<end)
                previousEnd = end
                at = end
            } else {
                at += 1
            }
        }
        return found
    }

    /// Runs of letters, digits, `_` and `-` at least `minimum` long.
    static func tokenRuns(minimum: Int) -> @Sendable (UnsafeBufferPointer<UInt8>) -> [Range<Int>] {
        { bytes in
            func isToken(_ byte: UInt8) -> Bool {
                isAlphanumeric(byte) || byte == 0x5F || byte == 0x2D
            }
            var found: [Range<Int>] = []
            var position = 0
            while position < bytes.count {
                guard isToken(bytes[position]) else {
                    position += 1
                    continue
                }
                let start = position
                while position < bytes.count, isToken(bytes[position]) {
                    position += 1
                }
                if position - start >= minimum {
                    found.append(start..<position)
                }
            }
            return found
        }
    }
}
