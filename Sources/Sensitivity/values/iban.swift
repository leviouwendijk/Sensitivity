import Primitives

public extension Sensitivity {
    /// An IBAN with a valid ISO 13616 checksum (mod 97 == 1). Raw accepts
    /// spaces and lower case; the value is compact and upper case.
    struct IBAN: CodableInvariant, Sendable, Hashable {
        public struct ChecksumMismatch: InvarianceReason {
            public var code: InvarianceCode { .custom("iban_checksum") }
            public var message: String { "the IBAN's check digits do not match" }
        }

        public struct Malformed: InvarianceReason {
            public var code: InvarianceCode { .custom("iban_format") }
            public var message: String { "an IBAN is a country code, two check digits and 11 to 30 letters or digits" }
        }

        public let raw: String

        public init(_ raw: String) throws(InvarianceFailure) {
            let compact = raw.filter { !$0.isWhitespace }.uppercased()
            let characters = Array(compact)
            guard (15...34).contains(characters.count),
                  characters.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }),
                  characters[0].isLetter, characters[1].isLetter,
                  characters[2].isNumber, characters[3].isNumber
            else {
                throw InvarianceFailure(.init(Malformed(), path: [.field("iban")]))
            }
            // Country and check digits move to the end; letters count as 10...35.
            var remainder = 0
            for character in characters[4...] + characters[..<4] {
                if let digit = character.wholeNumberValue {
                    remainder = (remainder * 10 + digit) % 97
                } else if let ascii = character.asciiValue {
                    remainder = (remainder * 100 + Int(ascii) - 55) % 97
                }
            }
            guard remainder == 1 else {
                throw InvarianceFailure(.init(ChecksumMismatch(), path: [.field("iban")]))
            }
            self.raw = compact
        }
    }
}
