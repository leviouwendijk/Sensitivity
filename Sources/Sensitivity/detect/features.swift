public extension Sensitivity {
    /// Which trigger characters a text holds, from one pass over its bytes.
    /// A detector names the ones its matches cannot do without, and a scan
    /// skips it when the text lacks them: no `@`, no mail search.
    struct Features: OptionSet, Sendable, Hashable {
        public let rawValue: UInt16

        public init(rawValue: UInt16) {
            self.rawValue = rawValue
        }

        public static let digit = Self(rawValue: 1 << 0)
        public static let at = Self(rawValue: 1 << 1)
        public static let colon = Self(rawValue: 1 << 2)
        public static let slash = Self(rawValue: 1 << 3)
        public static let dash = Self(rawValue: 1 << 4)
        public static let dot = Self(rawValue: 1 << 5)
        /// `:` or `=`, as assignments use.
        public static let assignment = Self(rawValue: 1 << 6)

        /// The features of `text`.
        public init(of text: String) {
            var features: Features = []
            for byte in text.utf8 {
                switch byte {
                case 0x30...0x39: features.insert(.digit)
                case 0x40: features.insert(.at)
                case 0x3A: features.formUnion([.colon, .assignment])
                case 0x3D: features.insert(.assignment)
                case 0x2F: features.insert(.slash)
                case 0x2D: features.insert(.dash)
                case 0x2E: features.insert(.dot)
                default: continue
                }
            }
            self = features
        }
    }
}
