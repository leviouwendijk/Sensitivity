public extension Sensitivity {
    /// A value that must never show: printing, interpolating, debugging or
    /// dumping it gives `<redacted label>`, and reflection sees no children,
    /// so a type holding it does not leak it through its own description.
    ///
    ///     struct APIKey: Sensitivity.Redacted {
    ///         static let redactedLabel = "UniFi API key"
    ///         let raw: String
    ///     }
    protocol Redacted: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        /// What it is, as in `<redacted UniFi API key>`.
        static var redactedLabel: String { get }
    }
}

public extension Sensitivity.Redacted {
    var description: String {
        "<redacted \(Self.redactedLabel)>"
    }

    var debugDescription: String {
        description
    }

    var customMirror: Mirror {
        Mirror(self, children: [], displayStyle: .struct)
    }
}
