public extension Sensitivity {
    /// `value` with every letter and digit but the last `keeping` replaced
    /// by `*`; separators stay. Values with no more than `keeping` letters
    /// and digits are masked entirely.
    static func mask(_ value: String, keeping: Int = 4) -> String {
        let total = value.filter { $0.isLetter || $0.isNumber }.count
        let shown = total > keeping ? keeping : 0
        var remaining = total
        return String(value.map { character in
            guard character.isLetter || character.isNumber else { return character }
            remaining -= 1
            return remaining < shown ? character : "*"
        })
    }
}
