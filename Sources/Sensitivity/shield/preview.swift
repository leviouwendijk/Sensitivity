public extension Sensitivity {
    /// A protection as the owner reviews it: a header with the verdict and
    /// counts, the changed fields first (values masked), then the payload
    /// exactly as it leaves.
    static func preview(source: String, protection: Protection, payload: String) -> String {
        let replaced = protection.items.filter { $0.handle != nil }
        let flagged = protection.items.filter { $0.handle == nil }
        let verdict = replaced.isEmpty && flagged.isEmpty
            ? "clean"
            : "\(replaced.count) replaced" + (flagged.isEmpty ? "" : ", \(flagged.count) flagged")
        let counts = protection.counts
            .sorted { $0.key.rawValue < $1.key.rawValue }
            .map { "\($0.key.rawValue) \($0.value)" }
            .joined(separator: " · ")

        var lines = ["## \(source): \(verdict)"]
        if !counts.isEmpty {
            lines.append(counts)
        }
        if !protection.items.isEmpty {
            lines.append("")
            lines.append("| path | tier | original | stand-in | why |")
            lines.append("|---|---|---|---|---|")
            for item in replaced + flagged {
                let path = item.path.isEmpty ? "(text)" : item.path
                let standIn = item.handle?.token ?? "kept"
                lines.append("| \(path) | \(item.tier.rawValue) | \(item.preview) | \(standIn) | \(item.reason), \(item.score) |")
            }
        }
        lines.append("")
        lines.append("```")
        lines.append(payload)
        lines.append("```")
        return lines.joined(separator: "\n")
    }
}
