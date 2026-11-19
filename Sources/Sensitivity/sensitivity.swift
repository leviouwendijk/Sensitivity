import Matching

/// Finds sensitive data in text, scores how sure each finding is, and
/// replaces findings with stand-ins.
///
///     let findings = Sensitivity.scan(text, presets: Sensitivity.Preset.all)
///     var redactor = Sensitivity.Redactor(method: .pseudonym)
///     let scrubbed = redactor.apply(findings, to: text)
///
/// Presets cover what is sensitive anywhere (keys, contacts, IBANs, private
/// addresses); known values cover what is sensitive in context (a client's
/// name, a dog's name).
public enum Sensitivity {}

public extension Sensitivity {
    /// Every finding of the presets' detectors and the known values in
    /// `text`, without overlaps (the higher score wins, then the longer
    /// finding), in text order.
    static func scan(
        _ text: String,
        presets: [Preset] = Preset.all,
        known: [Known] = []
    ) -> [Finding] {
        var detectors = presets.flatMap(\.detectors)
        if !known.isEmpty {
            detectors.append(KnownValues(known))
        }
        return resolvingOverlaps(detectors.flatMap { $0.findings(in: text) })
    }

    /// Keeps, of findings that overlap, the one with the highest score (then
    /// the longest, then the earliest).
    static func resolvingOverlaps(_ findings: [Finding]) -> [Finding] {
        let ranked = findings.sorted { a, b in
            if a.score != b.score { return a.score > b.score }
            if a.range.offsetRange.count != b.range.offsetRange.count {
                return a.range.offsetRange.count > b.range.offsetRange.count
            }
            return a.range.startOffset < b.range.startOffset
        }
        var kept: [Finding] = []
        for finding in ranked where !kept.contains(where: { $0.range.offsetRange.overlaps(finding.range.offsetRange) }) {
            kept.append(finding)
        }
        return kept.sorted { $0.range.startOffset < $1.range.startOffset }
    }
}

extension String {
    /// The text at character offsets `range`.
    func text(at range: MatchRange) -> String {
        let start = index(startIndex, offsetBy: range.startOffset)
        let end = index(start, offsetBy: range.offsetRange.count)
        return String(self[start..<end])
    }
}
