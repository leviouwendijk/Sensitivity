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
    /// finding), in text order. Detectors whose trigger characters the text
    /// lacks are skipped.
    static func scan(
        _ text: String,
        presets: [Preset] = Preset.all,
        known: [Known] = []
    ) -> [Finding] {
        var detectors = presets.flatMap(\.detectors)
        if !known.isEmpty {
            detectors.append(KnownValues(known))
        }
        return scan(text, detectors: detectors)
    }

    /// `scan` with prepared detectors; keep a `KnownValues` and reuse it
    /// for many texts rather than rebuilding it per text.
    static func scan(_ text: String, detectors: [any Detector]) -> [Finding] {
        let features = Features(of: text)
        let applicable = detectors.filter { features.isSuperset(of: $0.requires) }
        guard !applicable.isEmpty else { return [] }
        // Prepared once for every detector.
        let subject = RegexSubject(text)
        let found = applicable.flatMap { $0.findings(in: subject) }
        return resolvingOverlaps(found)
    }

    /// Keeps, of findings that overlap, the one with the highest score (then
    /// the longest, then the earliest). Findings are swept in text order;
    /// only each run of overlapping findings is ranked.
    static func resolvingOverlaps(_ findings: [Finding]) -> [Finding] {
        let ordered = findings.sorted {
            $0.range.startOffset != $1.range.startOffset
                ? $0.range.startOffset < $1.range.startOffset
                : $0.range.endOffset > $1.range.endOffset
        }
        var kept: [Finding] = []
        var cluster: [Finding] = []
        var clusterEnd = 0
        for finding in ordered {
            if !cluster.isEmpty, finding.range.startOffset >= clusterEnd {
                kept += rankedWithoutOverlap(cluster)
                cluster = []
            }
            cluster.append(finding)
            clusterEnd = cluster.count == 1 ? finding.range.endOffset : max(clusterEnd, finding.range.endOffset)
        }
        kept += rankedWithoutOverlap(cluster)
        return kept
    }

    private static func rankedWithoutOverlap(_ cluster: [Finding]) -> [Finding] {
        guard cluster.count > 1 else { return cluster }
        let ranked = cluster.sorted { a, b in
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
