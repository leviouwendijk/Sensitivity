import Foundation
import Matching
import Sensitivity

/// Scan throughput on synthetic text: mostly ordinary prose and code, with
/// a sprinkling of invented sensitive values. `SENSITIVITY_BENCH_SAMPLES`
/// sets the samples per size (default 5); the median is reported.
@main
struct SensitivityBenchmark {
    static let paragraph = """
        The intake went well and the next session is planned for the weekend.
        let result = try parser.parse(input, configuration: .defaults) // 42 items
        Mail noor.devries@example.com or call 06 00 00 00 00 about Pip.
        Commit 3f786850e387550fdab836ed7e6dc881de23001b fixed the build on 10.0.0.7.
        Invoice to NL91 ABNA 0417 1643 00; api_key = "sk_test_Abc123Def456Ghi789".
        Nothing sensitive in this line, just words about training and behaviour.

        """

    static let known = [
        Sensitivity.Known("Noor", reason: "client"),
        Sensitivity.Known("Pip", reason: "client's dog"),
        Sensitivity.Known("Sam", reason: "client"),
    ]

    /// Time per detector on 1 MB, slowest first (`SENSITIVITY_BENCH_DETECTORS=1`).
    static func perDetector() {
        let text = String(repeating: paragraph, count: 1_000_000 / paragraph.count + 1)
        let subject = RegexSubject(text)
        var detectors: [any Sensitivity.Detector] = Sensitivity.Preset.all.flatMap(\.detectors)
        detectors.append(Sensitivity.KnownValues(known))
        let clock = ContinuousClock()
        var rows: [(String, Duration, Int)] = []
        for detector in detectors {
            let start = clock.now
            let count = detector.findings(in: subject).count
            rows.append((detector.name, clock.now - start, count))
        }
        for (name, duration, count) in rows.sorted(by: { $0.1 > $1.1 }) {
            print(String(format: "%-34@ %-8d %@", name as NSString, count, "\(duration)" as NSString))
        }
    }

    static func main() {
        if ProcessInfo.processInfo.environment["SENSITIVITY_BENCH_DETECTORS"] == "1" {
            perDetector()
            return
        }
        let samples = max(1, Int(ProcessInfo.processInfo.environment["SENSITIVITY_BENCH_SAMPLES"] ?? "") ?? 5)
        let sizes = [10_000, 100_000, 1_000_000]
        print("size        findings  median      throughput")
        for size in sizes {
            let text = String(repeating: paragraph, count: size / paragraph.count + 1)
            var timings: [Duration] = []
            var findings = 0
            for _ in 0..<samples {
                let clock = ContinuousClock()
                let start = clock.now
                findings = Sensitivity.scan(text, presets: Sensitivity.Preset.all, known: known).count
                timings.append(clock.now - start)
            }
            let median = timings.sorted()[timings.count / 2]
            let seconds = Double(median.components.seconds) + Double(median.components.attoseconds) / 1e18
            let megabytes = Double(text.utf8.count) / 1_000_000
            print(
                String(format: "%-11@ %-9d %-11@ %.2f MB/s", "\(text.utf8.count)B" as NSString, findings, "\(median)" as NSString, megabytes / seconds)
            )
        }
    }
}
