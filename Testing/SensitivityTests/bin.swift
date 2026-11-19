import Testing

private enum SensitivityTestError: Error {
    case failed
}

@main
struct SensitivityTestMain {
    static func main() async throws {
        let reporter = PlainTextTestReporter()
        let result = await TestRunner.run(
            SensitivityTestSuite.testSuite,
            sink: reporter
        )
        let rendered = await reporter.rendered()

        if !rendered.isEmpty {
            print(rendered)
        }

        if result.isFailure {
            throw SensitivityTestError.failed
        }
    }
}

enum SensitivityTestSuite {
    static let testSuite = TestSuite(
        "sensitivity",
        title: "Sensitivity: detection, scoring, replacement"
    ) {
        Test("contacts-found-with-offsets", tags: ["detect", "contacts"]) {
            try SensitivityTests.contactsFoundWithOffsets()
        }

        Test("iban-checksum-scores", tags: ["detect", "financial", "invariant"]) {
            try SensitivityTests.ibanChecksumScores()
        }

        Test("secrets-value-only-and-hashes-ignored", tags: ["detect", "secrets"]) {
            try SensitivityTests.secretsValueOnlyAndHashesIgnored()
        }

        Test("network-and-links", tags: ["detect", "network", "links"]) {
            try SensitivityTests.networkAndLinks()
        }

        Test("known-values-whole-words", tags: ["detect", "known"]) {
            try SensitivityTests.knownValuesWholeWords()
        }

        Test("overlaps-keep-the-stronger", tags: ["detect"]) {
            try SensitivityTests.overlapsKeepTheStronger()
        }

        Test("replacement-methods", tags: ["replace"]) {
            try SensitivityTests.replacementMethods()
        }

        Test("pseudonyms-consistent-across-texts", tags: ["replace"]) {
            try SensitivityTests.pseudonymsConsistentAcrossTexts()
        }
    }
}
