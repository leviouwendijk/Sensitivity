import Sensitivity
import Testing

/// Every person, address and number here is invented. NL91ABNA0417164300 is
/// the IBAN standard's documentation example.
enum SensitivityTests {
    static let note = """
        Intake for Noor de Vries (noor.devries@example.com, 06 00 00 00 00) and Pip.
        Invoice to NL91 ABNA 0417 1643 00, Teststraat 1, 1234 AB Testdorp.
        """

    static func contactsFoundWithOffsets() throws {
        let findings = Sensitivity.scan(note, presets: [.contacts])
        let texts = findings.map(\.text)
        try Expect.contains(texts, "noor.devries@example.com", "the mail address: \(texts)")
        try Expect.contains(texts, "06 00 00 00 00", "the mobile number with its spaces: \(texts)")
        try Expect.contains(texts, "1234 AB", "the postcode: \(texts)")

        let mail = try Expect.notNil(findings.first { $0.detector == "contacts.email" }, "a mail finding")
        let start = note.index(note.startIndex, offsetBy: mail.range.startOffset)
        try Expect.true(note[start...].hasPrefix("noor.devries@"), "offsets are character offsets into the text")
    }

    static func ibanChecksumScores() throws {
        let valid = try Expect.notNil(
            Sensitivity.scan(note, presets: [.financial]).first,
            "the IBAN is found with its spaces"
        )
        try Expect.equal(valid.text, "NL91 ABNA 0417 1643 00", "the whole IBAN")
        try Expect.equal(valid.score.raw, 97, "a valid checksum is near certain")

        let wrong = try Expect.notNil(
            Sensitivity.scan("Rekening NL92ABNA0417164300.", presets: [.financial]).first,
            "an IBAN-shaped value is still found"
        )
        try Expect.equal(wrong.score.raw, 45, "a wrong checksum lowers the score")

        try Expect.equal(try Sensitivity.IBAN("nl91 abna 0417 1643 00").raw, "NL91ABNA0417164300", "normalized to compact upper case")
        try Expect.throwsError("a wrong checksum does not construct") { _ = try Sensitivity.IBAN("NL92ABNA0417164300") }
        try Expect.throwsError("too short does not construct") { _ = try Sensitivity.IBAN("NL91ABNA") }
        try Expect.throwsError("a score above 100 does not construct") { _ = try Sensitivity.Score(101) }
    }

    static func secretsValueOnlyAndHashesIgnored() throws {
        let config = """
            api_key = "sk_test_Abc123Def456Ghi789"
            password: hunter2hunter2
            commit 3f786850e387550fdab836ed7e6dc881de23001b
            token 9fQ2xLm7Rk4Tz8Wb1Nc6Vd3Hs5Jp0Ya2Ue7Io9KgXq4
            -----BEGIN OPENSSH PRIVATE KEY-----
            """
        let findings = Sensitivity.scan(config, presets: [.secrets])
        let texts = findings.map(\.text)
        try Expect.contains(texts, "sk_test_Abc123Def456Ghi789", "the assigned value, without its name or quotes: \(texts)")
        try Expect.contains(texts, "hunter2hunter2", "a password after a colon: \(texts)")
        try Expect.contains(texts, "9fQ2xLm7Rk4Tz8Wb1Nc6Vd3Hs5Jp0Ya2Ue7Io9KgXq4", "a long mixed-case token: \(texts)")
        try Expect.true(findings.contains { $0.detector == "secrets.pem" }, "the PEM header")
        try Expect.false(texts.contains("3f786850e387550fdab836ed7e6dc881de23001b"), "a commit hash is not a secret: \(texts)")
    }

    static func networkAndLinks() throws {
        let log = """
            from 10.20.30.40 and 192.168.1.15 via aa:bb:cc:dd:ee:ff; public 8.8.8.8
            open https://example.com/accept?id=7&token=Zx81Qp
            """
        let texts = Sensitivity.scan(log, presets: [.network, .links]).map(\.text)
        try Expect.contains(texts, "10.20.30.40", "a 10/8 address: \(texts)")
        try Expect.contains(texts, "192.168.1.15", "a 192.168/16 address: \(texts)")
        try Expect.contains(texts, "aa:bb:cc:dd:ee:ff", "a MAC address: \(texts)")
        try Expect.false(texts.contains("8.8.8.8"), "a public address is not private: \(texts)")
        try Expect.contains(texts, "https://example.com/accept?id=7&token=Zx81Qp", "a URL with a token: \(texts)")
    }

    static func knownValuesWholeWords() throws {
        let known = [
            Sensitivity.Known("Noor", reason: "client"),
            Sensitivity.Known("Pip", reason: "client's dog"),
            Sensitivity.Known("Zoë", reason: "client"),
        ]
        let text = "NOOR walked Pip along the Noordzee; Pipeline done. Zoë called."
        let findings = Sensitivity.scan(text, presets: [], known: known)
        try Expect.equal(findings.map(\.text), ["NOOR", "Pip", "Zoë"], "whole words, any case, diacritics kept; not Noordzee or Pipeline")
        try Expect.equal(findings.map(\.kind), [.identity, .identity, .identity], "identities by default")
        try Expect.equal(findings.first?.reason, "client", "the reason travels with the finding")
    }

    static func overlapsKeepTheStronger() throws {
        let findings = Sensitivity.scan("Bel +31 6 00000000 vandaag.", presets: [.contacts])
        try Expect.equal(findings.count, 1, "one number, found by two detectors: \(findings.map(\.detector))")
        try Expect.equal(findings.first?.detector, "contacts.phone-nl-mobile", "the higher-scoring detector wins")
    }

    static func replacementMethods() throws {
        let text = "Mail noor@example.com or call 06 00 00 00 00."
        let findings = Sensitivity.scan(text, presets: [.contacts])

        var preserve = Sensitivity.Redactor(method: .preserve)
        try Expect.equal(preserve.apply(findings, to: text).text, "Mail aaaa@aaaaaaa.aaa or call 00 00 00 00 00.", "shape kept")

        var verbose = Sensitivity.Redactor(method: .verbose)
        try Expect.equal(verbose.apply(findings, to: text).text, "Mail [CONTACT] or call [CONTACT].", "kind named")

        var redact = Sensitivity.Redactor(method: .redact)
        let redacted = redact.apply(findings, to: text)
        try Expect.equal(redacted.text, "Mail [REDACTED] or call [REDACTED].", "plainly redacted")
        try Expect.equal(redacted.replacements.map(\.original), ["noor@example.com", "06 00 00 00 00"], "the mapping keeps the originals, in order")
    }

    static func pseudonymsConsistentAcrossTexts() throws {
        let known = [Sensitivity.Known("Noor", reason: "client"), Sensitivity.Known("Sam", reason: "client")]
        var redactor = Sensitivity.Redactor(method: .pseudonym)

        let first = "Noor asked about Sam; noor@example.com."
        let second = "Sam replied to Noor."
        let a = redactor.apply(Sensitivity.scan(first, presets: [.contacts], known: known), to: first)
        let b = redactor.apply(Sensitivity.scan(second, presets: [.contacts], known: known), to: second)

        try Expect.equal(a.text, "Identity A asked about Identity B; Contact A.", "numbered per kind")
        try Expect.equal(b.text, "Identity B replied to Identity A.", "the same value keeps its stand-in in a later text")
    }
}
