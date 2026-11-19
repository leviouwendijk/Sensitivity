import Sensitivity
import Testing

/// Named secrets, payments, network ranges, masking, redacted values and
/// allowlist projection. All values are invented.
extension SensitivityTests {
    static func namedSecretsValueOnly() throws {
        let text = """
            export MAIL_PASSWORD_SAM_HM=k3yfor5am
            Authorization: Bearer 3f786850e387550fdab836ed7e6dc881de23001b
            X-Bunq-Client-Authentication: 0a1b2c3d4e5f60718293a4b5c6d7e8f9
            {"access_token": "deadbeefcafe1234"}
            git checkout 3f786850e387550fdab836ed7e6dc881de23001c
            """
        let texts = Sensitivity.scan(text, presets: [.secrets]).map(\.text)
        try Expect.equal(
            texts,
            [
                "k3yfor5am",
                "3f786850e387550fdab836ed7e6dc881de23001b",
                "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
                "deadbeefcafe1234",
            ],
            "values named by env, header or key, without their names; a bare hash is left alone"
        )
    }

    static func paymentsAndBIC() throws {
        let text = "Login AT-1234-5678 for SL-8765-4321; BIC: ABNANL2A. Swift code generator."
        let findings = Sensitivity.scan(text, presets: [.payments, .financial])
        try Expect.equal(findings.map(\.text), ["AT-1234-5678", "SL-8765-4321", "ABNANL2A"], "AT code, service id, labelled BIC; not prose")
        try Expect.equal(findings.map(\.kind), [.secret, .identifier, .financial], "kinds per payment value")
    }

    static func networkRangesWhole() throws {
        let text = "LAN 10.0.0.0/24, host 10.0.0.7, ULA fd12:3456:789a::1, link fe80::1/64"
        let texts = Sensitivity.scan(text, presets: [.network]).map(\.text)
        try Expect.equal(texts, ["10.0.0.0/24", "10.0.0.7", "fd12:3456:789a::1", "fe80::1/64"], "a CIDR is one finding")
    }

    static func scanShortcutsAndPrecision() throws {
        try Expect.equal(Sensitivity.Features(of: "plain words only"), [], "no trigger characters")
        try Expect.true(Sensitivity.Features(of: "a@b.c 1").isSuperset(of: [.at, .dot, .digit]), "triggers found")

        let addresses = Sensitivity.scan("10.0.0.300 and 10.0.0.30 and 10.0.0.0/33 and 192.168.0.0/16", presets: [.network]).map(\.text)
        try Expect.equal(
            addresses,
            ["10.0.0.30", "10.0.0.0", "192.168.0.0/16"],
            "an octet above 255 is no address; a prefix above 32 is no range, though its address still counts"
        )

        let known = [
            Sensitivity.Known("Noor", reason: "client"),
            Sensitivity.Known("Noor de Vries", reason: "client, full name"),
            Sensitivity.Known("noor", reason: "duplicate"),
        ]
        let findings = Sensitivity.scan("Noor de Vries and noor.", presets: [], known: known)
        try Expect.equal(findings.map(\.text), ["Noor de Vries", "noor"], "the longest known value wins")
        try Expect.equal(findings.map(\.reason), ["client, full name", "client"], "the first declaration of a value wins")

        let mail = "to first.last+tag@sub.example.co.uk, x@example.nl. Not a@b, @example.nl, user@localhost or ä@é.nl; then sam@example.nl"
        try Expect.equal(
            Sensitivity.scan(mail, presets: [.contacts]).map(\.text),
            ["first.last+tag@sub.example.co.uk", "x@example.nl", "sam@example.nl"],
            "addresses need a local part and a dotted domain ending in letters; a trailing dot is left out"
        )
        let tokens = "short Ab1 \(String(repeating: "aB3", count: 14)) \(String(repeating: "ab3", count: 14))"
        try Expect.equal(
            Sensitivity.scan(tokens, presets: [.secrets]).map(\.text),
            [String(repeating: "aB3", count: 14)],
            "a long run with mixed case and digits; lowercase hex-like runs are left"
        )

        for pattern in Sensitivity.Preset.all.flatMap(\.detectors).compactMap({ $0 as? Sensitivity.Pattern }) {
            try Expect.true(pattern.isValid, "\(pattern.name) compiles")
        }
    }

    static func masking() throws {
        try Expect.equal(Sensitivity.mask("NL91 ABNA 0417 1643 00"), "**** **** **** **43 00", "last four kept, separators kept")
        try Expect.equal(Sensitivity.mask("abc"), "***", "short values fully masked")

        let text = "Pay to NL91ABNA0417164300."
        var redactor = Sensitivity.Redactor(method: .mask)
        try Expect.equal(
            redactor.apply(Sensitivity.scan(text, presets: [.financial]), to: text).text,
            "Pay to **************4300.",
            "the mask method"
        )
    }

    struct DemoKey: Sensitivity.Redacted {
        static let redactedLabel = "demo key"
        let raw: String
    }

    struct Holder {
        let name: String
        let key: DemoKey
    }

    static func redactedValuesNeverShow() throws {
        let key = DemoKey(raw: "s3cr3t-value")
        try Expect.equal("\(key)", "<redacted demo key>", "interpolation")
        try Expect.equal(String(reflecting: key), "<redacted demo key>", "debug description")
        try Expect.equal(Mirror(reflecting: key).children.count, 0, "reflection sees nothing")

        var dumped = ""
        dump(Holder(name: "sam", key: key), to: &dumped)
        try Expect.false(dumped.contains("s3cr3t"), "dump of a holder: \(dumped)")
        try Expect.false("\(Holder(name: "sam", key: key))".contains("s3cr3t"), "a holder's description")
    }

    static func safeLabelsAllowlist() throws {
        try Expect.equal(try Sensitivity.SafeLabel("Main LAN_2-guest").raw, "Main LAN_2-guest", "letters, digits, space, - and _")
        for unsafe in ["lan 10.0.0.1", "nas.example.lan", "https://x", "fd12::1", "  ", String(repeating: "a", count: 65), "café"] {
            try Expect.throwsError("rejected: \(unsafe)") { _ = try Sensitivity.SafeLabel(unsafe) }
        }
        try Expect.equal(Sensitivity.SafeLabel.or("lan 10.0.0.1", fallback: "network 3"), "network 3", "fallback when unsafe")
        try Expect.equal(Sensitivity.SafeLabel.or(nil, fallback: "network 3"), "network 3", "fallback when absent")

        try Expect.equal(Sensitivity.SafeToken.or("ALLOW_RETURN"), "ALLOW_RETURN", "an enum-like token")
        try Expect.isNil(Sensitivity.SafeToken.or("allow return"), "no spaces in a token")

        let screened = Sensitivity.TextPolicy(maximumLength: 80, allowsSpace: true, punctuation: ["@", "."], screenedBy: ["contacts"])
        try Expect.notNil(screened.violation("mail sam@example.nl"), "screened by the contacts preset")
        try Expect.isNil(screened.violation("version 1.2"), "clean text passes")
        try Expect.true(Sensitivity.isClean("Main LAN"), "nothing found")
    }
}
