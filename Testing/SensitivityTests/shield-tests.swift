import Foundation
import Primitives
import Sensitivity
import Testing

/// Handles, the vault and the shield. All values are invented.
extension SensitivityTests {
    final class MemoryStore: Sensitivity.VaultStore, @unchecked Sendable {
        private let lock = NSLock()
        private var saved: [Sensitivity.Vault.Entry] = []

        func load() throws -> [Sensitivity.Vault.Entry] { lock.withLock { saved } }
        func save(_ entries: [Sensitivity.Vault.Entry]) throws { lock.withLock { saved = entries } }
        func clear() throws { lock.withLock { saved = [] } }
        var count: Int { lock.withLock { saved.count } }
    }

    static func shieldProtectsWithHandles() async throws {
        let shield = Sensitivity.Shield(vault: Sensitivity.Vault())
        let text = "Mail sam@example.com or 06 00 00 00 00; pay NL91ABNA0417164300 at 1234 AB; host 10.0.0.7."
        let (protected, protection) = await shield.protect(text, source: "mail_read")

        try Expect.false(protected.contains("sam@example.com"), "the address is gone: \(protected)")
        try Expect.false(protected.contains("NL91ABNA0417164300"), "the IBAN is gone")
        try Expect.true(protected.contains("1234 AB"), "a postcode (score 50) is flagged and kept")
        try Expect.equal(Sensitivity.Handle.occurrences(in: protected).count, 4, "four handles: \(protected)")
        try Expect.equal(protection.items.first { $0.kind == .network }?.tier, .soft, "private addresses are soft by policy")
        try Expect.equal(protection.items.first { $0.kind == .financial }?.tier, .handle, "an IBAN is a handle")
        try Expect.equal(protection.items.first { $0.kind == .contact && $0.handle == nil }?.preview, "**34 AB", "flagged items keep a masked preview")

        let again = await shield.protect("Reply to SAM@example.com", source: "mail_read").text
        let first = Sensitivity.Handle.occurrences(in: protected).first { $0.handle.kind == .contact }?.handle
        try Expect.equal(again, "Reply to \(first?.token ?? "?")", "the same address keeps its handle, case aside")
    }

    static func knownValuesCatchEchoes() async throws {
        let shield = Sensitivity.Shield(vault: Sensitivity.Vault())
        _ = await shield.protect("token = s3cr3tValue99", source: "read_files")
        // The bare value has no name before it, so only the vault recognises it.
        let echoed = await shield.protect("the key s3cr3tValue99 again", source: "model")
        try Expect.false(echoed.text.contains("s3cr3tValue99"), "a value seen once is caught everywhere: \(echoed.text)")
        try Expect.equal(echoed.protection.items.first?.detector, "known", "found as a known value")
    }

    static func neverListAndJSONPaths() async throws {
        let policy = Sensitivity.ShieldPolicy(never: ["info@example.com"])
        let shield = Sensitivity.Shield(vault: Sensitivity.Vault(), policy: policy)
        let payload: JSONValue = .object([
            "from": .string("INFO@example.com"),
            "payments": .array([.object(["iban": .string("NL91 ABNA 0417 1643 00"), "amount": .double(12.5)])]),
        ])
        let (protected, protection) = await shield.protect(payload, source: "bunq_payments")
        try Expect.equal(protected.objectValue?["from"], .string("INFO@example.com"), "a public value is never replaced")
        try Expect.equal(protection.items.map(\.path), ["payments[0].iban"], "the path of the replaced field")
        try Expect.equal(protected.objectValue?["payments"]?.arrayValue?.first?.objectValue?["amount"], .double(12.5), "numbers untouched")
    }

    static func resolveInsideTheBoundary() async throws {
        let vault = Sensitivity.Vault()
        let shield = Sensitivity.Shield(vault: vault)
        let protected = await shield.protect("to sam@example.com", source: "mail_read").text
        let handle = try Expect.notNil(Sensitivity.Handle.occurrences(in: protected).first?.handle, "a handle")

        let input: JSONValue = .object(["to": .string(handle.token), "subject": .string("Re: \(handle.token)")])
        let resolved = try await shield.resolve(input, for: "mail_send") { _ in true }
        try Expect.equal(resolved.objectValue?["to"], .string("sam@example.com"), "the value, inside the tool")
        try Expect.equal(resolved.objectValue?["subject"], .string("Re: sam@example.com"), "embedded handles too")

        var refusal: Sensitivity.ShieldFailure?
        do {
            _ = try await shield.resolve(input, for: "web_fetch") { $0.grants.contains("web_fetch") }
        } catch {
            refusal = error
        }
        try Expect.equal(refusal, .notPermitted(handle, tool: "web_fetch"), "a refused handle throws, naming handle and tool")
        try Expect.true(await vault.grant(handle, to: "web_fetch"), "the owner grants it")
        let granted = try await shield.resolve(input, for: "web_fetch") { $0.grants.contains("web_fetch") }
        try Expect.equal(granted.objectValue?["to"], .string("sam@example.com"), "granted now")

        var unknown: Sensitivity.ShieldFailure?
        do {
            _ = try await shield.resolve(.string("⟦contact:00000000⟧"), for: "mail_send") { _ in true }
        } catch {
            unknown = error
        }
        try Expect.equal(unknown, .unknown(.init(kind: .contact, id: "00000000")), "an unknown handle throws")
    }

    static func vaultLifetimeAndStore() async throws {
        let store = MemoryStore()
        let vault = Sensitivity.Vault(lifetime: .seconds(60), store: store)
        let handle = await vault.handle(for: "sam@example.com", kind: .contact, tier: .handle, detector: "t", reason: "t", score: 90, source: "test")
        try Expect.equal(store.count, 1, "saved to the store")

        let reopened = Sensitivity.Vault(store: store)
        try Expect.equal(await reopened.value(of: handle), "sam@example.com", "reloaded from the store")

        await reopened.expire(now: Date().addingTimeInterval(120))
        try Expect.isNil(await reopened.value(of: handle), "expired after its lifetime")

        await vault.clear()
        try Expect.equal(store.count, 0, "cleared with the session")

        try Expect.equal(try store.load().count, 0, "nothing left")
        var dumped = ""
        dump(Sensitivity.SensitiveValue("hunter2hunter2"), to: &dumped)
        try Expect.false(dumped.contains("hunter2"), "a sensitive value never dumps")
    }

    static func unreferencedAndReleased() async throws {
        let store = MemoryStore()
        let vault = Sensitivity.Vault(lifetime: nil, store: store)
        let kept = await vault.handle(for: "sam@example.com", kind: .contact, tier: .handle, detector: "t", reason: "t", score: 90, source: "a", session: "s1")
        let shared = await vault.handle(for: "06 00 00 00 00", kind: .contact, tier: .handle, detector: "t", reason: "t", score: 90, source: "a", session: "s1")
        _ = await vault.handle(for: "06 00 00 00 00", kind: .contact, tier: .handle, detector: "t", reason: "t", score: 90, source: "b", session: "s2")
        let unused = await vault.handle(for: "NL91ABNA0417164300", kind: .financial, tier: .handle, detector: "t", reason: "t", score: 97, source: "a", session: "s1")

        let later = Date().addingTimeInterval(2 * 60 * 60)
        let dropped = await vault.retain(referenced: [kept.id, shared.id], now: later)
        try Expect.equal(dropped, 1, "the value no record holds is dropped")
        try Expect.isNil(await vault.value(of: unused), "gone")
        try Expect.equal(await vault.retain(referenced: [], now: Date()), 0, "young entries wait out the grace period")

        try Expect.equal(await vault.release(session: "s1"), 1, "releasing s1 drops what only s1 saw")
        try Expect.notNil(await vault.value(of: shared), "a value s2 also saw stays")
        try Expect.equal(await vault.release(session: "s2"), 1, "and goes with s2")
        try Expect.equal(await vault.count, 0, "empty")
        try Expect.equal(store.count, 0, "an empty vault leaves nothing in its store")
    }

    static func pinnedEntriesStay() async throws {
        let vault = Sensitivity.Vault(lifetime: .seconds(60))
        let pinned = await vault.handle(for: "sam@example.com", kind: .contact, tier: .handle, detector: "t", reason: "t", score: 90, source: "a", session: "s1")
        let loose = await vault.handle(for: "alex@example.com", kind: .contact, tier: .handle, detector: "t", reason: "t", score: 90, source: "a", session: "s1")
        await vault.pin(only: [pinned.id])

        await vault.release(session: "s1")
        await vault.expire(now: Date().addingTimeInterval(3600))
        await vault.retain(referenced: [], now: Date().addingTimeInterval(7200))
        try Expect.notNil(await vault.value(of: pinned), "no release, expiry or sweep drops a pinned value")
        try Expect.isNil(await vault.value(of: loose), "the unpinned one went")

        let sealed = await vault.export([pinned.id])
        try Expect.equal(sealed.map(\.value.raw), ["sam@example.com"], "exported with its value, for a sealed copy")
        let elsewhere = Sensitivity.Vault()
        try Expect.equal(await elsewhere.insert(sealed), 1, "imported on another machine")
        try Expect.equal(await elsewhere.value(of: pinned), "sam@example.com", "the same handle resolves there")
        try Expect.equal(await elsewhere.insert(sealed), 0, "importing twice adds nothing")

        try Expect.equal(await elsewhere.forget([pinned.id]), 1, "a deliberate scrub forgets it, pinned or not")
        try Expect.isNil(await elsewhere.value(of: pinned), "its handle is stale there now")

        await vault.pin(only: [])
        await vault.expire(now: Date().addingTimeInterval(3600))
        try Expect.isNil(await vault.value(of: pinned), "once unpinned, it expires like any other")
    }

    static func previewShowsMaskedValues() async throws {
        let shield = Sensitivity.Shield(vault: Sensitivity.Vault())
        let (protected, protection) = await shield.protect("pay NL91ABNA0417164300 from 1234 AB", source: "bunq_payments")
        let preview = Sensitivity.preview(source: "bunq_payments", protection: protection, payload: protected)
        try Expect.true(preview.hasPrefix("## bunq_payments: 1 replaced, 1 flagged"), "the verdict: \(preview)")
        try Expect.true(preview.contains("**************4300"), "masked original")
        try Expect.false(preview.contains("NL91ABNA0417164300"), "never the value")
    }

    static func keychainRoundTrip() throws {
        guard ProcessInfo.processInfo.environment["SENSITIVITY_KEYCHAIN_TEST"] == "1" else { return }
        let store = Sensitivity.KeychainVaultStore(service: "agentic.sensitivity.test", account: UUID().uuidString)
        defer { try? store.clear() }
        try Expect.equal(try store.load().count, 0, "empty at first")
        let entry = Sensitivity.Vault.Entry(
            handle: .init(kind: .contact, id: "0000000a"),
            value: .init("sam@example.com"),
            tier: .handle, detector: "t", reason: "t", score: 90,
            sources: ["test"], grants: [], created: Date(), expires: nil
        )
        try store.save([entry])
        try store.save([entry])
        try Expect.equal(try store.load().first?.value.raw, "sam@example.com", "round trip through the Keychain")
    }
}

private extension JSONValue {
    var objectValue: [String: JSONValue]? {
        if case .object(let members) = self { return members }
        return nil
    }

    var arrayValue: [JSONValue]? {
        if case .array(let values) = self { return values }
        return nil
    }
}
