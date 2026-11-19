import Foundation

public extension Sensitivity {
    /// A value kept out of sight: it prints, dumps and reflects as
    /// `<redacted sensitive value>`, but `raw` is there for whoever holds it.
    struct SensitiveValue: Sendable, Codable, Hashable, Redacted {
        public static let redactedLabel = "sensitive value"

        public let raw: String

        public init(_ raw: String) {
            self.raw = raw
        }
    }

    /// Keeps a vault's entries somewhere that survives the process, such as
    /// the Keychain. Values live only there and in memory, never in session
    /// records.
    protocol VaultStore: Sendable {
        func load() throws -> [Vault.Entry]
        func save(_ entries: [Vault.Entry]) throws
        func clear() throws
    }

    /// Handle → value for one session (or one host process). A cache of
    /// values whose sources stay authoritative: losing it means fetching
    /// again, never losing data. Entries expire after `lifetime`.
    actor Vault {
        public struct Entry: Sendable, Codable, Hashable {
            public let handle: Handle
            public let value: SensitiveValue
            public let tier: Tier
            public let detector: String
            public let reason: String
            public let score: Int
            public var sources: [String]
            public var grants: Set<String>
            public let created: Date
            public var expires: Date?

            public init(
                handle: Handle,
                value: SensitiveValue,
                tier: Tier,
                detector: String,
                reason: String,
                score: Int,
                sources: [String],
                grants: Set<String>,
                created: Date,
                expires: Date?
            ) {
                self.handle = handle
                self.value = value
                self.tier = tier
                self.detector = detector
                self.reason = reason
                self.score = score
                self.sources = sources
                self.grants = grants
                self.created = created
                self.expires = expires
            }

            var description: HandleDescription {
                HandleDescription(
                    handle: handle,
                    tier: tier,
                    preview: Sensitivity.mask(value.raw),
                    detector: detector,
                    reason: reason,
                    score: score,
                    sources: sources,
                    grants: grants.sorted()
                )
            }
        }

        public let lifetime: Duration?
        private let store: (any VaultStore)?
        private var entries: [String: Entry] = [:]
        /// kind + value → handle id, so a value keeps its handle.
        private var byValue: [String: String] = [:]
        private var known: KnownValues?

        /// A vault in memory; with `store`, entries are loaded from it and
        /// saved to it on every change.
        public init(lifetime: Duration? = .seconds(24 * 60 * 60), store: (any VaultStore)? = nil) {
            self.lifetime = lifetime
            self.store = store
            if let loaded = try? store?.load() {
                let now = Date()
                for entry in loaded where (entry.expires ?? .distantFuture) > now {
                    entries[entry.handle.id] = entry
                    byValue[Self.key(entry.handle.kind, entry.value.raw)] = entry.handle.id
                }
            }
        }

        /// The handle for `value`: its existing one, or a new one.
        public func handle(
            for value: String,
            kind: Kind,
            tier: Tier,
            detector: String,
            reason: String,
            score: Int,
            source: String
        ) -> Handle {
            let key = Self.key(kind, value)
            if let id = byValue[key], var entry = entries[id] {
                if !entry.sources.contains(source), entry.sources.count < 8 {
                    entry.sources.append(source)
                    entries[id] = entry
                    persist()
                }
                return entry.handle
            }
            var id: String
            repeat {
                id = String(format: "%08x", UInt32.random(in: .min ... .max))
            } while entries[id] != nil
            let now = Date()
            let entry = Entry(
                handle: Handle(kind: kind, id: id),
                value: SensitiveValue(value),
                tier: tier,
                detector: detector,
                reason: reason,
                score: score,
                sources: [source],
                grants: [],
                created: now,
                expires: lifetime.map { now.addingTimeInterval(Double($0.components.seconds)) }
            )
            entries[id] = entry
            byValue[key] = id
            known = nil
            persist()
            return entry.handle
        }

        /// The value behind `handle`; nil when unknown or expired.
        public func value(of handle: Handle) -> String? {
            guard let entry = live(handle) else { return nil }
            return entry.value.raw
        }

        public func describe(_ handle: Handle) -> HandleDescription? {
            live(handle)?.description
        }

        public func descriptions() -> [HandleDescription] {
            entries.values
                .filter { ($0.expires ?? .distantFuture) > Date() }
                .sorted { $0.created < $1.created }
                .map(\.description)
        }

        /// Lets `tool` use `handle` from now on.
        @discardableResult
        public func grant(_ handle: Handle, to tool: String) -> Bool {
            guard var entry = live(handle) else { return false }
            entry.grants.insert(tool)
            entries[handle.id] = entry
            persist()
            return true
        }

        /// Every live value, for finding it again wherever it reappears.
        public func knownValues() -> KnownValues {
            if let known { return known }
            let values = entries.values
                .filter { ($0.expires ?? .distantFuture) > Date() }
                .map { Known($0.value.raw, kind: $0.handle.kind, reason: "seen before (\($0.handle.token))") }
            let detector = KnownValues(values)
            known = detector
            return detector
        }

        /// Forgets every entry and clears the store; for a closed session.
        public func clear() {
            entries = [:]
            byValue = [:]
            known = nil
            try? store?.clear()
        }

        /// Drops expired entries.
        public func expire(now: Date = Date()) {
            let before = entries.count
            entries = entries.filter { ($0.value.expires ?? .distantFuture) > now }
            byValue = byValue.filter { entries[$0.value] != nil }
            if entries.count != before {
                known = nil
                persist()
            }
        }

        private func live(_ handle: Handle) -> Entry? {
            guard let entry = entries[handle.id],
                  entry.handle.kind == handle.kind,
                  (entry.expires ?? .distantFuture) > Date()
            else {
                return nil
            }
            return entry
        }

        private func persist() {
            try? store?.save(Array(entries.values))
        }

        private static func key(_ kind: Kind, _ value: String) -> String {
            // Mail addresses differ only in case; other values are exact.
            "\(kind.rawValue)\u{0}\(kind == .contact ? value.lowercased() : value)"
        }
    }
}
