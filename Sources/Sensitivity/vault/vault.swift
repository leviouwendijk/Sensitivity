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
            /// Sessions that saw the value; empty for values seen outside one.
            public var sessions: Set<String>
            /// Referenced by a pinned session: no expiry, release or sweep
            /// drops it while the pin stands.
            public var pinned: Bool
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
                sessions: Set<String> = [],
                pinned: Bool = false,
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
                self.sessions = sessions
                self.pinned = pinned
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
            source: String,
            session: String? = nil
        ) -> Handle {
            let key = Self.key(kind, value)
            if let id = byValue[key], var entry = entries[id] {
                var changed = false
                if !entry.sources.contains(source), entry.sources.count < 8 {
                    entry.sources.append(source)
                    changed = true
                }
                if let session, !entry.sessions.contains(session) {
                    entry.sessions.insert(session)
                    changed = true
                }
                if changed {
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
                sessions: session.map { [$0] } ?? [],
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

        /// Marks exactly the entries in `ids` as pinned and unpins the rest:
        /// the handles pinned sessions reference.
        public func pin(only ids: Set<String>) {
            var changed = false
            for (id, var entry) in entries where entry.pinned != ids.contains(id) {
                entry.pinned = ids.contains(id)
                entries[id] = entry
                changed = true
            }
            if changed { persist() }
        }

        /// The entries for `ids`, values included: what a sealed copy of a
        /// session carries.
        public func export(_ ids: Set<String>) -> [Entry] {
            ids.compactMap { entries[$0] }.sorted { $0.created < $1.created }
        }

        /// Adds `imported` entries (from a sealed copy) that are not here
        /// yet; a value already held keeps its own handle. Returns how many
        /// were added.
        @discardableResult
        public func insert(_ imported: [Entry]) -> Int {
            var added = 0
            for entry in imported where entries[entry.handle.id] == nil && byValue[Self.key(entry.handle.kind, entry.value.raw)] == nil {
                entries[entry.handle.id] = entry
                byValue[Self.key(entry.handle.kind, entry.value.raw)] = entry.handle.id
                added += 1
            }
            if added > 0 {
                known = nil
                persist()
            }
            return added
        }

        /// Forgets the values behind `ids`, pinned or not: for a deliberate
        /// scrub such as a deletion request. Their handles become stale.
        @discardableResult
        public func forget(_ ids: Set<String>) -> Int {
            let before = entries.count
            entries = entries.filter { !ids.contains($0.key) }
            byValue = byValue.filter { entries[$0.value] != nil }
            let forgotten = before - entries.count
            if forgotten > 0 {
                known = nil
                persist()
            }
            return forgotten
        }

        /// Forgets every entry and clears the store; for a closed session.
        public func clear() {
            entries = [:]
            byValue = [:]
            known = nil
            try? store?.clear()
        }

        /// Keeps only entries whose handle some record still holds, plus those
        /// younger than `grace` (values a live session has not recorded yet).
        /// Returns how many were dropped.
        @discardableResult
        public func retain(referenced ids: Set<String>, grace: Duration = .seconds(60 * 60), now: Date = Date()) -> Int {
            let cutoff = now.addingTimeInterval(-Double(grace.components.seconds))
            return drop { !ids.contains($0.handle.id) && $0.created < cutoff }
        }

        /// Forgets `session`: entries no other session saw are dropped.
        @discardableResult
        public func release(session: String) -> Int {
            for (id, var entry) in entries where entry.sessions.contains(session) {
                entry.sessions.remove(session)
                entries[id] = entry
            }
            return drop { $0.sessions.isEmpty }
        }

        public var count: Int {
            entries.count
        }

        private func drop(where condition: (Entry) -> Bool) -> Int {
            let before = entries.count
            entries = entries.filter { $0.value.pinned || !condition($0.value) }
            byValue = byValue.filter { entries[$0.value] != nil }
            let dropped = before - entries.count
            if dropped > 0 {
                known = nil
                persist()
            }
            return dropped
        }

        /// Drops expired entries.
        public func expire(now: Date = Date()) {
            let before = entries.count
            entries = entries.filter { $0.value.pinned || ($0.value.expires ?? .distantFuture) > now }
            byValue = byValue.filter { entries[$0.value] != nil }
            if entries.count != before {
                known = nil
                persist()
            }
        }

        private func live(_ handle: Handle) -> Entry? {
            guard let entry = entries[handle.id],
                  entry.handle.kind == handle.kind,
                  entry.pinned || (entry.expires ?? .distantFuture) > Date()
            else {
                return nil
            }
            return entry
        }

        /// An empty vault leaves nothing behind in its store.
        private func persist() {
            if entries.isEmpty {
                try? store?.clear()
            } else {
                try? store?.save(Array(entries.values))
            }
        }

        private static func key(_ kind: Kind, _ value: String) -> String {
            // Mail addresses differ only in case; other values are exact.
            "\(kind.rawValue)\u{0}\(kind == .contact ? value.lowercased() : value)"
        }
    }
}

extension Sensitivity.Vault.Entry {
    private enum CodingKeys: String, CodingKey {
        case handle, value, tier, detector, reason, score, sources, grants, sessions, pinned, created, expires
    }

    /// Entries stored before sessions were recorded decode with none.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            handle: try container.decode(Sensitivity.Handle.self, forKey: .handle),
            value: try container.decode(Sensitivity.SensitiveValue.self, forKey: .value),
            tier: try container.decode(Sensitivity.Tier.self, forKey: .tier),
            detector: try container.decode(String.self, forKey: .detector),
            reason: try container.decode(String.self, forKey: .reason),
            score: try container.decode(Int.self, forKey: .score),
            sources: try container.decode([String].self, forKey: .sources),
            grants: try container.decode(Set<String>.self, forKey: .grants),
            sessions: try container.decodeIfPresent(Set<String>.self, forKey: .sessions) ?? [],
            pinned: try container.decodeIfPresent(Bool.self, forKey: .pinned) ?? false,
            created: try container.decode(Date.self, forKey: .created),
            expires: try container.decodeIfPresent(Date.self, forKey: .expires)
        )
    }
}
