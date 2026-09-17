import ContainerizationOCI
import Foundation
import Logging

/// `docker save` (v25+) writes an OCI layout whose index blob preserves the
/// image's original multi-platform index — every platform and attestation
/// manifest digest — while only including blobs for the platform the engine
/// had. Apple's `ImageStore.load` resolves an index strictly and fails on the
/// first absent manifest, so the layout is pruned down to what the tarball
/// actually contains before loading.
enum OCILayoutPruner {
    enum PruneError: Error, LocalizedError, Equatable {
        case nothingLoadable
        case indexNestingTooDeep

        var errorDescription: String? {
            switch self {
            case .nothingLoadable:
                return "the tarball contains no image manifest with complete content for any platform"
            case .indexNestingTooDeep:
                return "the tarball nests image indexes beyond the supported depth"
            }
        }
    }

    static func pruneManifestsWithMissingBlobs(at layout: URL, logger: Logger) throws {
        let indexURL = layout.appendingPathComponent("index.json")
        let (decoded, decodedLeniently) = decodeIndexLeniently(try Data(contentsOf: indexURL), logger: logger)
        var index = decoded
        let originalDigests = index.manifests.map(\.digest)

        let cache = PruneCache()
        index.manifests = try index.manifests.compactMap { try prunedDescriptor($0, in: layout, cache: cache, logger: logger) }

        guard !index.manifests.isEmpty else {
            throw PruneError.nothingLoadable
        }
        if decodedLeniently || index.manifests.map(\.digest) != originalDigests {
            try JSONEncoder().encode(index).write(to: indexURL)
        }
    }

    /// Returns the descriptor to keep for `descriptor`, rewriting an index down to the
    /// manifests whose content is present (recursively, so a partially-present nested
    /// index keeps its loadable platforms), or nil when nothing under it is loadable.
    ///
    /// A real `docker save` nests one index level; beyond this the tarball is rejected.
    /// The cap bounds recursion against a crafted chain of distinct nested indexes —
    /// which neither the cycle guard (all digests differ) nor the cache (each visited
    /// once) would otherwise stop before a stack overflow. It aborts rather than drops
    /// the branch so a result stays independent of the depth it was first reached at,
    /// keeping the digest-keyed cache correct.
    private static let maxIndexNestingDepth = 32

    /// Blob content is never re-hashed against its digest, so a crafted tarball can make
    /// an index reference itself (a cycle) or fan out to the same sub-index exponentially.
    /// The path guard cuts cycles; the cache collapses repeated sub-indexes to one visit.
    private static func prunedDescriptor(_ descriptor: Descriptor, in layout: URL, depth: Int = 0, visiting: Set<String> = [], cache: PruneCache, logger: Logger) throws
        -> Descriptor?
    {
        guard depth <= maxIndexNestingDepth else { throw PruneError.indexNestingTooDeep }
        if isIndex(descriptor.mediaType), visiting.contains(descriptor.digest) {
            return nil
        }
        // Keyed by media type too: the same bytes are validated differently as an index
        // vs a manifest, and blobs are never re-hashed, so one digest can carry both.
        return try cache.result(of: descriptor.digest, as: descriptor.mediaType) {
            guard blobExists(descriptor.digest, in: layout) else { return nil }
            if isManifest(descriptor.mediaType) {
                guard let manifest = try? JSONDecoder().decode(Manifest.self, from: Data(contentsOf: blobURL(descriptor.digest, in: layout))) else {
                    return nil
                }
                let complete = blobExists(manifest.config.digest, in: layout) && manifest.layers.allSatisfy { blobExists($0.digest, in: layout) }
                return complete ? descriptor : nil
            }
            if isIndex(descriptor.mediaType) {
                guard let blobData = try? Data(contentsOf: blobURL(descriptor.digest, in: layout)) else {
                    return nil
                }
                let (decoded, decodedLeniently) = decodeIndexLeniently(blobData, logger: logger)
                var childIndex = decoded
                let pruned = try childIndex.manifests.compactMap {
                    try prunedDescriptor($0, in: layout, depth: depth + 1, visiting: visiting.union([descriptor.digest]), cache: cache, logger: logger)
                }
                guard !pruned.isEmpty else { return nil }
                guard decodedLeniently || pruned.map(\.digest) != childIndex.manifests.map(\.digest) else { return descriptor }
                childIndex.manifests = pruned
                return try rewrittenIndex(childIndex, keeping: descriptor, in: layout, logger: logger)
            }
            return descriptor
        }
    }

    /// Decodes an `Index`, dropping (and logging) only the individual manifest
    /// entries whose descriptor fails to decode — e.g. a path-traversal digest —
    /// instead of failing the whole blob. Returns whether the lenient fallback
    /// path was used, so callers that only rewrite a blob when its manifest list
    /// changed still rewrite it here (the fallback path already filtered its
    /// returned manifests, so a naive before/after comparison would see no
    /// difference and leave the tainted bytes on disk under the same digest).
    ///
    /// `Index.manifests` is `[Descriptor]`, and `Descriptor`'s own decoder now
    /// validates its digest, so `JSONDecoder` aborts the entire array on the
    /// first invalid element. Decoding each element independently keeps
    /// otherwise-intact sibling manifests loadable. A blob that isn't valid JSON
    /// at all yields an index with no manifests, which callers already treat as
    /// nothing loadable.
    private static func decodeIndexLeniently(_ data: Data, logger: Logger) -> (Index, decodedLeniently: Bool) {
        if let index = try? JSONDecoder().decode(Index.self, from: data) {
            return (index, false)
        }
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return (Index(manifests: []), true)
        }
        let rawManifests = object["manifests"] as? [[String: Any]] ?? []
        let manifests: [Descriptor] = rawManifests.compactMap { raw in
            guard let itemData = try? JSONSerialization.data(withJSONObject: raw),
                let descriptor = try? JSONDecoder().decode(Descriptor.self, from: itemData)
            else {
                logger.warning("dropping manifest entry with an invalid descriptor")
                return nil
            }
            return descriptor
        }
        let schemaVersion = object["schemaVersion"] as? Int ?? 2
        let mediaType = object["mediaType"] as? String ?? MediaTypes.index
        let annotations = object["annotations"] as? [String: String]
        return (Index(schemaVersion: schemaVersion, mediaType: mediaType, manifests: manifests, annotations: annotations), true)
    }

    private static func rewrittenIndex(_ childIndex: Index, keeping original: Descriptor, in layout: URL, logger: Logger) throws -> Descriptor {
        let data = try JSONEncoder().encode(childIndex)
        let digest = "sha256:" + data.sha256Hex()
        try data.write(to: blobURL(digest, in: layout))
        logger.info("pruned index \(original.digest) -> \(digest): kept \(childIndex.manifests.count) manifest(s)")
        return Descriptor(
            mediaType: original.mediaType,
            digest: digest,
            size: Int64(data.count),
            urls: original.urls,
            annotations: original.annotations,
            platform: original.platform,
            artifactType: original.artifactType
        )
    }

    private final class PruneCache {
        private struct Key: Hashable {
            let digest: String
            let mediaType: String
        }
        private var resolved: [Key: Descriptor?] = [:]

        func result(of digest: String, as mediaType: String, compute: () throws -> Descriptor?) rethrows -> Descriptor? {
            let key = Key(digest: digest, mediaType: mediaType)
            if let known = resolved[key] { return known }
            let value = try compute()
            resolved[key] = value
            return value
        }
    }

    private static func isIndex(_ mediaType: String) -> Bool {
        mediaType == MediaTypes.index || mediaType == MediaTypes.dockerManifestList
    }

    private static func isManifest(_ mediaType: String) -> Bool {
        mediaType == MediaTypes.imageManifest || mediaType == MediaTypes.dockerManifest
    }

    /// Digests come from attacker-suppliable tarball JSON and are spliced into
    /// filesystem paths — anything but `algorithm:hex` addressing a regular file is
    /// treated as absent (a digest-named directory is not a blob).
    private static func blobExists(_ digest: String, in layout: URL) -> Bool {
        guard isWellFormedDigest(digest) else { return false }
        var isDirectory: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: blobURL(digest, in: layout).path, isDirectory: &isDirectory)
        return exists && !isDirectory.boolValue
    }

    private static func isWellFormedDigest(_ digest: String) -> Bool {
        digest.wholeMatch(of: /[a-z0-9]+:[a-fA-F0-9]{32,}/) != nil
    }

    private static func blobURL(_ digest: String, in layout: URL) -> URL {
        let components = digest.split(separator: ":")
        let algorithm = components.count == 2 ? String(components[0]) : "sha256"
        let hex = components.count == 2 ? String(components[1]) : digest
        return layout.appendingPathComponent("blobs").appendingPathComponent(algorithm).appendingPathComponent(hex)
    }
}
