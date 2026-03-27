import CryptoKit
import Foundation
import Security

public struct ManagedKey: Equatable {
    public let id: String
    public let name: String
    public let comment: String
    public let createdAt: Date
    public let keyBlob: Data
    public let publicKey: String
    public let fingerprint: String
}

public enum SSHAgentCoreError: Error, LocalizedError, Equatable {
    case secureEnclaveKeyUnavailable
    case invalidPublicKeyFormat
    case unsupportedCommand(String)
    case missingValue(String)
    case invalidOption(String)
    case keyNotFound(String)
    case metadataCorrupt
    case keychainFailure(operation: String, status: OSStatus)

    public var errorDescription: String? {
        switch self {
        case .secureEnclaveKeyUnavailable:
            return "Secure Enclave key could not be created on this device."
        case .invalidPublicKeyFormat:
            return "Public key format is invalid."
        case .unsupportedCommand(let command):
            return "Unsupported command: \(command)"
        case .missingValue(let flag):
            return "Missing value for option \(flag)"
        case .invalidOption(let option):
            return "Invalid option: \(option)"
        case .keyNotFound(let id):
            return "Managed key not found: \(id)"
        case .metadataCorrupt:
            return "Stored key metadata is corrupt."
        case .keychainFailure(let operation, let status):
            return "\(operation) failed with status \(status): \(securityErrorMessage(status))"
        }
    }
}

public final class SecureEnclaveKeyStore {
    public static let metadataService = "com.touchidsshagent.key-metadata"
    private static let accountPrefix = "managed-key."

    public init() {}

    public func createKey(name: String, comment: String) throws -> ManagedKey {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedComment = comment.trimmingCharacters(in: .whitespacesAndNewlines)
        let finalName = trimmedName.isEmpty ? defaultName() : trimmedName
        let finalComment = trimmedComment.isEmpty ? defaultComment() : trimmedComment

        let id = UUID().uuidString.lowercased()
        let createdAt = Date()

        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey()
        } catch {
            throw SSHAgentCoreError.secureEnclaveKeyUnavailable
        }

        let metadata = KeyMetadata(
            id: id,
            name: finalName,
            comment: finalComment,
            createdAt: createdAt,
            keyReferenceBase64: key.dataRepresentation.base64EncodedString()
        )
        try storeMetadata(metadata)

        let publicKeyData = key.publicKey.x963Representation
        let keyBlob = try OpenSSHPublicKeyEncoder.keyBlobFromX963(rawPublicKey: publicKeyData)
        let publicKey = try OpenSSHPublicKeyEncoder.encodeFromX963(rawPublicKey: publicKeyData, comment: finalComment)
        let fingerprint = try OpenSSHPublicKeyEncoder.fingerprintFromX963(rawPublicKey: publicKeyData)

        return ManagedKey(
            id: id,
            name: finalName,
            comment: finalComment,
            createdAt: createdAt,
            keyBlob: keyBlob,
            publicKey: publicKey,
            fingerprint: fingerprint
        )
    }

    public func listKeys() throws -> [ManagedKey] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.metadataService,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return []
        }
        guard status == errSecSuccess else {
            throw SSHAgentCoreError.keychainFailure(operation: "SecItemCopyMatching(metadata-all)", status: status)
        }

        let items = normalizeKeychainResult(result)
        var managedKeys: [ManagedKey] = []
        managedKeys.reserveCapacity(items.count)

        for item in items {
            guard
                let account = item[kSecAttrAccount as String] as? String,
                account.hasPrefix(Self.accountPrefix)
            else {
                continue
            }

            let id = String(account.dropFirst(Self.accountPrefix.count))
            let metadata: KeyMetadata
            do {
                guard let loaded = try loadMetadata(id: id) else {
                    continue
                }
                metadata = loaded
            } catch {
                // Skip entries that cannot be read in this session (e.g. keychain auth denied).
                continue
            }

            guard let keyReference = Data(base64Encoded: metadata.keyReferenceBase64) else {
                continue
            }

            let key: SecureEnclave.P256.Signing.PrivateKey
            do {
                key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyReference)
            } catch {
                continue
            }

            let publicKeyData = key.publicKey.x963Representation
            let keyBlob = try OpenSSHPublicKeyEncoder.keyBlobFromX963(rawPublicKey: publicKeyData)
            let publicKey = try OpenSSHPublicKeyEncoder.encodeFromX963(rawPublicKey: publicKeyData, comment: metadata.comment)
            let fingerprint = try OpenSSHPublicKeyEncoder.fingerprintFromX963(rawPublicKey: publicKeyData)

            managedKeys.append(
                ManagedKey(
                    id: metadata.id,
                    name: metadata.name,
                    comment: metadata.comment,
                    createdAt: metadata.createdAt,
                    keyBlob: keyBlob,
                    publicKey: publicKey,
                    fingerprint: fingerprint
                )
            )
        }

        return managedKeys.sorted { $0.createdAt > $1.createdAt }
    }

    public func loadSigningKey(id: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
        guard let metadata = try loadMetadata(id: id) else {
            throw SSHAgentCoreError.keyNotFound(id)
        }
        guard let keyReference = Data(base64Encoded: metadata.keyReferenceBase64) else {
            throw SSHAgentCoreError.metadataCorrupt
        }
        do {
            return try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyReference)
        } catch {
            throw SSHAgentCoreError.secureEnclaveKeyUnavailable
        }
    }

    public func loadManagedKey(id: String) throws -> ManagedKey {
        guard let metadata = try loadMetadata(id: id) else {
            throw SSHAgentCoreError.keyNotFound(id)
        }
        let key = try loadSigningKey(id: id)
        let publicKeyData = key.publicKey.x963Representation
        let keyBlob = try OpenSSHPublicKeyEncoder.keyBlobFromX963(rawPublicKey: publicKeyData)
        let publicKey = try OpenSSHPublicKeyEncoder.encodeFromX963(rawPublicKey: publicKeyData, comment: metadata.comment)
        let fingerprint = try OpenSSHPublicKeyEncoder.fingerprintFromX963(rawPublicKey: publicKeyData)

        return ManagedKey(
            id: metadata.id,
            name: metadata.name,
            comment: metadata.comment,
            createdAt: metadata.createdAt,
            keyBlob: keyBlob,
            publicKey: publicKey,
            fingerprint: fingerprint
        )
    }

    public func sign(id: String, data: Data) throws -> Data {
        let key = try loadSigningKey(id: id)
        let signature = try key.signature(for: data)
        return signature.rawRepresentation
    }

    private func storeMetadata(_ metadata: KeyMetadata) throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let payload = try encoder.encode(metadata)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.metadataService,
            kSecAttrAccount as String: accountName(forID: metadata.id),
            kSecValueData as String: payload,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess {
            return
        }
        if addStatus != errSecDuplicateItem {
            throw SSHAgentCoreError.keychainFailure(operation: "SecItemAdd(metadata)", status: addStatus)
        }

        let updateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.metadataService,
            kSecAttrAccount as String: accountName(forID: metadata.id),
        ]
        let updateAttrs: [String: Any] = [
            kSecValueData as String: payload,
        ]
        let updateStatus = SecItemUpdate(updateQuery as CFDictionary, updateAttrs as CFDictionary)
        guard updateStatus == errSecSuccess else {
            throw SSHAgentCoreError.keychainFailure(operation: "SecItemUpdate(metadata)", status: updateStatus)
        }
    }

    private func loadMetadata(id: String) throws -> KeyMetadata? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.metadataService,
            kSecAttrAccount as String: accountName(forID: id),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw SSHAgentCoreError.keychainFailure(operation: "SecItemCopyMatching(metadata-one)", status: status)
        }
        guard let payload = result as? Data else {
            throw SSHAgentCoreError.metadataCorrupt
        }
        return try decodeMetadata(payload)
    }

    private func decodeMetadata(_ payload: Data) throws -> KeyMetadata {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(KeyMetadata.self, from: payload)
        } catch {
            throw SSHAgentCoreError.metadataCorrupt
        }
    }

    private func normalizeKeychainResult(_ result: CFTypeRef?) -> [[String: Any]] {
        if let array = result as? [[String: Any]] {
            return array
        }
        if let dict = result as? [String: Any] {
            return [dict]
        }
        return []
    }

    private func accountName(forID id: String) -> String {
        Self.accountPrefix + id
    }

    private func defaultName() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return "touchid-key-\(formatter.string(from: Date()))"
    }

    private func defaultComment() -> String {
        let host = Host.current().localizedName ?? "mac"
        return "\(NSUserName())@\(host)"
    }
}

private struct KeyMetadata: Codable {
    let id: String
    let name: String
    let comment: String
    let createdAt: Date
    let keyReferenceBase64: String
}

public enum OpenSSHPublicKeyEncoder {
    private static let algorithm = "ecdsa-sha2-nistp256"
    private static let curve = "nistp256"

    public static func encodeFromX963(rawPublicKey: Data, comment: String) throws -> String {
        let blob = try keyBlobFromX963(rawPublicKey: rawPublicKey)
        let b64 = blob.base64EncodedString()
        return "\(algorithm) \(b64) \(comment)"
    }

    public static func fingerprintFromX963(rawPublicKey: Data) throws -> String {
        let blob = try keyBlobFromX963(rawPublicKey: rawPublicKey)
        let digest = SHA256.hash(data: blob)
        let fingerprint = Data(digest).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return "SHA256:\(fingerprint)"
    }

    public static func keyBlobFromX963(rawPublicKey: Data) throws -> Data {
        guard rawPublicKey.count == 65, rawPublicKey.first == 0x04 else {
            throw SSHAgentCoreError.invalidPublicKeyFormat
        }
        var blob = Data()
        blob.append(sshString(Data(algorithm.utf8)))
        blob.append(sshString(Data(curve.utf8)))
        blob.append(sshString(rawPublicKey))
        return blob
    }

    public static func signatureBlobFromRawECDSA(rawSignature: Data) throws -> Data {
        guard rawSignature.count == 64 else {
            throw SSHAgentCoreError.invalidPublicKeyFormat
        }
        let r = Data(rawSignature[0..<32])
        let s = Data(rawSignature[32..<64])
        var inner = Data()
        inner.append(sshString(mpintFromUnsigned(r)))
        inner.append(sshString(mpintFromUnsigned(s)))

        var outer = Data()
        outer.append(sshString(Data(algorithm.utf8)))
        outer.append(sshString(inner))
        return outer
    }

    private static func sshString(_ value: Data) -> Data {
        var data = Data()
        data.append(uint32BE(UInt32(value.count)))
        data.append(value)
        return data
    }

    private static func uint32BE(_ value: UInt32) -> Data {
        Data([
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF),
        ])
    }

    private static func mpintFromUnsigned(_ value: Data) -> Data {
        var trimmed = value
        while trimmed.count > 1, trimmed.first == 0x00 {
            trimmed.removeFirst()
        }
        if trimmed.isEmpty {
            return Data([0x00])
        }
        if let first = trimmed.first, (first & 0x80) != 0 {
            return Data([0x00]) + trimmed
        }
        return trimmed
    }
}

public func securityErrorMessage(_ status: OSStatus) -> String {
    if let msg = SecCopyErrorMessageString(status, nil) as String? {
        return msg
    }
    return "Unknown Security.framework error"
}
