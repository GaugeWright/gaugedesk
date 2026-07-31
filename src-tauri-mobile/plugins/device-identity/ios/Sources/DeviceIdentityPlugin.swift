import CryptoKit
import Foundation
import Security
import SwiftRs
import Tauri

final class SignChallengeArgs: Decodable {
    let challenge: String
}

final class StoreMachineCredentialArgs: Decodable {
    let endpoint: String
    let machine: String
    let grantId: String
    let credential: String
}

final class RemoveMachineCredentialArgs: Decodable {
    let machine: String
}

final class StoreAccountSessionArgs: Decodable {
    let idToken: String
}

private struct StoredMachineCredentialRegistry: Codable, Equatable {
    let version: Int
    var credentials: [StoredMachineCredential]
}

private struct LaunchUrlResponse: Encodable {
    let url: String?
}

private struct MachineCredentialResponse: Encodable {
    let credential: StoredMachineCredential?
}

private struct MachineCredentialRegistryResponse: Encodable {
    let version: Int
    let credentials: [StoredMachineCredential]
}

private struct StoredAccountSession: Codable, Equatable {
    let idToken: String
}

private struct AccountSessionResponse: Encodable {
    let idToken: String?
}

enum DeviceIdentityError: LocalizedError {
    case malformedPublicKey
    case malformedSignature
    case security(OSStatus)
    case keyCreation(String)

    var errorDescription: String? {
        switch self {
        case .malformedPublicKey:
            return "the device public key was malformed"
        case .malformedSignature:
            return "the device signature was malformed"
        case let .security(status):
            return SecCopyErrorMessageString(status, nil) as String?
                ?? "Keychain operation failed (\(status))"
        case let .keyCreation(message):
            return message
        }
    }
}

extension Data {
    var base64URL: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    var lowercaseHex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

func compressedP256PublicKey(_ x963: Data) throws -> Data {
    guard x963.count == 65, x963.first == 0x04 else {
        throw DeviceIdentityError.malformedPublicKey
    }
    let x = x963[1...32]
    let yLast = x963[64]
    var compressed = Data([yLast & 1 == 0 ? 0x02 : 0x03])
    compressed.append(contentsOf: x)
    return compressed
}

private func readDERLength(_ bytes: [UInt8], offset: inout Int) throws -> Int {
    guard offset < bytes.count else {
        throw DeviceIdentityError.malformedSignature
    }
    let first = Int(bytes[offset])
    offset += 1
    if first & 0x80 == 0 {
        return first
    }
    let count = first & 0x7f
    guard count > 0, count <= 2, offset + count <= bytes.count else {
        throw DeviceIdentityError.malformedSignature
    }
    var length = 0
    for _ in 0..<count {
        length = (length << 8) | Int(bytes[offset])
        offset += 1
    }
    return length
}

private func readDERInteger(_ bytes: [UInt8], offset: inout Int) throws -> Data {
    guard offset < bytes.count, bytes[offset] == 0x02 else {
        throw DeviceIdentityError.malformedSignature
    }
    offset += 1
    let length = try readDERLength(bytes, offset: &offset)
    guard length > 0, offset + length <= bytes.count else {
        throw DeviceIdentityError.malformedSignature
    }
    var integer = Array(bytes[offset..<(offset + length)])
    offset += length
    while integer.count > 1, integer.first == 0 {
        integer.removeFirst()
    }
    guard integer.count <= 32 else {
        throw DeviceIdentityError.malformedSignature
    }
    return Data(repeating: 0, count: 32 - integer.count) + Data(integer)
}

func rawP256Signature(_ der: Data) throws -> Data {
    let bytes = [UInt8](der)
    var offset = 0
    guard offset < bytes.count, bytes[offset] == 0x30 else {
        throw DeviceIdentityError.malformedSignature
    }
    offset += 1
    let sequenceLength = try readDERLength(bytes, offset: &offset)
    guard offset + sequenceLength == bytes.count else {
        throw DeviceIdentityError.malformedSignature
    }
    let r = try readDERInteger(bytes, offset: &offset)
    let s = try readDERInteger(bytes, offset: &offset)
    guard offset == bytes.count else {
        throw DeviceIdentityError.malformedSignature
    }
    return r + s
}

final class DeviceIdentityPlugin: Plugin {
    private let identityTag = Data(
        "com.gaugewright.gaugedesk.device-identity.v1".utf8
    )
    private let credentialService =
        "com.gaugewright.gaugedesk.machine-credential.v1"
    private let credentialAccount = "active-machine"
    private let accountSessionService =
        "com.gaugewright.gaugedesk.account-session.v1"
    private let accountSessionAccount = "active-account"
    #if targetEnvironment(simulator)
    private let simulatorIdentityKey =
        "com.gaugewright.gaugedesk.simulator-device-identity.v1"
    private let simulatorCredentialKey =
        "com.gaugewright.gaugedesk.simulator-machine-credential.v1"
    private let simulatorAccountSessionKey =
        "com.gaugewright.gaugedesk.simulator-account-session.v1"
    #endif

    private func log(_ message: String) {
        NSLog("[GaugeDeskDeviceIdentity] %@", message)
    }

    #if !targetEnvironment(simulator)
    private func privateKeyQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: identityTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
    }

    private func existingPrivateKey() throws -> SecKey? {
        log("checking for an existing identity key")
        var item: CFTypeRef?
        let status = SecItemCopyMatching(
            privateKeyQuery() as CFDictionary,
            &item
        )
        log("identity key lookup completed with status \(status)")
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let key = item else {
            throw DeviceIdentityError.security(status)
        }
        return (key as! SecKey)
    }

    private func createPrivateKey() throws -> SecKey {
        log("creating a new identity key")
        var privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: identityTag,
        ]
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]

        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            &accessError
        ) else {
            let message = accessError?.takeRetainedValue().localizedDescription
                ?? "could not create Secure Enclave access control"
            throw DeviceIdentityError.keyCreation(message)
        }
        privateAttributes[kSecAttrAccessControl as String] = access
        attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave

        attributes[kSecPrivateKeyAttrs as String] = privateAttributes
        var createError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(
            attributes as CFDictionary,
            &createError
        ) else {
            let message = createError?.takeRetainedValue().localizedDescription
                ?? "could not create the device identity"
            throw DeviceIdentityError.keyCreation(message)
        }
        log("identity key creation completed")
        return key
    }

    private func privateKey() throws -> SecKey {
        if let existing = try existingPrivateKey() {
            return existing
        }
        return try createPrivateKey()
    }

    private func publicKeyBytes(_ privateKey: SecKey) throws -> Data {
        log("exporting the identity public key")
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw DeviceIdentityError.malformedPublicKey
        }
        var copyError: Unmanaged<CFError>?
        guard let external = SecKeyCopyExternalRepresentation(
            publicKey,
            &copyError
        ) as Data? else {
            let message = copyError?.takeRetainedValue().localizedDescription
                ?? "could not read the device public key"
            throw DeviceIdentityError.keyCreation(message)
        }
        let compressed = try compressedP256PublicKey(external)
        log("identity public-key export completed")
        return compressed
    }
    #else
    private func simulatorPrivateKey() throws -> P256.Signing.PrivateKey {
        if let stored = UserDefaults.standard.data(
            forKey: simulatorIdentityKey
        ) {
            return try P256.Signing.PrivateKey(rawRepresentation: stored)
        }
        let key = P256.Signing.PrivateKey()
        UserDefaults.standard.set(
            key.rawRepresentation,
            forKey: simulatorIdentityKey
        )
        return key
    }
    #endif

    private func credentialQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: credentialService,
            kSecAttrAccount as String: credentialAccount,
            kSecAttrSynchronizable as String: false,
        ]
    }

    private func accountSessionQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: accountSessionService,
            kSecAttrAccount as String: accountSessionAccount,
            kSecAttrSynchronizable as String: false,
        ]
    }

    private func readAccountSessionData() throws -> Data? {
        #if targetEnvironment(simulator)
        return UserDefaults.standard.data(forKey: simulatorAccountSessionKey)
        #else
        var query = accountSessionQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let encoded = item as? Data else {
            throw DeviceIdentityError.security(status)
        }
        return encoded
        #endif
    }

    private func writeAccountSessionData(_ encoded: Data?) throws {
        #if targetEnvironment(simulator)
        if let encoded {
            UserDefaults.standard.set(encoded, forKey: simulatorAccountSessionKey)
        } else {
            UserDefaults.standard.removeObject(forKey: simulatorAccountSessionKey)
        }
        #else
        let query = accountSessionQuery()
        guard let encoded else {
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw DeviceIdentityError.security(status)
            }
            return
        }
        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: encoded] as CFDictionary
        )
        if updateStatus == errSecItemNotFound {
            var inserted = query
            inserted[kSecValueData as String] = encoded
            inserted[kSecAttrAccessible as String] =
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(inserted as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw DeviceIdentityError.security(addStatus)
            }
        } else if updateStatus != errSecSuccess {
            throw DeviceIdentityError.security(updateStatus)
        }
        #endif
    }

    private func readCredentialData() throws -> Data? {
        #if targetEnvironment(simulator)
        return UserDefaults.standard.data(forKey: simulatorCredentialKey)
        #else
        var query = credentialQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let encoded = item as? Data else {
            throw DeviceIdentityError.security(status)
        }
        return encoded
        #endif
    }

    private func writeCredentialData(_ encoded: Data?) throws {
        #if targetEnvironment(simulator)
        if let encoded {
            UserDefaults.standard.set(encoded, forKey: simulatorCredentialKey)
        } else {
            UserDefaults.standard.removeObject(forKey: simulatorCredentialKey)
        }
        #else
        let query = credentialQuery()
        guard let encoded else {
            let status = SecItemDelete(query as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw DeviceIdentityError.security(status)
            }
            return
        }
        let updateStatus = SecItemUpdate(
            query as CFDictionary,
            [kSecValueData as String: encoded] as CFDictionary
        )
        if updateStatus == errSecItemNotFound {
            var inserted = query
            inserted[kSecValueData as String] = encoded
            inserted[kSecAttrAccessible as String] =
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(inserted as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw DeviceIdentityError.security(addStatus)
            }
        } else if updateStatus != errSecSuccess {
            throw DeviceIdentityError.security(updateStatus)
        }
        #endif
    }

    private func credentialRegistry() throws -> StoredMachineCredentialRegistry {
        guard let encoded = try readCredentialData() else {
            return StoredMachineCredentialRegistry(version: 1, credentials: [])
        }
        if let registry = try? JSONDecoder().decode(
            StoredMachineCredentialRegistry.self,
            from: encoded
        ) {
            guard registry.version == 1 else {
                throw DeviceIdentityError.keyCreation(
                    "unsupported Machine credential registry version"
                )
            }
            let normalized = registry.credentials.reduce(
                [StoredMachineCredential]()
            ) { current, credential in
                upsertMachineCredential(current, credential)
            }
            let repaired = StoredMachineCredentialRegistry(
                version: 1,
                credentials: normalized
            )
            if repaired != registry {
                try saveCredentialRegistry(repaired)
            }
            return repaired
        }

        // Additive, idempotent migration of the former singleton Keychain item.
        let legacy = try JSONDecoder().decode(
            StoredMachineCredential.self,
            from: encoded
        )
        let migrated = StoredMachineCredentialRegistry(
            version: 1,
            credentials: migrateSingletonCredential([], legacy: legacy)
        )
        try saveCredentialRegistry(migrated)
        return migrated
    }

    private func saveCredentialRegistry(
        _ registry: StoredMachineCredentialRegistry
    ) throws {
        let sorted = StoredMachineCredentialRegistry(
            version: 1,
            credentials: registry.credentials.sorted { $0.machine < $1.machine }
        )
        try writeCredentialData(
            sorted.credentials.isEmpty ? nil : JSONEncoder().encode(sorted)
        )
    }

    private func reject(
        _ invoke: Invoke,
        operation: String,
        error: Error
    ) {
        invoke.reject("\(operation): \(error.localizedDescription)")
    }

    @objc public func getIdentity(_ invoke: Invoke) throws {
        log("getIdentity invoked")
        do {
            #if targetEnvironment(simulator)
            let publicKey = try compressedP256PublicKey(
                simulatorPrivateKey().publicKey.x963Representation
            )
            #else
            let publicKey = try publicKeyBytes(privateKey())
            #endif
            let fingerprint = Data(SHA256.hash(data: publicKey))
            log("resolving getIdentity")
            invoke.resolve([
                "id": "device:\(fingerprint.base64URL)",
                "publicKey": publicKey.lowercaseHex,
                "algorithm": "ES256",
            ])
        } catch {
            log("rejecting getIdentity: \(error.localizedDescription)")
            reject(
                invoke,
                operation: "could not open the device identity",
                error: error
            )
        }
    }

    @objc public func getLaunchUrl(_ invoke: Invoke) throws {
        // The first-party deep-link plugin is the single iOS URL lifecycle
        // authority. This compatibility command exists because Android also
        // checks the Activity's initial intent during a cold launch.
        invoke.resolve(LaunchUrlResponse(url: nil))
    }

    @objc public func signChallenge(_ invoke: Invoke) throws {
        do {
            let args = try invoke.parseArgs(SignChallengeArgs.self)
            #if targetEnvironment(simulator)
            let signature = try simulatorPrivateKey().signature(
                for: Data(args.challenge.utf8)
            )
            invoke.resolve([
                "algorithm": "ES256",
                "signature": signature.rawRepresentation.base64URL,
            ])
            #else
            let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256
            let key = try privateKey()
            guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
                throw DeviceIdentityError.keyCreation(
                    "the device key cannot produce ES256 signatures"
                )
            }
            var signError: Unmanaged<CFError>?
            guard let der = SecKeyCreateSignature(
                key,
                algorithm,
                Data(args.challenge.utf8) as CFData,
                &signError
            ) as Data? else {
                let message = signError?.takeRetainedValue().localizedDescription
                    ?? "could not sign the device challenge"
                throw DeviceIdentityError.keyCreation(message)
            }
            invoke.resolve([
                "algorithm": "ES256",
                "signature": try rawP256Signature(der).base64URL,
            ])
            #endif
        } catch {
            reject(
                invoke,
                operation: "could not sign the device challenge",
                error: error
            )
        }
    }

    @objc public func storeMachineCredential(_ invoke: Invoke) throws {
        do {
            let args = try invoke.parseArgs(StoreMachineCredentialArgs.self)
            let stored = StoredMachineCredential(
                endpoint: args.endpoint,
                machine: args.machine,
                grantId: args.grantId,
                credential: args.credential
            )
            var registry = try credentialRegistry()
            registry.credentials = upsertMachineCredential(
                registry.credentials,
                stored
            )
            try saveCredentialRegistry(registry)
            invoke.resolve()
        } catch {
            reject(
                invoke,
                operation: "could not store the Machine credential",
                error: error
            )
        }
    }

    @objc public func getMachineCredential(_ invoke: Invoke) throws {
        log("getMachineCredential invoked")
        do {
            let stored = try credentialRegistry().credentials
                .sorted { $0.machine < $1.machine }
                .first
            invoke.resolve(MachineCredentialResponse(credential: stored))
        } catch {
            reject(
                invoke,
                operation: "could not open the Machine credential",
                error: error
            )
        }
    }

    @objc public func clearMachineCredential(_ invoke: Invoke) throws {
        do {
            try writeCredentialData(nil)
            invoke.resolve()
        } catch {
            reject(
                invoke,
                operation: "could not clear the Machine credential",
                error: error
            )
        }
    }

    @objc public func listMachineCredentials(_ invoke: Invoke) throws {
        do {
            let registry = try credentialRegistry()
            invoke.resolve(
                MachineCredentialRegistryResponse(
                    version: registry.version,
                    credentials: registry.credentials.sorted {
                        $0.machine < $1.machine
                    }
                )
            )
        } catch {
            reject(
                invoke,
                operation: "could not list Machine credentials",
                error: error
            )
        }
    }

    @objc public func removeMachineCredential(_ invoke: Invoke) throws {
        do {
            let args = try invoke.parseArgs(RemoveMachineCredentialArgs.self)
            var registry = try credentialRegistry()
            registry.credentials = machineCredentialsRemoving(
                registry.credentials,
                machine: args.machine
            )
            try saveCredentialRegistry(registry)
            invoke.resolve()
        } catch {
            reject(
                invoke,
                operation: "could not remove the Machine credential",
                error: error
            )
        }
    }

    @objc public func storeAccountSession(_ invoke: Invoke) throws {
        do {
            let args = try invoke.parseArgs(StoreAccountSessionArgs.self)
            guard !args.idToken.isEmpty else {
                throw DeviceIdentityError.keyCreation(
                    "account session token is empty"
                )
            }
            try writeAccountSessionData(
                JSONEncoder().encode(StoredAccountSession(idToken: args.idToken))
            )
            invoke.resolve()
        } catch {
            reject(
                invoke,
                operation: "could not store the account session",
                error: error
            )
        }
    }

    @objc public func getAccountSession(_ invoke: Invoke) throws {
        do {
            let session = try readAccountSessionData().map {
                try JSONDecoder().decode(StoredAccountSession.self, from: $0)
            }
            invoke.resolve(AccountSessionResponse(idToken: session?.idToken))
        } catch {
            reject(
                invoke,
                operation: "could not open the account session",
                error: error
            )
        }
    }

    @objc public func clearAccountSession(_ invoke: Invoke) throws {
        do {
            try writeAccountSessionData(nil)
            invoke.resolve()
        } catch {
            reject(
                invoke,
                operation: "could not clear the account session",
                error: error
            )
        }
    }
}

@_cdecl("init_plugin_gaugedesk_device_identity")
func initPlugin() -> Plugin {
    DeviceIdentityPlugin()
}
