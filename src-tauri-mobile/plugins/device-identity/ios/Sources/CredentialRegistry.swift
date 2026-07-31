import Foundation

struct StoredMachineCredential: Codable, Equatable {
    let endpoint: String
    let machine: String
    let grantId: String
    let credential: String
}

func upsertMachineCredential(
    _ current: [StoredMachineCredential],
    _ credential: StoredMachineCredential
) -> [StoredMachineCredential] {
    var byMachine: [String: StoredMachineCredential] = [:]
    for existing in current {
        byMachine[existing.machine] = existing
    }
    byMachine[credential.machine] = credential
    return byMachine.values.sorted { $0.machine < $1.machine }
}

func machineCredentialsRemoving(
    _ current: [StoredMachineCredential],
    machine: String
) -> [StoredMachineCredential] {
    current
        .filter { $0.machine != machine }
        .sorted { $0.machine < $1.machine }
}

func migrateSingletonCredential(
    _ current: [StoredMachineCredential],
    legacy: StoredMachineCredential
) -> [StoredMachineCredential] {
    current.isEmpty ? [legacy] : current.sorted { $0.machine < $1.machine }
}
