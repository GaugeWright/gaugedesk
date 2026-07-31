import Foundation

private func credential(
    _ machine: String,
    grant: String
) -> StoredMachineCredential {
    StoredMachineCredential(
        endpoint: "https://\(machine).example",
        machine: machine,
        grantId: grant,
        credential: "secret:\(grant)"
    )
}

private func require(
    _ condition: @autoclosure () -> Bool,
    _ message: String
) {
    guard condition() else {
        fatalError(message)
    }
}

@main
private enum RegistryParityMain {
    static func main() {
        let machineA = credential("machine-a", grant: "grant-a")
        let machineB = credential("machine-b", grant: "grant-b")

        let added = upsertMachineCredential([machineA], machineB)
        require(
            added == [machineA, machineB],
            "adding a Machine lost a credential"
        )

        let replacement = credential("machine-b", grant: "grant-b2")
        require(
            upsertMachineCredential(added, replacement)
                == [machineA, replacement],
            "replacing one Machine changed another Machine"
        )
        require(
            machineCredentialsRemoving(added, machine: "machine-a")
                == [machineB],
            "removing one Machine changed another Machine"
        )

        let migrated = migrateSingletonCredential([], legacy: machineA)
        require(
            migrated == [machineA],
            "singleton migration did not preserve credential"
        )
        require(
            migrateSingletonCredential(
                migrated,
                legacy: credential("machine-a", grant: "obsolete")
            ) == migrated,
            "singleton migration was not idempotent"
        )

        print("iOS credential registry parity: OK")
    }
}
