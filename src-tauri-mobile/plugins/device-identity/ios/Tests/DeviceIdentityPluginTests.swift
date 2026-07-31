import XCTest
@testable import GaugeDeskDeviceIdentityPlugin

final class DeviceIdentityPluginTests: XCTestCase {
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

    func testCompressesX963PublicKey() throws {
        let x = Array(repeating: UInt8(0x11), count: 32)
        let evenY = Array(repeating: UInt8(0x22), count: 32)
        let oddY = Array(repeating: UInt8(0x22), count: 31) + [UInt8(0x23)]

        XCTAssertEqual(
            try compressedP256PublicKey(Data([0x04] + x + evenY)),
            Data([0x02] + x)
        )
        XCTAssertEqual(
            try compressedP256PublicKey(Data([0x04] + x + oddY)),
            Data([0x03] + x)
        )
    }

    func testConvertsDERSignatureToRawP256() throws {
        let der = Data([0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x02])
        let raw = try rawP256Signature(der)

        XCTAssertEqual(raw.count, 64)
        XCTAssertEqual(raw[31], 0x80)
        XCTAssertEqual(raw[63], 0x02)
    }

    func testRejectsOversizedSignatureInteger() {
        let integer = [UInt8](repeating: 0x01, count: 33)
        let der = Data(
            [0x30, 0x26, 0x02, 0x21]
                + integer
                + [0x02, 0x01, 0x01]
        )

        XCTAssertThrowsError(try rawP256Signature(der))
    }

    func testAddingAndReplacingOneMachinePreservesTheOther() {
        let machineA = credential("machine-a", grant: "grant-a")
        let machineB = credential("machine-b", grant: "grant-b")
        let added = upsertMachineCredential([machineA], machineB)
        XCTAssertEqual(added, [machineA, machineB])

        let replacement = credential("machine-b", grant: "grant-b2")
        XCTAssertEqual(
            upsertMachineCredential(added, replacement),
            [machineA, replacement]
        )
    }

    func testRemovalIsMachineLocal() {
        let machineA = credential("machine-a", grant: "grant-a")
        let machineB = credential("machine-b", grant: "grant-b")
        XCTAssertEqual(
            machineCredentialsRemoving(
                [machineA, machineB],
                machine: "machine-a"
            ),
            [machineB]
        )
    }

    func testSingletonMigrationIsAdditiveAndIdempotent() {
        let machineA = credential("machine-a", grant: "grant-a")
        let migrated = migrateSingletonCredential([], legacy: machineA)
        XCTAssertEqual(migrated, [machineA])
        XCTAssertEqual(
            migrateSingletonCredential(
                migrated,
                legacy: credential("machine-a", grant: "obsolete")
            ),
            migrated
        )
    }
}
