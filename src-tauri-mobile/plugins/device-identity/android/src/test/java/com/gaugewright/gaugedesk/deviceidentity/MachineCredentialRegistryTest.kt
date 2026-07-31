package com.gaugewright.gaugedesk.deviceidentity

import org.junit.Assert.assertEquals
import org.junit.Test

class MachineCredentialRegistryTest {
    @Test
    fun addingAndReplacingOneMachinePreservesTheOther() {
        val initial = mapOf("machine:a" to "grant:a")
        val added = upsertMachineCredential(initial, "machine:b", "grant:b")
        assertEquals(
            mapOf("machine:a" to "grant:a", "machine:b" to "grant:b"),
            added,
        )

        val replaced = upsertMachineCredential(added, "machine:b", "grant:b2")
        assertEquals("grant:a", replaced["machine:a"])
        assertEquals("grant:b2", replaced["machine:b"])
    }

    @Test
    fun removalIsMachineLocal() {
        val initial = mapOf(
            "machine:a" to "grant:a",
            "machine:b" to "grant:b",
        )
        assertEquals(
            mapOf("machine:b" to "grant:b"),
            removeMachineCredential(initial, "machine:a"),
        )
    }

    @Test
    fun singletonMigrationIsAdditiveAndIdempotent() {
        val migrated = migrateSingletonCredential(
            emptyMap(),
            "machine:a",
            "grant:a",
        )
        assertEquals(mapOf("machine:a" to "grant:a"), migrated)
        assertEquals(
            migrated,
            migrateSingletonCredential(migrated, "machine:a", "obsolete"),
        )
    }
}
