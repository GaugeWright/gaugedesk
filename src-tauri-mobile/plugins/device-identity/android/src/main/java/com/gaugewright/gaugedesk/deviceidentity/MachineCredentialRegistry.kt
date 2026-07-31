package com.gaugewright.gaugedesk.deviceidentity

/**
 * Pure registry operations shared by the Android vault adapter and its JVM
 * conformance tests. A Machine id is the only replacement key: adding or
 * removing one entry cannot disturb another Machine's credential.
 */
internal fun <T> upsertMachineCredential(
    current: Map<String, T>,
    machine: String,
    credential: T,
): Map<String, T> = current.toMutableMap().apply {
    put(machine, credential)
}.toSortedMap()

internal fun <T> removeMachineCredential(
    current: Map<String, T>,
    machine: String,
): Map<String, T> = current.toMutableMap().apply {
    remove(machine)
}.toSortedMap()

internal fun <T> migrateSingletonCredential(
    current: Map<String, T>,
    legacyMachine: String,
    legacyCredential: T,
): Map<String, T> =
    if (current.isNotEmpty()) current.toSortedMap()
    else sortedMapOf(legacyMachine to legacyCredential)
