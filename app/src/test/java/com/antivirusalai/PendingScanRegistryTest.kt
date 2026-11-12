package com.antivirusalai

import org.junit.Assert.assertEquals
import org.junit.Test

class PendingScanRegistryTest {
    @Test
    fun reservesUniquePathsAndDeduplicatesRepeatedEvents() {
        val registry = PendingScanRegistry(capacity = 2)

        assertEquals(PendingScanReservation.RESERVED, registry.reserve("/shared/Download/a.bin"))
        assertEquals(PendingScanReservation.DUPLICATE, registry.reserve("/shared/Download/a.bin"))
        assertEquals(1, registry.size())
    }

    @Test
    fun enforcesCapacityUntilAnActiveScanIsReleased() {
        val registry = PendingScanRegistry(capacity = 1)

        assertEquals(PendingScanReservation.RESERVED, registry.reserve("/shared/Download/a.bin"))
        assertEquals(PendingScanReservation.FULL, registry.reserve("/shared/Download/b.bin"))

        registry.release("/shared/Download/a.bin")

        assertEquals(PendingScanReservation.RESERVED, registry.reserve("/shared/Download/b.bin"))
        assertEquals(1, registry.size())
    }

    @Test
    fun releasingUnknownPathIsSafe() {
        val registry = PendingScanRegistry(capacity = 1)
        registry.release("/missing/file")
        assertEquals(0, registry.size())
    }
}
