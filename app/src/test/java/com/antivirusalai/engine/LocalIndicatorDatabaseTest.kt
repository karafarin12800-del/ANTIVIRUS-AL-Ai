package com.antivirusalai.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class LocalIndicatorDatabaseTest {
    @Test
    fun matchesOnlyTheBenignProjectFixture() {
        assertEquals(
            LocalIndicatorDatabase.Match.BENIGN_PROJECT_TEST_MARKER,
            LocalIndicatorDatabase.lookup(LocalIndicatorDatabase.BENIGN_TEST_MARKER_SHA256)
        )
    }

    @Test
    fun unknownHashIsNotTreatedAsKnownIndicator() {
        assertNull(LocalIndicatorDatabase.lookup("0".repeat(64)))
    }
}
