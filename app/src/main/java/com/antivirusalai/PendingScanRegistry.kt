package com.antivirusalai

/** Result of reserving one path in the bounded real-time scan queue. */
internal enum class PendingScanReservation { RESERVED, DUPLICATE, FULL }

/**
 * Tracks queued and actively scanned paths so repeated FileObserver events
 * cannot create duplicate or unbounded scan work.
 */
internal class PendingScanRegistry(private val capacity: Int) {
    private val pending = LinkedHashSet<String>()

    init {
        require(capacity > 0) { "Queue capacity must be positive." }
    }

    @Synchronized
    fun reserve(canonicalPath: String): PendingScanReservation {
        require(canonicalPath.isNotBlank()) { "A canonical file path is required." }
        if (canonicalPath in pending) return PendingScanReservation.DUPLICATE
        if (pending.size >= capacity) return PendingScanReservation.FULL
        pending += canonicalPath
        return PendingScanReservation.RESERVED
    }

    @Synchronized
    fun release(canonicalPath: String) {
        pending.remove(canonicalPath)
    }

    @Synchronized
    fun size(): Int = pending.size
}
