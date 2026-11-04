package com.antivirusalai.engine

/**
 * Future boundary for an opt-in, hash-only reputation lookup.
 * The MVP has no endpoint, API key, network permission, or file-upload path.
 */
sealed interface ThreatLookup {
    data object NotConfigured : ThreatLookup
    data class KnownHash(
        val family: String?,
        val source: String,
        val confidence: String
    ) : ThreatLookup
    data class NoMatch(val source: String) : ThreatLookup
}

interface ThreatIntelligenceProvider {
    suspend fun lookupSha256(sha256: String): ThreatLookup
}

class OfflineThreatIntelligenceProvider : ThreatIntelligenceProvider {
    override suspend fun lookupSha256(sha256: String): ThreatLookup =
        ThreatLookup.NotConfigured
}
