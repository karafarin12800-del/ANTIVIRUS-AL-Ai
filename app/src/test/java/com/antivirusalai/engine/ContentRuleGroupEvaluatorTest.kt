package com.antivirusalai.engine

import com.antivirusalai.intel.ThreatClassification
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ContentRuleGroupEvaluatorTest {
    private fun rule(index: Int) = ContentSignatureRule(
        id = "FALLSPY-${index.toString().padStart(2, '0')}",
        familyId = "FALLSPY_ANDROID",
        classification = ThreatClassification.SUSPICIOUS,
        confidence = 75,
        pattern = "INDICATOR_${index}".toByteArray(Charsets.US_ASCII),
        description = "Harmless test indicator.",
        sourceId = "WITHSECURELABS_IOCS",
        licenseId = "BSD-2-Clause",
        groupId = "WITHSECURE_FALLSPY",
        minimumGroupMatches = 4
    )

    @Test
    fun belowFourOfTenIsPartialAndNeverQualified() {
        val rules = (1..10).map(::rule)
        val matches = setOf("FALLSPY-01", "FALLSPY-02", "FALLSPY-03")
        assertTrue(ContentRuleGroupEvaluator.qualifiedMatches(rules, matches).isEmpty())
        val partial = ContentRuleGroupEvaluator.partialMatches(rules, matches).single()
        assertEquals(3, partial.matchedCount)
        assertEquals(4, partial.requiredCount)
    }

    @Test
    fun fourOfTenQualifiesOnlyTheFourMatchedIndicators() {
        val rules = (1..10).map(::rule)
        val matches = setOf("FALLSPY-01", "FALLSPY-02", "FALLSPY-03", "FALLSPY-04")
        val qualified = ContentRuleGroupEvaluator.qualifiedMatches(rules, matches)
        assertEquals(4, qualified.size)
        assertTrue(qualified.all { it.groupId == "WITHSECURE_FALLSPY" })
        assertTrue(ContentRuleGroupEvaluator.partialMatches(rules, matches).isEmpty())
    }

    @Test
    fun unmatchedRulesFromOtherGroupsDoNotIncreaseThreshold() {
        val rules = (1..10).map(::rule) + ContentSignatureRule(
            id = "OTHER-01",
            familyId = "OTHER_FAMILY",
            classification = ThreatClassification.SUSPICIOUS,
            confidence = 50,
            pattern = "OTHER_PATTERN".toByteArray(Charsets.US_ASCII),
            description = "Other group fixture.",
            sourceId = "INTERNAL_TEST",
            licenseId = "MIT",
            groupId = "OTHER_GROUP",
            minimumGroupMatches = 1
        )
        val matches = setOf("FALLSPY-01", "FALLSPY-02", "FALLSPY-03")
        assertTrue(ContentRuleGroupEvaluator.qualifiedMatches(rules, matches).isEmpty())
    }
}
