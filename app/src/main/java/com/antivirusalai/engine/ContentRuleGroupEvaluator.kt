package com.antivirusalai.engine

data class PartialContentRuleGroup(
    val groupId: String,
    val familyId: String,
    val matchedCount: Int,
    val requiredCount: Int
)

/**
 * Applies the source rule's grouped condition after native byte matching.
 * The native scanner emits pattern IDs; a verdict is eligible only when the
 * minimum number of distinct patterns in the source group has matched.
 */
object ContentRuleGroupEvaluator {
    fun qualifiedMatches(
        rules: List<ContentSignatureRule>,
        matchedRuleIds: Set<String>
    ): List<ContentSignatureRule> {
        return rules.groupBy { it.groupId }.values.flatMap { group ->
            val matched = group.filter { it.id in matchedRuleIds }
            if (matched.size >= group.first().minimumGroupMatches) matched else emptyList()
        }.sortedBy { it.id }
    }

    fun partialMatches(
        rules: List<ContentSignatureRule>,
        matchedRuleIds: Set<String>
    ): List<PartialContentRuleGroup> {
        return rules.groupBy { it.groupId }.values.mapNotNull { group ->
            val matchedCount = group.count { it.id in matchedRuleIds }
            val requiredCount = group.first().minimumGroupMatches
            if (matchedCount in 1 until requiredCount) {
                PartialContentRuleGroup(
                    groupId = group.first().groupId,
                    familyId = group.first().familyId,
                    matchedCount = matchedCount,
                    requiredCount = requiredCount
                )
            } else {
                null
            }
        }.sortedBy { it.groupId }
    }
}
