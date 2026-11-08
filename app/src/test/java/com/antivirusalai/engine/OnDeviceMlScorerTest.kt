package com.antivirusalai.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class OnDeviceMlScorerTest {
    @Test
    fun forestReturnsLeafRiskAndPathExplanation() {
        val index = OnDeviceMlScorer.FEATURE_NAMES.indexOf("permission_count")
        val tree = MlDecisionTree(
            listOf(
                MlTreeNode(index, 2.5f, 1, 2, 0f),
                MlTreeNode(-1, 0f, -1, -1, 0.05f),
                MlTreeNode(-1, 0f, -1, -1, 0.90f)
            )
        )
        val model = MlForestModel(
            version = "unit-test",
            threshold = 0.80f,
            featureNames = OnDeviceMlScorer.FEATURE_NAMES,
            trees = listOf(tree, tree, tree)
        )
        val (score, explanation) = model.predict(
            MlFeatureVector(
                featureCount = OnDeviceMlScorer.FEATURE_NAMES.size,
                values = mapOf("permission_count" to 7f)
            )
        )
        assertEquals(0.90f, score, 0.0001f)
        assertEquals(listOf("permission_count"), explanation)
    }

    @Test
    fun benignBranchRemainsBelowDecisionThreshold() {
        val index = OnDeviceMlScorer.FEATURE_NAMES.indexOf("debuggable")
        val tree = MlDecisionTree(
            listOf(
                MlTreeNode(index, 0.5f, 1, 2, 0f),
                MlTreeNode(-1, 0f, -1, -1, 0.02f),
                MlTreeNode(-1, 0f, -1, -1, 0.95f)
            )
        )
        val model = MlForestModel(
            version = "unit-test",
            threshold = 0.80f,
            featureNames = OnDeviceMlScorer.FEATURE_NAMES,
            trees = listOf(tree)
        )
        val (score, _) = model.predict(MlFeatureVector(1, mapOf("debuggable" to 0f)))
        assertTrue(score < model.threshold)
    }
}
