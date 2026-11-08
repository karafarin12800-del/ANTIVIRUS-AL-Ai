package com.antivirusalai.engine

import kotlinx.coroutines.CancellationException

/**
 * Runs one analysis stage in isolation. A failed optional engine must not stop
 * independent stages (for example hash reputation, static parsing, or ML).
 * Fatal VM errors are deliberately not swallowed.
 */
internal enum class ScanStageState { COMPLETED, FAILED }

internal data class ScanStageExecution<T>(
    val stageId: String,
    val state: ScanStageState,
    val value: T?,
    val failureCode: String? = null
) {
    val completed: Boolean get() = state == ScanStageState.COMPLETED
}

internal object ScanStageRunner {
    fun <T> execute(stageId: String, action: () -> T): ScanStageExecution<T> {
        require(stageId.matches(Regex("[A-Z0-9_]{1,48}"))) { "Invalid scan stage identifier." }
        return try {
            ScanStageExecution(stageId, ScanStageState.COMPLETED, action())
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: LinkageError) {
            ScanStageExecution(stageId, ScanStageState.FAILED, null, "LINKAGE_ERROR")
        } catch (error: Exception) {
            val code = error.javaClass.simpleName
                .uppercase()
                .replace(Regex("[^A-Z0-9_]"), "_")
                .take(48)
                .ifBlank { "ENGINE_ERROR" }
            ScanStageExecution(stageId, ScanStageState.FAILED, null, code)
        }
    }

    fun failureEvidence(execution: ScanStageExecution<*>): ScanEvidence? {
        if (execution.completed) return null
        val code = execution.failureCode ?: "ENGINE_ERROR"
        return ScanEvidence(
            code = "SCAN_STAGE_${execution.stageId}_FAILED",
            title = "An analysis engine could not complete",
            detail = "Stage ${execution.stageId} failed ($code). Other independent analysis stages continue; this failure is not evidence that the file is safe.",
            severity = EvidenceSeverity.INFO
        )
    }
}
