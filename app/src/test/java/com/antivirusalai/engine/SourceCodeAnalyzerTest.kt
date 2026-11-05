package com.antivirusalai.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SourceCodeAnalyzerTest {
    @Test
    fun supportsCommonSourceAndConfigExtensions() {
        assertTrue(SourceCodeAnalyzer.supports("MainActivity.kt"))
        assertTrue(SourceCodeAnalyzer.supports("server.py"))
        assertTrue(SourceCodeAnalyzer.supports("client.ts"))
        assertTrue(SourceCodeAnalyzer.supports("settings.json"))
        assertFalse(SourceCodeAnalyzer.supports("photo.jpg"))
        assertNull(SourceCodeAnalyzer.analyze("photo.jpg", "binary"))
    }

    @Test
    fun reportsUnclosedKotlinBlockWithSourceLocation() {
        val report = SourceCodeAnalyzer.analyze(
            "Example.kt",
            "fun main() {\n    val answer = 42\n"
        )
        assertNotNull(report)
        assertTrue(report!!.diagnostics.any {
            it.ruleId == "UNCLOSED_DELIMITER" && it.line == 1
        })
    }

    @Test
    fun reportsUnterminatedString() {
        val report = SourceCodeAnalyzer.analyze(
            "Example.java",
            "class Example {\n  String title = \"unfinished;\n}"
        )
        assertTrue(report!!.diagnostics.any { it.ruleId == "UNTERMINATED_STRING" && it.line == 2 })
    }

    @Test
    fun ignoresSecurityPatternsInsideLineComments() {
        val report = SourceCodeAnalyzer.analyze(
            "Example.js",
            "// eval(untrustedInput)\nconst message = \"hello\";"
        )
        assertFalse(report!!.diagnostics.any { it.ruleId == "DYNAMIC_CODE_EXECUTION" })
    }

    @Test
    fun detectsLikelyHardcodedSecretAndReportsLine() {
        val report = SourceCodeAnalyzer.analyze(
            "config.py",
            "region = \"eu\"\napi_key = \"live_secret_value_12345\""
        )
        val finding = report!!.diagnostics.firstOrNull { it.ruleId == "HARDCODED_SECRET" }
        assertNotNull(finding)
        assertEquals(2, finding!!.line)
        assertEquals(CodeIssueSeverity.HIGH, finding.severity)
    }

    @Test
    fun detectsPythonSyntaxHintAndRiskySubprocessPattern() {
        val report = SourceCodeAnalyzer.analyze(
            "worker.py",
            "def process(command)\n    subprocess.run(command, shell=True)"
        )
        assertTrue(report!!.diagnostics.any { it.ruleId == "PYTHON_MISSING_COLON" })
        assertTrue(report.diagnostics.any { it.ruleId == "PYTHON_SHELL_TRUE" })
    }

    @Test
    fun doesNotFlagValidSingleLinePythonSuite() {
        val report = SourceCodeAnalyzer.analyze(
            "inline.py",
            "if ready: print('ok')"
        )
        assertFalse(report!!.diagnostics.any { it.ruleId == "PYTHON_MISSING_COLON" })
    }

    @Test
    fun findsTodoMarkersInsideComments() {
        val report = SourceCodeAnalyzer.analyze(
            "notes.js",
            "// TODO: remove temporary compatibility path"
        )
        assertTrue(report!!.diagnostics.any { it.ruleId == "TODO_OR_FIXME" })
    }

    @Test
    fun reportsInvalidJsonStructure() {
        val report = SourceCodeAnalyzer.analyze(
            "settings.json",
            "{\"enabled\": true,}"
        )
        assertTrue(report!!.diagnostics.any { it.ruleId == "JSON_SYNTAX" })
    }

    @Test
    fun reportsMismatchedXmlTags() {
        val report = SourceCodeAnalyzer.analyze(
            "layout.xml",
            "<root><item></root>"
        )
        assertTrue(report!!.diagnostics.any {
            it.ruleId == "XML_MISMATCHED_TAG" || it.ruleId == "XML_UNCLOSED_TAG"
        })
    }

    @Test
    fun rejectsBinaryLikeSourceContent() {
        val binaryLike = "fun main() {" + 0.toChar() + 1.toChar() + "}"
        val report = SourceCodeAnalyzer.analyze("not-really-code.kt", binaryLike)
        assertNotNull(report)
        assertFalse(report!!.completed)
        assertTrue(report.limitationEn.orEmpty().contains("NUL"))
    }

    @Test
    fun doesNotTreatAndroidManifestNamespaceAsCleartextTraffic() {
        val report = SourceCodeAnalyzer.analyze(
            "AndroidManifest.xml",
            "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"></manifest>"
        )
        assertFalse(report!!.diagnostics.any { it.ruleId == "CLEARTEXT_HTTP" })
    }

    @Test
    fun oversizedSourceReturnsExplicitLimitedReport() {
        val report = SourceCodeAnalyzer.limitedReport("large.kt")
        assertNotNull(report)
        assertFalse(report!!.completed)
        assertEquals("Kotlin", report.language)
    }
}
