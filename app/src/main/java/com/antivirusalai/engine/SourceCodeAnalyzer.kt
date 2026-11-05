package com.antivirusalai.engine

import java.util.ArrayDeque

enum class CodeIssueSeverity { ERROR, HIGH, MEDIUM, LOW, INFO }

data class CodeDiagnostic(
    val ruleId: String,
    val titleFa: String,
    val titleEn: String,
    val detailFa: String,
    val detailEn: String,
    val line: Int,
    val column: Int,
    val severity: CodeIssueSeverity
)

data class CodeAnalysisReport(
    val language: String,
    val lineCount: Int,
    val diagnostics: List<CodeDiagnostic>,
    val completed: Boolean = true,
    val limitationFa: String? = null,
    val limitationEn: String? = null
) {
    val actionableIssueCount: Int
        get() = diagnostics.count {
            it.severity == CodeIssueSeverity.ERROR ||
                it.severity == CodeIssueSeverity.HIGH ||
                it.severity == CodeIssueSeverity.MEDIUM
        }
}

object SourceCodeAnalyzer {
    const val MAX_SOURCE_BYTES = 1024L * 1024L
    private const val MAX_FINDINGS = 80

    private val languages = mapOf(
        "kt" to "Kotlin", "kts" to "Kotlin script", "java" to "Java",
        "py" to "Python", "pyw" to "Python",
        "js" to "JavaScript", "mjs" to "JavaScript", "cjs" to "JavaScript", "jsx" to "JSX",
        "ts" to "TypeScript", "tsx" to "TSX",
        "c" to "C", "h" to "C/C++ header", "cc" to "C++", "cpp" to "C++", "cxx" to "C++",
        "hpp" to "C++ header", "cs" to "C#", "go" to "Go", "rs" to "Rust",
        "php" to "PHP", "rb" to "Ruby", "swift" to "Swift",
        "sh" to "Shell", "bash" to "Shell", "zsh" to "Shell", "ps1" to "PowerShell",
        "sql" to "SQL", "html" to "HTML", "htm" to "HTML", "css" to "CSS", "scss" to "SCSS",
        "xml" to "XML", "json" to "JSON", "yml" to "YAML", "yaml" to "YAML",
        "gradle" to "Gradle", "properties" to "Properties", "toml" to "TOML"
    )

    private data class OpenDelimiter(val char: Char, val offset: Int)
    private data class Rule(
        val id: String,
        val titleFa: String,
        val titleEn: String,
        val detailFa: String,
        val detailEn: String,
        val severity: CodeIssueSeverity,
        val expression: Regex,
        val extensions: Set<String>? = null
    )

    fun supports(fileName: String): Boolean = languageFor(fileName) != null

    fun languageFor(fileName: String): String? =
        languages[fileName.substringAfterLast('.', "").lowercase()]

    fun limitedReport(fileName: String): CodeAnalysisReport? {
        val language = languageFor(fileName) ?: return null
        return CodeAnalysisReport(
            language = language,
            lineCount = 0,
            diagnostics = emptyList(),
            completed = false,
            limitationFa = "فایل کد از سقف ۱ مگابایتِ تحلیل ایستا بزرگ‌تر است؛ فقط هش فایل بررسی شد.",
            limitationEn = "The source file exceeds the 1 MB static-analysis limit; only its file hash was checked."
        )
    }

    fun analyze(fileName: String, source: String): CodeAnalysisReport? {
        val extension = fileName.substringAfterLast('.', "").lowercase()
        val language = languages[extension] ?: return null
        if (source.any { it.code == 0 }) {
            return CodeAnalysisReport(
                language = language,
                lineCount = 0,
                diagnostics = emptyList(),
                completed = false,
                limitationFa = "محتوا دارای نویسه صفر است و به‌عنوان متن کد قابل اعتماد تحلیل نشد.",
                limitationEn = "The content contains NUL bytes and was not treated as trustworthy source text."
            )
        }
        val findings = mutableListOf<CodeDiagnostic>()
        val codeOnly = inspectLexicalStructure(source, extension, findings)

        if (extension == "py" || extension == "pyw") {
            inspectPythonColons(source, codeOnly, findings)
        }
        if (extension == "json") {
            JsonSyntaxValidator(source).validate()?.let { failure ->
                findings += diagnostic(
                    source, failure.offset, "JSON_SYNTAX",
                    "خطای ساختار JSON", "JSON syntax error",
                    failure.messageFa, failure.messageEn, CodeIssueSeverity.ERROR
                )
            }
        }
        if (extension == "xml") {
            inspectXmlTags(source, codeOnly, findings)
        }
        applySecurityRules(source, codeOnly, extension, findings)

        val finalFindings = findings
            .distinctBy { it.ruleId + ":" + it.line + ":" + it.column }
            .sortedWith(compareBy<CodeDiagnostic>({ it.line }, { it.column }, { it.ruleId }))
            .take(MAX_FINDINGS)

        return CodeAnalysisReport(
            language = language,
            lineCount = source.count { it == '\n' } + 1,
            diagnostics = finalFindings
        )
    }

    private fun inspectLexicalStructure(
        source: String,
        extension: String,
        findings: MutableList<CodeDiagnostic>
    ): String {
        val output = source.toCharArray()
        val delimiters = ArrayDeque<OpenDelimiter>()
        val hashComments = extension in setOf(
            "py", "pyw", "rb", "sh", "bash", "zsh", "ps1", "yml", "yaml",
            "toml", "properties"
        )
        val sqlComments = extension == "sql"
        val htmlComments = extension in setOf("html", "htm", "xml")
        val slashComments = extension !in setOf(
            "html", "htm", "xml", "css", "scss", "properties", "toml", "yaml", "yml"
        )
        val supportsTriple = extension in setOf("py", "pyw", "kt", "kts")
        var state = 0 // 0=code, 1=line comment, 2=block comment, 3=HTML comment, 4=string
        var quote = 0.toChar()
        var quoteStart = 0
        var triple = false
        var escaped = false
        var commentStart = 0
        var index = 0

        fun blank(position: Int) {
            if (output[position] != '\n' && output[position] != '\r') output[position] = ' '
        }

        while (index < source.length) {
            val ch = source[index]
            when (state) {
                0 -> when {
                    htmlComments && source.startsWith("<!--", index) -> {
                        commentStart = index
                        for (p in index until minOf(index + 4, output.size)) blank(p)
                        state = 3
                        index += 4
                    }
                    slashComments && source.startsWith("//", index) -> {
                        commentStart = index
                        blank(index); blank(index + 1)
                        state = 1
                        index += 2
                    }
                    (slashComments || extension == "css" || extension == "scss") &&
                        source.startsWith("/*", index) -> {
                        commentStart = index
                        blank(index); blank(index + 1)
                        state = 2
                        index += 2
                    }
                    hashComments && ch == '#' -> {
                        commentStart = index
                        blank(index)
                        state = 1
                        index++
                    }
                    sqlComments && source.startsWith("--", index) -> {
                        commentStart = index
                        blank(index); blank(index + 1)
                        state = 1
                        index += 2
                    }
                    ch == '"' || ch == '\'' || ch.code == 96 -> {
                        quote = ch
                        quoteStart = index
                        val tripleToken = String(charArrayOf(ch, ch, ch))
                        triple = supportsTriple && ch.code != 96 &&
                            source.startsWith(tripleToken, index) &&
                            (extension == "py" || extension == "pyw" || ch == '"')
                        state = 4
                        escaped = false
                        index += if (triple) 3 else 1
                    }
                    ch == '(' || ch == '[' || ch == '{' -> {
                        delimiters.addLast(OpenDelimiter(ch, index))
                        index++
                    }
                    ch == ')' || ch == ']' || ch == '}' -> {
                        val expected = when (ch) {
                            ')' -> '('
                            ']' -> '['
                            else -> '{'
                        }
                        if (delimiters.lastOrNull()?.char == expected) {
                            delimiters.removeLast()
                        } else {
                            findings += diagnostic(
                                source, index, "UNMATCHED_CLOSING_DELIMITER",
                                "علامت بسته‌شدن نامتوازن", "Unmatched closing delimiter",
                                "این علامت بسته‌شدن، بازکننده متناظرِ معتبر ندارد.",
                                "This closing delimiter has no matching opening delimiter.",
                                CodeIssueSeverity.ERROR
                            )
                        }
                        index++
                    }
                    else -> index++
                }
                1 -> {
                    if (ch == '\n') state = 0 else blank(index)
                    index++
                }
                2 -> {
                    if (source.startsWith("*/", index)) {
                        blank(index); blank(index + 1)
                        state = 0
                        index += 2
                    } else {
                        blank(index)
                        index++
                    }
                }
                3 -> {
                    if (source.startsWith("-->", index)) {
                        for (p in index until minOf(index + 3, output.size)) blank(p)
                        state = 0
                        index += 3
                    } else {
                        blank(index)
                        index++
                    }
                }
                else -> {
                    if (!triple && ch == '\n' && quote.code != 96 && !escaped) {
                        findings += diagnostic(
                            source, quoteStart, "UNTERMINATED_STRING",
                            "رشته بسته نشده", "Unterminated string literal",
                            "رشته در همین خط شروع شده اما پیش از پایان خط بسته نشده است.",
                            "The string starts on this line but is not closed before the line ends.",
                            CodeIssueSeverity.ERROR
                        )
                        state = 0
                        continue
                    }
                    when {
                        escaped -> {
                            escaped = false
                            index++
                        }
                        ch == '\\' -> {
                            escaped = true
                            index++
                        }
                        triple && source.startsWith(String(charArrayOf(quote, quote, quote)), index) -> {
                            state = 0
                            index += 3
                        }
                        !triple && ch == quote -> {
                            state = 0
                            index++
                        }
                        else -> index++
                    }
                }
            }
        }

        when (state) {
            2, 3 -> findings += diagnostic(
                source, commentStart, "UNTERMINATED_COMMENT",
                "توضیح بسته نشده", "Unterminated comment",
                "بخش توضیحات شروع شده اما علامت پایان آن پیدا نشد.",
                "A comment was opened but its closing marker was not found.",
                CodeIssueSeverity.ERROR
            )
            4 -> findings += diagnostic(
                source, quoteStart, "UNTERMINATED_STRING",
                "رشته بسته نشده", "Unterminated string literal",
                "علامت پایانی رشته در فایل پیدا نشد.",
                "The closing quote for this string was not found.",
                CodeIssueSeverity.ERROR
            )
        }

        while (delimiters.isNotEmpty()) {
            val opening = delimiters.removeLast()
            findings += diagnostic(
                source, opening.offset, "UNCLOSED_DELIMITER",
                "علامت باز بدون جفت", "Unclosed delimiter",
                "برای علامت باز «" + opening.char + "» علامت بسته‌شدن متناظر پیدا نشد.",
                "No matching closing delimiter was found for '" + opening.char + "'.",
                CodeIssueSeverity.ERROR
            )
        }
        return String(output)
    }

    private fun inspectPythonColons(
        source: String,
        codeOnly: String,
        findings: MutableList<CodeDiagnostic>
    ) {
        val keywords = Regex("""^(if|elif|else|for|while|def|class|try|except|finally|with)\b""")
        var offset = 0
        codeOnly.split('\n').forEach { line ->
            val first = line.trim()
            if (keywords.containsMatchIn(first) && first.isNotBlank() && !first.endsWith(":")) {
                findings += diagnostic(
                    source, offset + line.indexOfFirst { !it.isWhitespace() }.coerceAtLeast(0),
                    "PYTHON_MISSING_COLON",
                    "احتمال جاافتادن دونقطه", "Possible missing colon",
                    "در پایان دستور کنترلی یا تعریف پایتون معمولاً باید «:» قرار بگیرد.",
                    "Python control statements and definitions normally end with a colon.",
                    CodeIssueSeverity.ERROR
                )
            }
            offset += line.length + 1
        }
    }

    private fun applySecurityRules(
        source: String,
        codeOnly: String,
        extension: String,
        findings: MutableList<CodeDiagnostic>
    ) {
        val rules = listOf(
            Rule(
                "PRIVATE_KEY_MATERIAL",
                "محتوای کلید خصوصی در فایل", "Private key material in source",
                "این فایل ظاهراً بخشی از یک کلید خصوصی را در خود دارد. آن را در کد منتشرشده یا مخزن عمومی نگه ندار.",
                "The file appears to contain private-key material. Do not keep it in published source or a public repository.",
                CodeIssueSeverity.HIGH,
                Regex("""-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----""", RegexOption.IGNORE_CASE)
            ),
            Rule(
                "HARDCODED_SECRET",
                "احتمال رمز یا توکن ثابت", "Possible hard-coded secret",
                "یک مقدار شبیه رمز، کلید API یا توکن داخل کد نوشته شده است. آن را به تنظیمات امن خارج از کد منتقل و در صورت واقعی بودن، تعویض کن.",
                "A value resembling a password, API key or token is embedded in source. Move it to secure configuration and rotate it if genuine.",
                CodeIssueSeverity.HIGH,
                Regex(
                    """\b(api[_-]?key|client[_-]?secret|access[_-]?token|password|passwd|secret)\b\s*[:=]\s*["']([^"'\\\r\n]{8,})["']""",
                    RegexOption.IGNORE_CASE
                )
            ),
            Rule(
                "CLEARTEXT_HTTP",
                "نشانی HTTP بدون رمزنگاری", "Cleartext HTTP URL",
                "نشانی HTTP پیدا شد. برای داده حساس از HTTPS استفاده کن؛ استثناهای localhost باید جداگانه بررسی شوند.",
                "An HTTP URL was found. Use HTTPS for sensitive traffic; localhost exceptions should be reviewed separately.",
                CodeIssueSeverity.MEDIUM,
                Regex("""http://(?!localhost(?::\d+)?(?:/|$)|127\.0\.0\.1(?::\d+)?(?:/|$)|10\.0\.2\.2(?::\d+)?(?:/|$))""", RegexOption.IGNORE_CASE)
            ),
            Rule(
                "DYNAMIC_CODE_EXECUTION",
                "اجرای پویای کد", "Dynamic code execution",
                "تابع eval یا exec پیدا شد. اجرای ورودی کنترل‌نشده می‌تواند به تزریق کد منجر شود؛ منبع ورودی را بررسی کن.",
                "An eval/exec call was found. Executing untrusted input can lead to code injection; review the input source.",
                CodeIssueSeverity.MEDIUM,
                Regex("""\b(?:eval|exec)\s*\(""", RegexOption.IGNORE_CASE),
                setOf("js", "mjs", "cjs", "jsx", "ts", "tsx", "py", "pyw", "php")
            ),
            Rule(
                "PYTHON_SHELL_TRUE",
                "اجرای فرمان با shell=True", "Subprocess call with shell=True",
                "ترکیب shell=True و ورودی متغیر ممکن است امکان تزریق فرمان ایجاد کند. آرگومان‌ها را به‌شکل فهرست مستقل ارسال کن.",
                "Combining shell=True with variable input can enable command injection. Prefer passing arguments as a list.",
                CodeIssueSeverity.HIGH,
                Regex("""subprocess\.(?:run|Popen|call)\s*\([^)\n]{0,400}\bshell\s*=\s*True""", RegexOption.IGNORE_CASE),
                setOf("py", "pyw")
            ),
            Rule(
                "PYTHON_UNSAFE_PICKLE",
                "بارگذاری داده با pickle", "Unsafe pickle deserialization",
                "pickle.load می‌تواند هنگام بازکردن داده غیرقابل‌اعتماد کد اجرا کند. فقط داده‌های کاملاً قابل‌اعتماد را با آن باز کن.",
                "pickle.load can execute code while loading untrusted data. Use it only with fully trusted data.",
                CodeIssueSeverity.HIGH,
                Regex("""\bpickle\.loads?\s*\(""", RegexOption.IGNORE_CASE),
                setOf("py", "pyw")
            ),
            Rule(
                "SQL_STRING_CONCATENATION",
                "ساخت پرس‌وجوی SQL با الحاق رشته", "SQL query built by string concatenation",
                "پرس‌وجوی SQL ظاهراً با الحاق رشته ساخته می‌شود. از query پارامتری و bind parameter استفاده کن.",
                "The SQL query appears to be built by string concatenation. Use parameterized queries and bind parameters.",
                CodeIssueSeverity.HIGH,
                Regex("""(?:rawQuery|execSQL|executeQuery|prepareStatement)\s*\([^;\n]{0,240}\+""", RegexOption.IGNORE_CASE),
                setOf("kt", "kts", "java", "cs", "php")
            ),
            Rule(
                "TLS_TRUST_ALL",
                "اعتبارسنجی گواهی TLS ممکن است غیرفعال باشد",
                "TLS certificate validation may be disabled",
                "یک پیاده‌سازی ظاهراً خالی برای بررسی گواهی سرور پیدا شد. اعتبارسنجی گواهی را حذف نکن.",
                "An apparently empty server-certificate validation implementation was found. Do not disable certificate validation.",
                CodeIssueSeverity.HIGH,
                Regex("""checkServerTrusted\s*\([^)]*\)\s*\{\s*\}""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)),
                setOf("kt", "kts", "java")
            ),
            Rule(
                "TLS_HOSTNAME_ALWAYS_TRUE",
                "تأیید نام میزبان همیشه true است",
                "Hostname verification always returns true",
                "بررسی نام میزبان ظاهراً بدون اعتبارسنجی موفق اعلام می‌شود. از HostnameVerifier پیش‌فرض و معتبر استفاده کن.",
                "Hostname verification appears to succeed without validation. Use the platform's default, properly validating verifier.",
                CodeIssueSeverity.HIGH,
                Regex("""HostnameVerifier[\s\S]{0,240}?return\s+true""", RegexOption.IGNORE_CASE),
                setOf("kt", "kts", "java")
            ),
            Rule(
                "WEAK_CRYPTO",
                "الگوریتم رمزنگاری ضعیف", "Weak cryptographic algorithm",
                "نام MD5، SHA-1 یا DES پیدا شد. برای کاربرد امنیتی از الگوریتم مدرن و متناسب استفاده کن.",
                "MD5, SHA-1 or DES was found. Choose a modern algorithm appropriate to the security task.",
                CodeIssueSeverity.MEDIUM,
                Regex("""(?:MessageDigest\.getInstance|Cipher\.getInstance)?\s*\(?\s*["']?(?:MD5|SHA-?1|DES)(?:/|["']|\b)""", RegexOption.IGNORE_CASE),
                setOf("kt", "kts", "java", "py", "pyw", "js", "ts", "cs", "go", "php")
            ),
            Rule(
                "XSS_HTML_SINK",
                "دست‌کاری مستقیم HTML", "Direct HTML injection sink",
                "innerHTML یا document.write پیدا شد. محتوای کنترل‌شده توسط کاربر را پیش از نمایش پاک‌سازی و اعتبارسنجی کن.",
                "innerHTML or document.write was found. Sanitize and validate user-controlled content before rendering it.",
                CodeIssueSeverity.MEDIUM,
                Regex("""(?:innerHTML|outerHTML)\s*=|document\.write\s*\(""", RegexOption.IGNORE_CASE),
                setOf("js", "mjs", "cjs", "jsx", "ts", "tsx")
            ),
            Rule(
                "EMPTY_EXCEPTION_HANDLER",
                "مدیریت خالی خطا", "Empty exception handler",
                "بلوک catch ظاهراً خالی است و ممکن است خطا را پنهان کند. خطا را مدیریت، ثبت یا دوباره پرتاب کن.",
                "An apparently empty catch block may hide failures. Handle, report or rethrow the exception.",
                CodeIssueSeverity.MEDIUM,
                Regex("""catch\s*(?:\([^)]*\))?\s*\{\s*\}""", RegexOption.IGNORE_CASE),
                setOf("kt", "kts", "java", "js", "ts", "cs", "swift")
            ),
            Rule(
                "PYTHON_BARE_EXCEPT",
                "گرفتن همه خطاها بدون نوع مشخص", "Bare Python exception handler",
                "except عمومی می‌تواند خطاهای مهم را پنهان کند. نوع استثناهای مورد انتظار را مشخص کن.",
                "A bare except can hide important failures. Catch only the exception types you expect.",
                CodeIssueSeverity.LOW,
                Regex("""(?m)^\s*except\s*:\s*(?:pass\s*)?$""", RegexOption.IGNORE_CASE),
                setOf("py", "pyw")
            ),
            Rule(
                "ANDROID_WEBVIEW_JAVASCRIPT",
                "فعال‌سازی JavaScript در WebView", "JavaScript enabled in WebView",
                "فعال‌کردن JavaScript به‌تنهایی آسیب‌پذیری قطعی نیست؛ در صورت بارگذاری محتوای غیرقابل‌اعتماد، سطح حمله را بازبینی کن.",
                "Enabling JavaScript is not a vulnerability by itself; review the attack surface if untrusted content is loaded.",
                CodeIssueSeverity.LOW,
                Regex("""setJavaScriptEnabled\s*\(\s*true\s*\)""", RegexOption.IGNORE_CASE),
                setOf("kt", "kts", "java")
            ),
            Rule(
                "TODO_OR_FIXME",
                "یادداشت تکمیل‌نشده در کد", "Unresolved TODO/FIXME marker",
                "یک نشانگر TODO یا FIXME پیدا شد. بررسی کن آیا کار یا اصلاحی باقی مانده است.",
                "A TODO or FIXME marker was found. Check whether work or a correction remains.",
                CodeIssueSeverity.LOW,
                Regex("""\b(?:TODO|FIXME)\b""", RegexOption.IGNORE_CASE)
            )
        )

        for (rule in rules) {
            if (rule.extensions != null && extension !in rule.extensions) continue
            val scanText = if (rule.id == "TODO_OR_FIXME") source else codeOnly
            for (match in rule.expression.findAll(scanText).take(5)) {
                if (rule.id == "HARDCODED_SECRET") {
                    val value = match.groupValues.getOrNull(2).orEmpty().lowercase()
                    val placeholders = listOf("placeholder", "your_", "change_me", "changeme", "example", "dummy", "test", "xxxxxxxx")
                    if (placeholders.any { value.contains(it) }) continue
                }
                findings += diagnostic(
                    source, match.range.first, rule.id,
                    rule.titleFa, rule.titleEn, rule.detailFa, rule.detailEn, rule.severity
                )
            }
        }
    }


    private fun inspectXmlTags(
        source: String,
        codeOnly: String,
        findings: MutableList<CodeDiagnostic>
    ) {
        val stack = ArrayDeque<Pair<String, Int>>()
        val pattern = Regex("""</?\s*([A-Za-z_][A-Za-z0-9_.:-]*)\b[^<>]*?>""")
        for (match in pattern.findAll(codeOnly)) {
            val token = match.value
            val name = match.groupValues[1]
            when {
                token.startsWith("</") -> {
                    if (stack.lastOrNull()?.first == name) {
                        stack.removeLast()
                    } else {
                        findings += diagnostic(
                            source, match.range.first, "XML_MISMATCHED_TAG",
                            "تگ‌های XML هماهنگ نیستند", "Mismatched XML tag",
                            "تگ بسته‌شونده با نام " + name + " با آخرین تگ بازشده مطابقت ندارد.",
                            "The closing tag '" + name + "' does not match the most recently opened tag.",
                            CodeIssueSeverity.ERROR
                        )
                    }
                }
                !token.trimEnd().endsWith("/>") -> stack.addLast(name to match.range.first)
            }
        }
        while (stack.isNotEmpty()) {
            val opened = stack.removeLast()
            findings += diagnostic(
                source, opened.second, "XML_UNCLOSED_TAG",
                "تگ XML بسته نشده", "Unclosed XML tag",
                "برای تگ " + opened.first + " تگ بسته‌شونده پیدا نشد.",
                "No closing tag was found for '" + opened.first + "'.",
                CodeIssueSeverity.ERROR
            )
        }
    }

    private data class JsonFailure(
        val offset: Int,
        val messageFa: String,
        val messageEn: String
    )

    private class JsonSyntaxValidator(private val text: String) {
        private var index = 0

        fun validate(): JsonFailure? = try {
            skipWhitespace()
            parseValue()
            skipWhitespace()
            if (index != text.length) fail(
                "پس از مقدار اصلی، نویسه اضافی وجود دارد.",
                "Unexpected content after the JSON value."
            )
            null
        } catch (failure: ParseFailure) {
            JsonFailure(failure.offset, failure.messageFa, failure.messageEn)
        }

        private class ParseFailure(
            val offset: Int,
            val messageFa: String,
            val messageEn: String
        ) : RuntimeException()

        private fun fail(fa: String, en: String): Nothing =
            throw ParseFailure(index, fa, en)

        private fun skipWhitespace() {
            while (index < text.length && text[index] in charArrayOf(' ', '\n', '\r', '\t')) index++
        }

        private fun parseValue() {
            skipWhitespace()
            if (index >= text.length) fail("مقدار JSON ناقص است.", "Expected a JSON value.")
            when (text[index]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseString()
                't' -> parseLiteral("true")
                'f' -> parseLiteral("false")
                'n' -> parseLiteral("null")
                '-', in '0'..'9' -> parseNumber()
                else -> fail("مقدار JSON معتبر نیست.", "Invalid JSON value.")
            }
        }

        private fun parseObject() {
            index++
            skipWhitespace()
            if (consume('}')) return
            while (true) {
                skipWhitespace()
                if (index >= text.length || text[index] != '"') {
                    fail("کلید شیء JSON باید رشته باشد.", "A JSON object key must be a string.")
                }
                parseString()
                skipWhitespace()
                expect(':', "پس از کلید، «:» لازم است.", "Expected ':' after the object key.")
                parseValue()
                skipWhitespace()
                if (consume('}')) return
                expect(',', "بین اعضای شیء، «,» لازم است.", "Expected ',' between object members.")
                skipWhitespace()
                if (index < text.length && text[index] == '}') {
                    fail("ویرگول پایانی در JSON مجاز نیست.", "Trailing commas are not allowed in JSON.")
                }
            }
        }

        private fun parseArray() {
            index++
            skipWhitespace()
            if (consume(']')) return
            while (true) {
                parseValue()
                skipWhitespace()
                if (consume(']')) return
                expect(',', "بین اعضای آرایه، «,» لازم است.", "Expected ',' between array elements.")
                skipWhitespace()
                if (index < text.length && text[index] == ']') {
                    fail("ویرگول پایانی در JSON مجاز نیست.", "Trailing commas are not allowed in JSON.")
                }
            }
        }

        private fun parseString() {
            expect('"', "رشته JSON باید با نقل‌قول شروع شود.", "A JSON string must start with a quote.")
            while (index < text.length) {
                val ch = text[index++]
                when {
                    ch == '"' -> return
                    ch.code < 0x20 -> fail("نویسه کنترلی خام در رشته JSON مجاز نیست.", "Unescaped control character in JSON string.")
                    ch == '\\' -> {
                        if (index >= text.length) fail("دنباله escape ناقص است.", "Incomplete escape sequence.")
                        val escaped = text[index++]
                        if (escaped == 'u') {
                            repeat(4) {
                                if (index >= text.length || text[index].digitToIntOrNull(16) == null) {
                                    fail("کد یونیکد در escape معتبر نیست.", "Invalid Unicode escape sequence.")
                                }
                                index++
                            }
                        } else if (escaped !in charArrayOf('"', '\\', '/', 'b', 'f', 'n', 'r', 't')) {
                            fail("نوع escape در JSON معتبر نیست.", "Invalid JSON escape sequence.")
                        }
                    }
                }
            }
            fail("رشته JSON بسته نشده است.", "Unterminated JSON string.")
        }

        private fun parseNumber() {
            val start = index
            consume('-')
            if (consume('0')) {
                if (index < text.length && text[index].isDigit()) {
                    fail("صفر ابتدایی در عدد JSON مجاز نیست.", "Leading zeroes are not allowed in JSON numbers.")
                }
            } else {
                if (index >= text.length || text[index] !in '1'..'9') {
                    fail("عدد JSON معتبر نیست.", "Invalid JSON number.")
                }
                while (index < text.length && text[index].isDigit()) index++
            }
            if (consume('.')) {
                if (index >= text.length || !text[index].isDigit()) {
                    fail("بخش اعشاری عدد ناقص است.", "Invalid fraction in JSON number.")
                }
                while (index < text.length && text[index].isDigit()) index++
            }
            if (index < text.length && (text[index] == 'e' || text[index] == 'E')) {
                index++
                if (index < text.length && (text[index] == '+' || text[index] == '-')) index++
                if (index >= text.length || !text[index].isDigit()) {
                    fail("توان عدد JSON ناقص است.", "Invalid exponent in JSON number.")
                }
                while (index < text.length && text[index].isDigit()) index++
            }
            if (index == start) fail("عدد JSON معتبر نیست.", "Invalid JSON number.")
        }

        private fun parseLiteral(value: String) {
            if (!text.startsWith(value, index)) fail("مقدار JSON معتبر نیست.", "Invalid JSON literal.")
            index += value.length
        }

        private fun consume(expected: Char): Boolean {
            if (index < text.length && text[index] == expected) {
                index++
                return true
            }
            return false
        }

        private fun expect(expected: Char, fa: String, en: String) {
            if (!consume(expected)) fail(fa, en)
        }
    }

    private fun diagnostic(
        source: String,
        offset: Int,
        ruleId: String,
        titleFa: String,
        titleEn: String,
        detailFa: String,
        detailEn: String,
        severity: CodeIssueSeverity
    ): CodeDiagnostic {
        val safeOffset = offset.coerceIn(0, source.length)
        var line = 1
        var column = 1
        for (index in 0 until safeOffset) {
            if (source[index] == '\n') {
                line++
                column = 1
            } else {
                column++
            }
        }
        return CodeDiagnostic(
            ruleId, titleFa, titleEn, detailFa, detailEn,
            line, column, severity
        )
    }
}