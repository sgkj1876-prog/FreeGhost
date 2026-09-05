package com.freeghost.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.*
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.zip.ZipInputStream

class MainActivity : Activity() {

    private var arabic = true

    private lateinit var title: TextView
    private lateinit var subtitle: TextView
    private lateinit var pick: Button
    private lateinit var lang: Button
    private lateinit var output: TextView

    private val purple = 0xff7c5cff.toInt()
    private val bg = 0xff101318.toInt()
    private val card = 0xff191e26.toInt()
    private val textColor = 0xfff3f4f6.toInt()
    private val mutedColor = 0xffa7adb8.toInt()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildUi()
    }

    private fun buildUi() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 32, 28, 24)
            setBackgroundColor(bg)
        }

        title = TextView(this).apply {
            textSize = 28f
            setTextColor(textColor)
            setTypeface(null, 1)
        }

        subtitle = TextView(this).apply {
            textSize = 14f
            setTextColor(mutedColor)
            setPadding(0, 8, 0, 24)
        }

        lang = Button(this).apply {
            setOnClickListener {
                arabic = !arabic
                updateText()
            }
        }

        pick = Button(this).apply {
            setOnClickListener {
                chooseApk()
            }
        }

        output = TextView(this).apply {
            textSize = 14f
            setTextColor(textColor)
            setPadding(18, 18, 18, 18)
            setBackgroundColor(card)
            gravity = Gravity.START
        }

        root.addView(title)
        root.addView(subtitle)

        root.addView(
            lang,
            LinearLayout.LayoutParams(-1, 55)
        )

        root.addView(
            pick,
            LinearLayout.LayoutParams(-1, 58).apply {
                topMargin = 12
            }
        )

        root.addView(
            output,
            LinearLayout.LayoutParams(-1, 0, 1f).apply {
                topMargin = 18
            }
        )

        setContentView(root)
        updateText()
    }

    private fun updateText() {
        title.text = "Free Ghost"

        subtitle.text =
            if (arabic)
                "محلل APK محلي — أدلة قابلة للتفسير"
            else
                "Local APK analyzer — explainable evidence"

        lang.text =
            if (arabic) "English" else "العربية"

        pick.text =
            if (arabic) "اختيار APK وتحليله"
            else "Choose APK & Analyze"

        if (output.text.isEmpty()) {
            output.text =
                if (arabic)
                    "اختر ملف APK لبدء التحليل."
                else
                    "Choose an APK to start analysis."
        }

        (window.decorView as View).layoutDirection =
            if (arabic)
                View.LAYOUT_DIRECTION_RTL
            else
                View.LAYOUT_DIRECTION_LTR
    }

    private fun chooseApk() {
        startActivityForResult(
            Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                type = "application/vnd.android.package-archive"
                addCategory(Intent.CATEGORY_OPENABLE)
            },
            42
        )
    }

    override fun onActivityResult(
        req: Int,
        res: Int,
        data: Intent?
    ) {
        super.onActivityResult(req, res, data)

        if (req == 42 && res == RESULT_OK) {
            data?.data?.let {
                analyze(it)
            }
        }
    }

    private fun analyze(uri: Uri) {
        output.text =
            if (arabic)
                "جاري التحليل…"
            else
                "Analyzing…"

        Thread {
            try {
                val r = Analyzer.analyze(contentResolver, uri)

                runOnUiThread {
                    output.text =
                        if (arabic) r.ar else r.en
                }

            } catch (e: Exception) {
                runOnUiThread {
                    output.text =
                        (if (arabic)
                            "فشل التحليل: "
                        else
                            "Analysis failed: ") +
                                (e.message ?: "Unknown error")
                }
            }
        }.start()
    }
}

object Analyzer {

    data class R(
        val ar: String,
        val en: String
    )

    private data class DexResult(
        val name: String,
        val strings: List<String>,
        val urls: List<String>
    )

    private val urlRegex =
        Regex(
            """https?://[^\s"'<>]+""",
            RegexOption.IGNORE_CASE
        )

    private val interestingRegex =
        Regex(
            """(?i)(https?://|socket|webview|dexclassloader|runtime|getruntime|accessibilityservice|deviceadmin|request_install_packages|system_alert_window|bind_accessibility_service|root|su\b|shell|exec\(|loadlibrary|native|firebase|telegram|discord)"""
        )

    fun analyze(
        cr: android.content.ContentResolver,
        uri: Uri
    ): R {

        val sha = MessageDigest.getInstance("SHA-256")
        var size = 0L

        /*
         * المرحلة الأولى:
         * حساب الحجم والـSHA-256 بدون تحميل الـAPK كله إلى الذاكرة.
         */
        cr.openInputStream(uri)!!.use { input ->

            val buf = ByteArray(65536)

            while (true) {
                val n = input.read(buf)

                if (n < 0) break

                size += n
                sha.update(buf, 0, n)
            }
        }

        var dexCount = 0
        var soCount = 0
        var manifest = false
        var resources = false

        var totalStrings = 0
        val allUrls = linkedSetOf<String>()
        val interesting = linkedSetOf<String>()
        val dexNames = mutableListOf<String>()
        val dexResults = mutableListOf<DexResult>()

        /*
         * المرحلة الثانية:
         * قراءة كل عناصر ZIP داخل APK.
         */
        cr.openInputStream(uri)!!.use { raw ->

            ZipInputStream(
                BufferedInputStream(raw)
            ).use { zip ->

                while (true) {

                    val entry = zip.nextEntry ?: break
                    val name = entry.name

                    when {
                        name == "AndroidManifest.xml" -> {
                            manifest = true
                        }

                        name == "resources.arsc" -> {
                            resources = true
                        }

                        name.endsWith(".so", true) -> {
                            soCount++
                        }

                        name.endsWith(".dex", true) -> {

                            dexCount++
                            dexNames.add(name)

                            val data = readEntry(zip)
                            val result =
                                parseDexStrings(name, data)

                            dexResults.add(result)

                            totalStrings +=
                                result.strings.size

                            result.urls.forEach {
                                allUrls.add(it)
                            }

                            result.strings
                                .filter {
                                    interestingRegex.containsMatchIn(it)
                                }
                                .take(100)
                                .forEach {
                                    interesting.add(
                                        "[$name] $it"
                                    )
                                }
                        }

                        name.endsWith(".xml", true) ||
                        name.startsWith("assets/", true) ||
                        name.startsWith("res/", true) -> {

                            /*
                             * لا نقرأ الملفات الضخمة كاملة.
                             * نأخذ فقط كمية معقولة للتحليل النصي.
                             */
                            val data =
                                readEntryLimited(
                                    zip,
                                    4 * 1024 * 1024
                                )

                            val text =
                                String(
                                    data,
                                    Charsets.ISO_8859_1
                                )

                            urlRegex
                                .findAll(text)
                                .take(100)
                                .forEach {
                                    allUrls.add(
                                        it.value.trimEnd(
                                            '.', ',', ';'
                                        )
                                    )
                                }

                            extractPrintableStrings(data)
                                .filter {
                                    interestingRegex
                                        .containsMatchIn(it)
                                }
                                .take(50)
                                .forEach {
                                    interesting.add(
                                        "[$name] $it"
                                    )
                                }
                        }
                    }

                    zip.closeEntry()
                }
            }
        }

        /*
         * استخراج أسماء Strings مفيدة من جميع DEX.
         */
        val uniqueStrings =
            dexResults
                .flatMap { it.strings }
                .asSequence()
                .map { it.trim() }
                .filter { it.length >= 4 }
                .distinct()
                .sortedWith(
                    compareByDescending<String> {
                        interestingRegex.containsMatchIn(it)
                    }.thenByDescending {
                        it.length
                    }
                )
                .toList()

        val shaHex =
            sha.digest().joinToString("") {
                String.format(
                    Locale.US,
                    "%02x",
                    it
                )
            }

        /*
         * مؤشر تحليلي تقريبي فقط.
         * لا يعتبر حكمًا بأن التطبيق ضار.
         */
        var score = 20

        if (dexCount > 0) score += 15
        if (soCount > 0) score += 8
        if (manifest) score += 5
        if (resources) score += 5
        if (allUrls.isNotEmpty()) score += 10
        if (interesting.isNotEmpty()) score += 15
        if (dexCount > 1) score += 5

        score = score.coerceIn(0, 95)

        val topStrings =
            uniqueStrings
                .filter {
                    it.length <= 300 &&
                    !it.contains('\u0000')
                }
                .take(35)

        val topInteresting =
            interesting
                .take(35)

        val dexList =
            if (dexNames.isEmpty())
                "لا يوجد"
            else
                dexNames.joinToString("\n") {
                    "• $it"
                }

        val urlList =
            if (allUrls.isEmpty())
                "لا توجد روابط HTTP/HTTPS واضحة"
            else
                allUrls
                    .take(30)
                    .joinToString("\n") {
                        "• $it"
                    }

        val interestingList =
            if (topInteresting.isEmpty())
                "لا توجد مؤشرات نصية بارزة"
            else
                topInteresting.joinToString("\n") {
                    "• $it"
                }

        val stringsList =
            if (topStrings.isEmpty())
                "لا توجد Strings كافية للعرض"
            else
                topStrings.joinToString("\n") {
                    "• $it"
                }

        val ar = """
نتيجة التحليل

الحجم: ${formatSize(size)}
SHA-256: $shaHex

DEX: $dexCount
Native .so: $soCount
AndroidManifest: ${if (manifest) "نعم" else "لا"}
Resources: ${if (resources) "نعم" else "لا"}

عدد Strings المستخرجة من DEX: $totalStrings
Strings فريدة: ${uniqueStrings.size}
مؤشرات URLs: ${allUrls.size}

ملفات DEX:
$dexList

الروابط المكتشفة:
$urlList

مؤشرات نصية مهمة:
$interestingList

عينة Strings دقيقة:
$stringsList

مؤشر التحليل التجريبي: $score%

ملاحظة:
المؤشر والنتائج هي تحليل ساكن ومؤشرات فقط، ولا تثبت وحدها أن التطبيق ضار أو آمن.
        """.trimIndent()

        val en = """
Analysis result

Size: ${formatSize(size)}
SHA-256: $shaHex

DEX: $dexCount
Native .so: $soCount
AndroidManifest: ${if (manifest) "yes" else "no"}
Resources: ${if (resources) "yes" else "no"}

Strings extracted from DEX: $totalStrings
Unique Strings: ${uniqueStrings.size}
URL indicators: ${allUrls.size}

DEX files:
$dexList

Detected URLs:
$urlList

Interesting text indicators:
$interestingList

Accurate String sample:
$stringsList

Experimental analysis indicator: $score%

Note:
This is static analysis and heuristic evidence only. It does not by itself prove that an application is malicious or safe.
        """.trimIndent()

        return R(ar, en)
    }

    /*
     * قراءة Entry بالكامل.
     */
    private fun readEntry(
        input: ZipInputStream
    ): ByteArray {

        val out = ByteArrayOutputStream()
        val buffer = ByteArray(65536)

        while (true) {
            val n = input.read(buffer)

            if (n <= 0) break

            out.write(buffer, 0, n)
        }

        return out.toByteArray()
    }

    /*
     * قراءة محدودة للملفات الكبيرة.
     */
    private fun readEntryLimited(
        input: ZipInputStream,
        maxBytes: Int
    ): ByteArray {

        val out = ByteArrayOutputStream()
        val buffer = ByteArray(65536)

        var total = 0

        while (total < maxBytes) {

            val wanted =
                minOf(
                    buffer.size,
                    maxBytes - total
                )

            val n =
                input.read(
                    buffer,
                    0,
                    wanted
                )

            if (n <= 0) break

            out.write(buffer, 0, n)
            total += n
        }

        return out.toByteArray()
    }

    /*
     * قراءة جدول String IDs الحقيقي في DEX.
     *
     * DEX header:
     * string_ids_size عند 0x38
     * string_ids_off  عند 0x3C
     */
    private fun parseDexStrings(
        name: String,
        data: ByteArray
    ): DexResult {

        if (data.size < 0x70) {
            return DexResult(
                name,
                emptyList(),
                emptyList()
            )
        }

        val magic =
            String(
                data,
                0,
                minOf(8, data.size),
                Charsets.ISO_8859_1
            )

        if (!magic.startsWith("dex\n")) {
            return DexResult(
                name,
                emptyList(),
                emptyList()
            )
        }

        val stringIdsSize =
            readLeInt(data, 0x38)

        val stringIdsOff =
            readLeInt(data, 0x3C)

        if (
            stringIdsSize <= 0 ||
            stringIdsSize > 2_000_000 ||
            stringIdsOff < 0 ||
            stringIdsOff >= data.size
        ) {
            return DexResult(
                name,
                emptyList(),
                emptyList()
            )
        }

        val strings = ArrayList<String>(
            minOf(stringIdsSize, 100_000)
        )

        val urls = linkedSetOf<String>()

        val max =
            minOf(
                stringIdsSize,
                (data.size - stringIdsOff) / 4
            )

        for (i in 0 until max) {

            val itemOffset =
                stringIdsOff + i * 4

            val stringDataOff =
                readLeInt(data, itemOffset)

            if (
                stringDataOff < 0 ||
                stringDataOff >= data.size
            ) {
                continue
            }

            val value =
                readDexString(
                    data,
                    stringDataOff
                )

            if (value.isEmpty()) continue

            /*
             * نتجنب Strings غير المفيدة جدًا.
             */
            if (
                value.length <= 4096 &&
                !value.contains('\u0000')
            ) {
                strings.add(value)

                urlRegex
                    .findAll(value)
                    .take(20)
                    .forEach {
                        urls.add(it.value)
                    }
            }
        }

        return DexResult(
            name,
            strings,
            urls.toList()
        )
    }

    /*
     * DEX يستخدم ULEB128 قبل بيانات الـString.
     */
    private fun readDexString(
        data: ByteArray,
        offset: Int
    ): String {

        if (offset < 0 || offset >= data.size) {
            return ""
        }

        var p = offset

        /*
         * UTF-16 length.
         * نحتاج القيمة لتخطي ULEB128 فقط؛
         * النص نفسه ينتهي بـ 0.
         */
        var shift = 0
        var utf16Length = 0

        while (p < data.size && shift < 35) {

            val b = data[p++].toInt() and 0xff

            utf16Length =
                utf16Length or
                    ((b and 0x7f) shl shift)

            if ((b and 0x80) == 0) break

            shift += 7
        }

        if (p >= data.size) return ""

        val start = p

        while (
            p < data.size &&
            data[p].toInt() != 0
        ) {
            p++
        }

        if (p <= start) return ""

        val length = p - start

        /*
         * UTF-8 هو الترميز المعتاد لبيانات DEX
         * مع دعم عملي جيد للبحث النصي.
         */
        return try {

            String(
                data,
                start,
                length,
                Charsets.UTF_8
            ).trim()

        } catch (_: Exception) {

            String(
                data,
                start,
                length,
                Charsets.ISO_8859_1
            ).trim()
        }
    }

    /*
     * استخراج سلاسل ASCII قابلة للقراءة من ملفات binary.
     */
    private fun extractPrintableStrings(
        data: ByteArray
    ): List<String> {

        val result = mutableListOf<String>()
        val current = StringBuilder()

        fun flush() {

            if (current.length >= 4) {
                val value =
                    current.toString().trim()

                if (value.isNotEmpty()) {
                    result.add(value)
                }
            }

            current.setLength(0)
        }

        for (b in data) {

            val c = b.toInt() and 0xff

            if (
                c in 32..126 ||
                c >= 0x80
            ) {
                current.append(c.toChar())

                if (current.length >= 512) {
                    flush()
                }

            } else {
                flush()
            }
        }

        flush()

        return result
    }

    private fun readLeInt(
        data: ByteArray,
        offset: Int
    ): Int {

        if (
            offset < 0 ||
            offset + 4 > data.size
        ) {
            return -1
        }

        return (
            (data[offset].toInt() and 0xff) or
            ((data[offset + 1].toInt() and 0xff) shl 8) or
            ((data[offset + 2].toInt() and 0xff) shl 16) or
            ((data[offset + 3].toInt() and 0xff) shl 24)
        )
    }

    private fun formatSize(
        bytes: Long
    ): String {

        if (bytes < 1024) {
            return "$bytes B"
        }

        if (bytes < 1024 * 1024) {
            return String.format(
                Locale.US,
                "%.2f KB",
                bytes / 1024.0
            )
        }

        if (bytes < 1024L * 1024L * 1024L) {
            return String.format(
                Locale.US,
                "%.2f MB",
                bytes / (1024.0 * 1024.0)
            )
        }

        return String.format(
            Locale.US,
            "%.2f GB",
            bytes / (1024.0 * 1024.0 * 1024.0)
        )
    }
}
