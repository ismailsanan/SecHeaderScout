package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.util.HtmlEscaper;
import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static io.github.ismailsanan.secheaderscout.testsupport.Results.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportExporterTest {

    private static final String XSS = "<script>alert(document.cookie)</script>";
    private static final String ATTR_BREAK = "\" onmouseover=\"alert(1)\" x='";
    private static final ZonedDateTime NOW = ZonedDateTime.parse("2026-11-08T10:00:00Z");

    private static String render(List<ScanResult> results) {
        return ReportExporter.render(results, "bundled abc", NOW);
    }

    @Test
    void everyHttpDerivedFieldIsEscaped() {
        Finding evil = new Finding(XSS, FindingType.WEAK, "name " + XSS, XSS + ATTR_BREAK, "rec " + XSS,
                "detail " + XSS, "bg", "fix", Severity.LOW, Confidence.FIRM);
        Finding evilMissing = new Finding("X" + ATTR_BREAK, FindingType.MISSING, "n", null, XSS, "d", "b", "r",
                Severity.INFORMATION, Confidence.CERTAIN);
        // a (legal) HTTP-fallback result, so the fallback warning and reason are rendered too
        String url = "http://example.com/" + XSS + ATTR_BREAK;
        ScanResult r = new ScanResult(url, url, "GET" + XSS, 200, false, true, null, "reason " + XSS,
                null, UrlClassifier.UrlType.NORMAL, List.of(evil, evilMissing), List.of("note " + XSS), Set.of());
        ScanResult failed = ScanResult.failed(XSS, "https://x/" + XSS, "error " + XSS);

        String html = render(List.of(r, failed));
        String lower = html.toLowerCase(Locale.ROOT);

        assertFalse(lower.contains("<script"), "script tag injected");
        assertFalse(lower.contains("onmouseover=\""), "attribute injection");
        assertTrue(html.contains("&lt;script&gt;alert(document.cookie)&lt;/script&gt;"), "payload shown as text");
        assertTrue(html.contains("&quot; onmouseover=&quot;alert(1)&quot; x=&#39;"));
    }

    @Test
    void reportForbidsScriptExecutionViaCsp() {
        String html = render(List.of());
        assertTrue(html.contains("content=\"default-src 'none'; style-src 'unsafe-inline'\""));
        assertFalse(html.toLowerCase(Locale.ROOT).contains("<script"));
    }

    @Test
    void emptyResults() {
        String html = render(List.of());
        assertTrue(html.contains("URLs scanned: 0"));
        assertTrue(html.contains("No results."));
        assertTrue(html.trim().endsWith("</html>"));
    }

    @Test
    void fallbackResultsAreClearlyMarked() {
        String html = render(List.of(fallback("example.com", List.of(missing("Referrer-Policy")))));
        assertTrue(html.contains("data-fallback=\"true\""));
        assertTrue(html.contains("data-protocol=\"HTTP\""));
        assertTrue(html.contains("HTTP fallback: HTTPS returned 503"));
        assertTrue(html.contains("1 result(s) were obtained over plain HTTP"));
    }

    @Test
    void largeResultSetRendersQuickly() {
        List<ScanResult> many = new ArrayList<>();
        for (int i = 0; i < 20_000; i++) {
            many.add(result("https://example.com/p" + i, List.of(missing("Referrer-Policy"), weak("X-A", "v")), Set.of()));
        }
        long start = System.nanoTime();
        String html = render(many);
        long ms = (System.nanoTime() - start) / 1_000_000;
        // generous bound: guards against quadratic behaviour (minutes at 20k rows), not a benchmark
        assertTrue(ms < 15_000, "rendering took " + ms + " ms");
        assertEquals(20_000, html.split("<section class=\"url-block", -1).length - 1);
    }

    @Test
    void exportWritesUtf8FileAtomically(@TempDir Path dir) throws Exception {
        Path out = dir.resolve("report.html");
        Files.writeString(out, "old");
        Path written = ReportExporter.export(List.of(result("https://example.com/é", List.of(), Set.of())),
                "v", out);
        String content = Files.readString(written, StandardCharsets.UTF_8);
        assertTrue(content.contains("https://example.com/é"));
        try (var files = Files.list(dir)) {
            assertEquals(1, files.count(), "temp file removed");
        }
    }

    @Test
    void escaperHandlesAllSignificantCharactersAndControls() {
        assertEquals("&amp;&lt;&gt;&quot;&#39;", HtmlEscaper.escape("&<>\"'"));
        assertEquals("a�b", HtmlEscaper.escape("a\u0000b"));
        assertEquals("", HtmlEscaper.escape(null));
        String tricky = "&amp; <x> \"q\" 'a' → &#8594;";
        assertEquals(tricky, HtmlEscaper.unescape(HtmlEscaper.escape(tricky)));
    }
}
