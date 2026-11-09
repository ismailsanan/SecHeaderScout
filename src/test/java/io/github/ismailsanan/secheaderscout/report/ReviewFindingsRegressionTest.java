package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.util.Log;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CancellationException;

import static io.github.ismailsanan.secheaderscout.model.Results.result;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Regression tests for findings from the security and architecture reviews. */
class ReviewFindingsRegressionTest {

    /** S-1: crafted reports with unterminated blocks used to take minutes (quadratic regex). */
    @Test
    void parserIsLinearOnUnterminatedSections() {
        String current = "<section class=\"url-block\" data-url=\"x\">".repeat(25_000);   // ~1 MB, no </section>
        String legacy = "<div class='url-block'>".repeat(40_000);                          // ~1 MB, legacy path
        String noQuotes = "<section class=\"url-block\" data-url=\"x\"><li class=\"missing\" data-header=\""
                + "a".repeat(1_000_000);
        long start = System.nanoTime();
        assertEquals(25_000, ReportParser.parse(current).size());
        assertTrue(ReportParser.parse(legacy).isEmpty());
        assertEquals(1, ReportParser.parse(noQuotes).size());
        long ms = (System.nanoTime() - start) / 1_000_000;
        // the quadratic version needed ~74 s for 0.8 MB; linear parsing takes milliseconds
        assertTrue(ms < 10_000, "parsing took " + ms + " ms");
    }

    @Test
    void parserStopsWhenInterrupted() {
        String html = "<section class=\"url-block\" data-url=\"x\"></section>".repeat(100);
        Thread.currentThread().interrupt();
        try {
            assertThrows(CancellationException.class, () -> ReportParser.parse(html));
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void parserStillReadsWellFormedReports() {
        String html = ReportExporter.render(List.of(
                result("https://a.example/x?y=\"1\"", List.of(io.github.ismailsanan.secheaderscout.model.Results.missing("Referrer-Policy")), Set.of()),
                result("https://b.example/", List.of(), Set.of())), "v", ZonedDateTime.now());
        List<ReportParser.PreviousResult> parsed = ReportParser.parse(html);
        assertEquals(2, parsed.size());
        assertEquals("https://a.example/x?y=\"1\"", parsed.get(0).url());
        assertEquals(Set.of("referrer-policy"), parsed.get(0).missingHeaders());
    }

    /** S-3: server-controlled text must not inject HTML, links or images into copied Markdown. */
    @Test
    void markdownEscapesServerControlledText() {
        String evil = "<img src=https://attacker.example/t.gif>[click](javascript:alert(1)) ![x](y) *b* `c` | d";
        Finding f = new Finding("X-Content-Type-Options", FindingType.INVALID, "name", evil, "nosniff",
                "The first value is '" + evil + "'", "bg", "fix", Severity.LOW, Confidence.CERTAIN);
        ScanResult r = new ScanResult("t", "https://e.example/", "GET", 200, true, false, null, null, null,
                io.github.ismailsanan.secheaderscout.engine.UrlClassifier.UrlType.NORMAL, List.of(f), List.of(), Set.of());
        ScanResult failed = ScanResult.failed("t", "https://e.example/", "error " + evil);
        String md = TextFormatter.reportMarkdown(List.of(r, failed));
        // code spans render their content literally, so only text outside them can inject markup
        String outsideCode = md.replaceAll("`[^`\\n]*`", "");
        assertFalse(java.util.regex.Pattern.compile("(?<!\\\\)[<\\[!]").matcher(outsideCode).find(),
                "unescaped markup outside code spans: " + outsideCode);
        assertTrue(md.contains("\\<img"), md);
        assertTrue(md.contains("\\[click\\]"), md);
        assertTrue(md.contains("X-Content-Type-Options") || md.contains("name"), "readable text kept: " + md);
    }

    /** S-4: tokens in query strings must not end up in Burp's extension log. */
    @Test
    void logRedactsQueryAndFragment() {
        assertEquals("https://app/reset?[redacted]", Log.redact("https://app/reset?token=SECRET"));
        assertEquals("https://app/a?[redacted]", Log.redact("https://app/a#access_token=x"));
        assertEquals("https://app/a", Log.redact("https://app/a"));
        assertEquals("null", Log.redact(null));
    }

    @Test
    void comparisonFormatterListsAllCategories() {
        ScanResult now = result("https://e.example/", List.of(io.github.ismailsanan.secheaderscout.model.Results.missing("Permissions-Policy")),
                Set.of("referrer-policy"));
        String text = TextFormatter.comparison(List.of(new Comparison("https://e.example/",
                Set.of("referrer-policy", "cache-control"), now)), true);
        assertTrue(text.contains("(cancelled, partial)"));
        assertTrue(text.contains("FIXED             -> referrer-policy"));
        assertTrue(text.contains("NEW ISSUE         -> permissions-policy"));
        assertTrue(text.contains("NO LONGER CHECKED -> cache-control"));
    }
}
