package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.model.ScanResult;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static io.github.ismailsanan.secheaderscout.testsupport.Results.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** FR-7 (fallback shown in details pane and Markdown), FR-11 (definitions version in report), SEC-1. */
class TextFormatterAndReportVersionTest {

    private static final ZonedDateTime NOW = ZonedDateTime.parse("2026-11-08T10:00:00Z");

    @Test
    void detailsPaneShowsFallbackWarningProtocolAndNotes() {
        ScanResult r = fallback("example.com", List.of(missing("Referrer-Policy")));
        String details = TextFormatter.details(r);
        assertTrue(details.contains("(HTTP 200)"), details);
        assertTrue(details.contains("HTTP fallback: HTTPS returned 503; these results were obtained over plain HTTP"),
                details);
        assertTrue(details.contains("NOTE          -> HTTP fallback note"), details);
        assertTrue(details.contains("MISSING       -> Referrer-Policy"), details);
    }

    @Test
    void detailsPaneShowsErrorsAndCleanResults() {
        assertTrue(TextFormatter.details(ScanResult.failed("h", "https://h/", "TLS failure"))
                .contains("ERROR         -> TLS failure"));
        assertTrue(TextFormatter.details(result("https://h/", List.of(), Set.of()))
                .contains("No issues found for the evaluated headers"));
    }

    @Test
    void reportMarkdownMarksFallbackResults() {
        String md = TextFormatter.reportMarkdown(List.of(fallback("example.com", List.of(missing("Referrer-Policy")))));
        assertTrue(md.startsWith("### example.com\n\n> **Warning:** HTTP fallback: HTTPS returned 503"), md);
        assertTrue(md.contains("**Missing:**\n\n- Referrer-Policy\n"), md);
    }

    @Test
    void reportMarkdownGroupsByHostWithMissingThenMisconfiguredBullets() {
        String md = TextFormatter.reportMarkdown(List.of(
                result("https://www.example.com/", List.of(missing("Content-Security-Policy"),
                        missing("Referrer-Policy"), weak("X-Frame-Options", "ALLOWALL")), Set.of()),
                result("https://api.example.com/v1", List.of(missing("Referrer-Policy")), Set.of()),
                result("https://WWW.example.com:443/login?next=/", List.of(missing("Content-Security-Policy"),
                        weak("X-Frame-Options", "ALLOWALL")), Set.of())));
        assertEquals("""
                ### www.example.com

                **Missing:**

                - Content-Security-Policy
                - Referrer-Policy (1 of 2 URLs)

                **Misconfigured:**

                - X-Frame-Options weak: `ALLOWALL`

                ### api.example.com

                **Missing:**

                - Referrer-Policy
                """, md);
    }

    @Test
    void reportMarkdownNamesTheHeaderWhenTheIssueNameDoesNotAndNotesVaryingValues() {
        io.github.ismailsanan.secheaderscout.engine.Finding a = new io.github.ismailsanan.secheaderscout.engine.Finding(
                "Content-Security-Policy", io.github.ismailsanan.secheaderscout.engine.FindingType.WEAK,
                "Unsafe inline scripts allowed", "script-src 'nonce-a' 'unsafe-inline'", "r", "d", "b", "f",
                io.github.ismailsanan.secheaderscout.engine.Severity.MEDIUM,
                io.github.ismailsanan.secheaderscout.engine.Confidence.CERTAIN);
        io.github.ismailsanan.secheaderscout.engine.Finding b = new io.github.ismailsanan.secheaderscout.engine.Finding(
                a.header(), a.type(), a.issueName(), "script-src 'nonce-b' 'unsafe-inline'", "r", "d", "b", "f",
                a.severity(), a.confidence());
        String md = TextFormatter.reportMarkdown(List.of(result("https://e.example/a", List.of(a), Set.of()),
                result("https://e.example/b", List.of(b), Set.of())));
        assertTrue(md.contains("- Content-Security-Policy: Unsafe inline scripts allowed: "
                + "`script-src 'nonce-a' 'unsafe-inline'` (value varies across URLs)\n"), md);
        assertFalse(md.contains("of 2 URLs"), "affects every URL: " + md);
    }

    @Test
    void reportMarkdownSkipsCleanHostsAndHasAnEmptyMessage() {
        assertEquals("No findings to copy.", TextFormatter.reportMarkdown(List.of()));
        assertEquals("No findings to copy.",
                TextFormatter.reportMarkdown(List.of(result("https://clean.example/", List.of(), Set.of()))));
        String md = TextFormatter.reportMarkdown(List.of(result("https://clean.example/", List.of(), Set.of()),
                result("https://dirty.example/", List.of(weak("X-A", "v")), Set.of())));
        assertFalse(md.contains("clean.example"));
        assertTrue(md.contains("- X-A weak: `v`"), md);
    }

    @Test
    void reportMarkdownIncludesUnanalysedTargets() {
        String md = TextFormatter.reportMarkdown(List.of(ScanResult.failed("h", "https://h/", "connection refused")));
        assertTrue(md.contains("**Not analysed:**\n\n- `https://h/`: connection refused"), md);
    }

    @Test
    void reportMarkdownCodeSpansAndHeadingsCannotBeBrokenOut() {
        String url = "https://e.example/`**pwn**`\n# heading";
        String md = TextFormatter.reportMarkdown(List.of(result(url, List.of(weak("X-A", "a`b\r\nc")), Set.of()),
                ScanResult.failed("t", "https://*evil*<b>\n# x/", "e")));
        assertTrue(md.startsWith("### e.example\n"), md);
        assertTrue(md.contains("### \\*evil\\*\\<b\\>\n"), md);
        assertFalse(md.contains("\n# "), md);
        assertTrue(md.contains("`a'b  c`"), md);
    }

    @Test
    void htmlReportShowsTheDefinitionsVersionEscaped() {
        String html = ReportExporter.render(List.of(), "bundled 06b5c6f (2026-10-18 07:04:36 UTC, 13 headers)", NOW);
        assertTrue(html.contains("<p>OWASP definitions: bundled 06b5c6f (2026-10-18 07:04:36 UTC, 13 headers)</p>"));
        String hostile = ReportExporter.render(List.of(), "<script>alert(1)</script>", NOW);
        assertFalse(hostile.toLowerCase(Locale.ROOT).contains("<script"));
        assertTrue(hostile.contains("OWASP definitions: &lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    @Test
    void htmlReportHasNoEventHandlersOrScriptUrlsForHostileInput() {
        String payload = "javascript:alert(1)\" onload=\"x' onerror='y";
        ScanResult r = result("https://e.example/" + payload, List.of(weak(payload, payload), missing(payload)), Set.of());
        String lower = ReportExporter.render(List.of(r), payload, NOW).toLowerCase(Locale.ROOT);
        assertFalse(lower.contains(" onload=\""));
        assertFalse(lower.contains(" onerror='"));
        assertFalse(lower.contains("href="), "report must not create links from untrusted URLs");
        assertFalse(lower.contains("src="));
    }
}
