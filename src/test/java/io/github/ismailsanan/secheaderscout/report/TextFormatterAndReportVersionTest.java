package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
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
        assertTrue(details.contains("\nNotes\n  - HTTP fallback note\n"), details);
        assertTrue(details.contains("\nMissing (1)\n  - Referrer-Policy  [Severity: Info]\n"), details);
    }

    @Test
    void detailsPaneShowsErrorsAndCleanResults() {
        assertTrue(TextFormatter.details(ScanResult.failed("h", "https://h/", "TLS failure"))
                .contains("ERROR: TLS failure"));
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
                - Referrer-Policy

                **Misconfigured:**

                - X-Frame-Options
                  - Weak: detail for ALLOWALL

                ### api.example.com

                **Missing:**

                - Referrer-Policy
                """, md);
    }

    private static Finding csp(String issue, String policy) {
        return new Finding("Content-Security-Policy", FindingType.WEAK, issue, policy, "r",
                "First sentence explains it. Second sentence is left out.", "b", "f", Severity.LOW,
                Confidence.FIRM);
    }

    /** Issue #8: one bullet per header, each problem with its reason; no URLs, URL counts or raw values. */
    @Test
    void reportMarkdownListsEachHeaderOnceWithItsProblemsAndNoUrlsOrLongValues() {
        String policy = "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn1.example https://cdn2.example "
                + "https://cdn3.example";
        String md = TextFormatter.reportMarkdown(List.of(
                result("https://e.example/a", List.of(csp("Content-Security-Policy allows inline scripts", policy),
                        csp("Content-Security-Policy allows eval", policy)), Set.of()),
                result("https://e.example/b", List.of(csp("Content-Security-Policy allows inline scripts",
                        policy + " https://other.example")), Set.of())));
        assertEquals("""
                ### e.example

                **Misconfigured:**

                - Content-Security-Policy
                  - Allows inline scripts: First sentence explains it.
                  - Allows eval: First sentence explains it.
                """, md);
        assertFalse(md.contains("https://"), md);
        assertFalse(md.contains("URLs"), md);
    }

    /** Issue #9: the details pane groups problems by header, explains briefly and omits long raw values. */
    @Test
    void detailsPaneGroupsMisconfigurationsByHeaderWithAlignedColumns() {
        String policy = "script-src 'unsafe-inline' 'unsafe-eval' https://cdn1.example https://cdn2.example";
        ScanResult r = result("https://e.example/", List.of(missing("Referrer-Policy"),
                csp("Content-Security-Policy allows inline scripts", policy),
                csp("Content-Security-Policy allows eval", policy), weak("X-Frame-Options", "ALLOWALL")), Set.of());
        String details = TextFormatter.details(r);
        assertTrue(details.contains("""

                Missing (1)
                  - Referrer-Policy          [Severity: Info]

                Misconfigured (2 headers)
                  - Content-Security-Policy  [Severity: Low]
                      * Allows inline scripts
                        First sentence explains it.
                      * Allows eval
                        First sentence explains it.
                  - X-Frame-Options          [Severity: Low]
                      * Weak: ALLOWALL
                        detail for ALLOWALL
                """), details);
        assertFalse(details.contains("cdn1"), details);
        assertFalse(details.contains("WEAK"), details);
    }

    @Test
    void reportMarkdownSkipsCleanHostsAndHasAnEmptyMessage() {
        assertEquals("No findings to copy.", TextFormatter.reportMarkdown(List.of()));
        assertEquals("No findings to copy.",
                TextFormatter.reportMarkdown(List.of(result("https://clean.example/", List.of(), Set.of()))));
        String md = TextFormatter.reportMarkdown(List.of(result("https://clean.example/", List.of(), Set.of()),
                result("https://dirty.example/", List.of(weak("X-A", "v")), Set.of())));
        assertFalse(md.contains("clean.example"));
        assertTrue(md.contains("- X-A\n  - Weak: detail for v\n"), md);
    }

    @Test
    void reportMarkdownIncludesUnanalysedTargets() {
        String md = TextFormatter.reportMarkdown(List.of(ScanResult.failed("h", "https://h/", "connection refused")));
        assertTrue(md.contains("**Not analysed:**\n\n- connection refused\n"), md);
        assertFalse(md.contains("https://h/"), md);
    }

    @Test
    void reportMarkdownCodeSpansAndHeadingsCannotBeBrokenOut() {
        String url = "https://e.example/`**pwn**`\n# heading";
        String md = TextFormatter.reportMarkdown(List.of(result(url, List.of(weak("X-A", "a`b\r\nc")), Set.of()),
                ScanResult.failed("t", "https://*evil*<b>\n# x/", "e")));
        assertTrue(md.startsWith("### e.example\n"), md);
        assertTrue(md.contains("### \\*evil\\*\\<b\\>\n"), md);
        assertFalse(md.contains("\n# "), md);
        assertTrue(md.contains("detail for a\\`b  c"), md);
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

    /** A finding's short summary (what is lacking, briefly why) is what the report shows after the problem. */
    @Test
    void reportAndDetailsPreferTheShortSummary() {
        Finding cache = new Finding("Cache-Control", FindingType.WEAK,
                "Cache-Control does not prevent storage of sensitive response", "private, max-age=600", "no-store",
                "This is a response to an authenticated request, but Cache-Control lacks 'no-store'. More.", "b", "f",
                Severity.INFORMATION, Confidence.TENTATIVE)
                .withSummary("lacks 'no-store'; the browser may keep this sensitive response on disk");
        ScanResult r = result("https://e.example/account", List.of(cache), Set.of());
        assertTrue(TextFormatter.reportMarkdown(List.of(r)).contains("- Cache-Control\n  - Does not prevent storage of "
                + "sensitive response: lacks 'no-store'; the browser may keep this sensitive response on disk\n"));
        String details = TextFormatter.details(r);
        assertTrue(details.contains("* Does not prevent storage of sensitive response: lacks 'no-store'"), details);
        assertFalse(details.contains("This is a response to an authenticated request"),
                "the long explanation is not repeated under a summary: " + details);
    }
}
