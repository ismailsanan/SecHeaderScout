package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static io.github.ismailsanan.secheaderscout.testsupport.Results.fallback;
import static io.github.ismailsanan.secheaderscout.testsupport.Results.missing;
import static io.github.ismailsanan.secheaderscout.testsupport.Results.result;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Regression tests for the report, score and comparison (incomplete results, fallback, escaping). */
class ReportRegressionTest {

    private static final ZonedDateTime NOW = ZonedDateTime.parse("2026-11-08T10:00:00Z");
    private static final String SECTION = "<section class=\"url-block\" data-url=\"";
    private static final String ITEM = "<li class=\"missing\" data-header=\"";

    private static ScanResult incomplete(String url, List<Finding> findings, Set<String> present) {
        return new ScanResult(url, url, "GET", 200, url.startsWith("https"), false, null, null, null,
                UrlClassifier.classify(url), findings,
                List.of("Internal error while evaluating Content-Security-Policy; this header was NOT assessed."),
                present, true);
    }

    private static Finding invalid(String header) {
        return new Finding(header, FindingType.INVALID, header + " invalid", "garbage", "rec", "detail", "bg", "fix",
                Severity.LOW, Confidence.CERTAIN);
    }

    private static List<Finding> missingAll(String... headers) {
        List<Finding> out = new ArrayList<>();
        for (String h : headers) {
            out.add(missing(h));
        }
        return out;
    }

    // ---- 1. ScoreCalculator -------------------------------------------------------------------

    @Test
    void scoreDoesNotGrowWithTheNumberOfIdenticalPages() {
        List<Finding> findings = missingAll("Cross-Origin-Embedder-Policy", "Permissions-Policy",
                "X-DNS-Prefetch-Control");
        ScoreCalculator.Score one = ScoreCalculator.calculate(
                List.of(result("https://e.example/p", findings, Set.of())));
        List<ScanResult> hundred = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            hundred.add(result("https://e.example/p" + i, findings, Set.of()));
        }
        assertEquals(ScoreCalculator.Score.LOW, one);
        assertEquals(one, ScoreCalculator.calculate(hundred));
    }

    @Test
    void sensitiveUrlMultiplierStillApplies() {
        List<Finding> findings = missingAll("Content-Security-Policy", "Strict-Transport-Security",
                "X-Frame-Options", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy");
        String logout = "https://e.example/logout";
        assertEquals(UrlClassifier.UrlType.LOGOUT, UrlClassifier.classify(logout));
        assertEquals(ScoreCalculator.Score.MEDIUM,
                ScoreCalculator.calculate(List.of(result("https://e.example/home", findings, Set.of()))));
        assertEquals(ScoreCalculator.Score.HIGH,
                ScoreCalculator.calculate(List.of(result(logout, findings, Set.of()))));
    }

    /**
     * An incomplete evaluation is neither dropped nor treated as clean: its findings count like a
     * complete result's, and the score is flagged as a lower bound (unassessed headers cannot count).
     */
    @Test
    void incompleteEvaluationCountsItsFindingsAndMarksTheScoreAsLowerBound() {
        List<Finding> findings = missingAll("Content-Security-Policy", "Strict-Transport-Security",
                "X-Frame-Options", "Cross-Origin-Opener-Policy");
        List<ScanResult> complete = List.of(result("https://e.example/", findings, Set.of()));
        List<ScanResult> partial = List.of(incomplete("https://e.example/", findings, Set.of()));
        assertEquals(ScoreCalculator.calculate(complete), ScoreCalculator.calculate(partial));
        assertFalse(ScoreCalculator.hasIncompleteEvaluations(complete));
        assertTrue(ScoreCalculator.hasIncompleteEvaluations(partial));
        assertTrue(ReportExporter.render(partial, "v", NOW).contains("(lower bound: 1 result(s) not fully evaluated)"));
    }

    // ---- 2. TextFormatter ------------------------------------------------------------------------

    @Test
    void markdownKeepsFallbackResultsWithoutFindings() {
        ScanResult cleanFallback = fallback("example.com", List.of());
        String md = TextFormatter.reportMarkdown(List.of(cleanFallback));
        assertTrue(md.contains("### example.com"), md);
        assertTrue(md.contains("> **Warning:** HTTP fallback: HTTPS returned 503"), md);
    }

    @Test
    void markdownAndDetailsShowIncompleteEvaluations() {
        ScanResult r = incomplete("https://e.example/", List.of(), Set.of());
        String md = TextFormatter.reportMarkdown(List.of(r));
        assertTrue(md.contains("**Evaluation incomplete** (1 of 1 URLs)"), md);
        assertTrue(md.contains("NOT assessed"), md);
        String details = TextFormatter.details(r);
        assertTrue(details.contains("EVALUATION INCOMPLETE"), details);
        assertFalse(details.contains("No issues found"), details);
    }

    // ---- 3. ReportExporter -----------------------------------------------------------------------

    @Test
    void erroredAndIncompleteResultsAreMarkedAndParseAsNotAnalysed() {
        ScanResult failed = ScanResult.failed("https://down.example/", "https://down.example/", "connection refused");
        ScanResult partial = incomplete("https://partial.example/", List.of(missing("Referrer-Policy")), Set.of());
        ScanResult ok = result("https://ok.example/", List.of(missing("Referrer-Policy")), Set.of());
        ScanResult clean = result("https://clean.example/", List.of(), Set.of());
        ScanResult partialNoFindings = incomplete("https://partial2.example/", List.of(), Set.of());
        String html = ReportExporter.render(List.of(failed, partial, ok, clean, partialNoFindings), "v", NOW);

        assertTrue(html.contains("data-error=\"true\""), html);
        assertTrue(html.contains("Not analysed: connection refused"), html);
        assertTrue(html.contains("data-incomplete=\"true\""), html);
        assertTrue(html.contains("Evaluation incomplete"), html);
        assertEquals(1, html.split("No issues found", -1).length - 1, "clean message only for the clean result");

        List<ReportParser.PreviousResult> parsed = ReportParser.parse(html);
        assertEquals(5, parsed.size());
        assertFalse(parsed.get(0).analysed(), "errored");
        assertFalse(parsed.get(1).analysed(), "incomplete");
        assertTrue(parsed.get(2).analysed());
        assertTrue(parsed.get(3).analysed());
        assertFalse(parsed.get(4).analysed());
        assertEquals(Set.of("referrer-policy"), parsed.get(2).missingHeaders());
    }

    // ---- 4. ReportParser ---------------------------------------------------------------------------

    @Test
    void legacyUrlTextIsNotReadAsAMissingHeader() {
        String legacy = "<html><body>"
                + "<div class='url-block'><div class='url'>https://x/?q=MISSING->csp</div>"
                + "<div class='missing'>MISSING → referrer-policy | Recommended: x</div></div>"
                + "</body></html>";
        List<ReportParser.PreviousResult> parsed = ReportParser.parse(legacy);
        assertEquals(1, parsed.size());
        assertEquals("https://x/?q=MISSING->csp", parsed.get(0).url());
        assertEquals(Set.of("referrer-policy"), parsed.get(0).missingHeaders());
        assertTrue(parsed.get(0).analysed());
    }

    @Test
    void legacyErrorBlockIsNotAnalysed() {
        String legacy = "<html><body>"
                + "<div class='url-block'><div class='url'>https://old.example/</div>"
                + "<div class='missing'>MISSING → [ERROR] Host Unreachable | Recommended: z</div></div>"
                + "<div class='url-block'><div class='url'>https://ok.example/</div>"
                + "<div class='missing'>MISSING → x-frame-options | Recommended: z</div></div>"
                + "</body></html>";
        List<ReportParser.PreviousResult> parsed = ReportParser.parse(legacy);
        assertEquals(2, parsed.size());
        assertFalse(parsed.get(0).analysed());
        assertTrue(parsed.get(0).missingHeaders().isEmpty());
        assertTrue(parsed.get(1).analysed());
    }

    @Test
    void legacyBlocksAfterBodyCloseAreIgnored() {
        String legacy = "<html><body>"
                + "<div class='url-block'><div class='url'>https://a.example/</div></div>"
                + "</body></html>"
                + "<div class='url-block'><div class='url'>https://injected.example/</div></div>";
        List<ReportParser.PreviousResult> parsed = ReportParser.parse(legacy);
        assertEquals(1, parsed.size());
        assertEquals("https://a.example/", parsed.get(0).url());
    }

    @Test
    void strayItemBetweenSectionsIsCreditedToNeither() {
        String html = SECTION + "a\">" + ITEM + "x\"></li></section>"
                + ITEM + "stray\"></li>"
                + SECTION + "b\">" + ITEM + "y\"></li></section>";
        List<ReportParser.PreviousResult> parsed = ReportParser.parse(html);
        assertEquals(2, parsed.size());
        assertEquals(Set.of("x"), parsed.get(0).missingHeaders());
        assertEquals(Set.of("y"), parsed.get(1).missingHeaders());
    }

    @Test
    void malformedSectionDoesNotCorruptTheNextOne() {
        String html = SECTION + "a\">" + ITEM + "broken></li></section>"
                + SECTION + "b\">" + ITEM + "csp\"></li>" + ITEM + "hsts\"></li></section>";
        List<ReportParser.PreviousResult> parsed = ReportParser.parse(html);
        assertEquals(2, parsed.size());
        assertTrue(parsed.get(0).missingHeaders().isEmpty(), parsed.get(0).toString());
        assertEquals("b", parsed.get(1).url());
        assertEquals(Set.of("csp", "hsts"), parsed.get(1).missingHeaders());
    }

    @Test
    void sectionWithoutUrlIsSkippedWithoutLeaking() {
        String html = "<section class=\"url-block\">" + ITEM + "leak\"></li></section>"
                + SECTION + "b\">" + ITEM + "csp\"></li></section>";
        List<ReportParser.PreviousResult> parsed = ReportParser.parse(html);
        assertEquals(1, parsed.size());
        assertEquals("b", parsed.get(0).url());
        assertEquals(Set.of("csp"), parsed.get(0).missingHeaders());
    }

    @Test
    void unterminatedStartTagAtTheEndKeepsEarlierResults() {
        String html = SECTION + "a\">" + ITEM + "x\"></li></section>" + SECTION + "b";
        List<ReportParser.PreviousResult> parsed = ReportParser.parse(html);
        assertEquals(1, parsed.size());
        assertEquals("a", parsed.get(0).url());
        assertEquals(Set.of("x"), parsed.get(0).missingHeaders());
    }

    @Test
    void sectionWithoutCloseStopsAtTheNextSection() {
        String html = SECTION + "a\">" + ITEM + "x\"></li>"
                + SECTION + "b\">" + ITEM + "y\"></li></section>";
        List<ReportParser.PreviousResult> parsed = ReportParser.parse(html);
        assertEquals(2, parsed.size());
        assertEquals(Set.of("x"), parsed.get(0).missingHeaders());
        assertEquals(Set.of("y"), parsed.get(1).missingHeaders());
    }

    @Test
    void manyUnterminatedItemsInOneSectionParseInLinearTime() {
        String html = SECTION + "a\">" + String.join("", Collections.nCopies(100_000, ITEM));
        long start = System.nanoTime();
        List<ReportParser.PreviousResult> parsed = ReportParser.parse(html);
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertEquals(1, parsed.size());
        assertTrue(parsed.get(0).missingHeaders().isEmpty(), "broken items yield no headers");
        // generous bound: guards against quadratic cursor behaviour, not a benchmark
        assertTrue(ms < 10_000, "parsing took " + ms + " ms");
    }

    // ---- 5. Comparison ------------------------------------------------------------------------------

    @Test
    void previouslyNotAnalysedGivesNoVerdicts() {
        ScanResult now = result("https://e.example/", List.of(missing("Referrer-Policy")), Set.of("x-frame-options"));
        Comparison c = Comparison.of(new ReportParser.PreviousResult("https://e.example/", Set.of(), false), now);
        assertTrue(c.noBaseline());
        assertTrue(c.indeterminate());
        assertTrue(c.fixed().isEmpty() && c.newlyMissing().isEmpty() && c.stillMissing().isEmpty()
                && c.noLongerChecked().isEmpty());
        assertFalse(c.unchanged());
        String text = TextFormatter.comparison(List.of(c), false);
        assertTrue(text.contains("previously not analysed — no baseline"), text);
        assertFalse(text.contains("NEW ISSUE"), text);
        assertFalse(text.contains("No changes"), text);
    }

    @Test
    void failedRescanGivesNoVerdicts() {
        ScanResult now = ScanResult.failed("https://e.example/", "https://e.example/", "timeout");
        Comparison c = new Comparison("https://e.example/", Set.of("referrer-policy"), now);
        assertTrue(c.rescanFailed());
        assertTrue(c.fixed().isEmpty() && c.noLongerChecked().isEmpty() && c.newlyMissing().isEmpty());
        String text = TextFormatter.comparison(List.of(c), false);
        assertTrue(text.contains("RESCAN FAILED     -> could not rescan: timeout"), text);
        assertFalse(text.contains("NO LONGER CHECKED"), text);
    }

    @Test
    void incompleteRescanKeepsOnlyStillMissing() {
        ScanResult now = incomplete("https://e.example/", List.of(missing("Referrer-Policy"), missing("Cache-Control")),
                Set.of("x-frame-options"));
        Comparison c = new Comparison("https://e.example/", Set.of("referrer-policy", "x-frame-options", "csp"), now);
        assertTrue(c.currentIncomplete());
        assertEquals(List.of("referrer-policy"), c.stillMissing());
        assertTrue(c.fixed().isEmpty(), "x-frame-options present, but an incomplete rescan cannot prove a fix");
        assertTrue(c.newlyMissing().isEmpty());
        assertTrue(c.noLongerChecked().isEmpty());
        String text = TextFormatter.comparison(List.of(c), false);
        assertTrue(text.contains("EVALUATION INCOMPLETE"), text);
        assertTrue(text.contains("STILL MISSING     -> referrer-policy"), text);
        assertFalse(text.contains("No changes"), text);
    }

    /** FR-12: a header that is now sent but unparseable is ignored by browsers, so it is not fixed. */
    @Test
    void presentButInvalidHeaderIsNotFixed() {
        ScanResult now = result("https://e.example/", List.of(invalid("X-Frame-Options")),
                Set.of("x-frame-options", "referrer-policy"));
        Comparison c = new Comparison("https://e.example/", Set.of("x-frame-options", "referrer-policy"), now);
        assertEquals(List.of("referrer-policy"), c.fixed());
        assertEquals(List.of("x-frame-options"), c.presentButInvalid());
        assertTrue(c.noLongerChecked().isEmpty());
        assertFalse(c.unchanged());
        String text = TextFormatter.comparison(List.of(c), false);
        assertTrue(text.contains("PRESENT, INVALID  -> x-frame-options"), text);
        assertFalse(text.contains("FIXED             -> x-frame-options"), text);
    }

    @Test
    void comparisonRejectsMismatchedTarget() {
        ScanResult now = result("https://other.example/", List.of(), Set.of());
        assertThrows(IllegalArgumentException.class,
                () -> new Comparison("https://e.example/", Set.of(), now));
    }
}
