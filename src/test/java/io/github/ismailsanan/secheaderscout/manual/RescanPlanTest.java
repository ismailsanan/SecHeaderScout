package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.report.ReportParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** SEC-9: the confirmation plan is complete, honest and immutable. */
class RescanPlanTest {

    private static ReportParser.PreviousResult prev(String url) {
        return new ReportParser.PreviousResult(url, Set.of());
    }

    @Test
    void invalidUrlsAreReportedNotSilentlyDropped() {
        RescanComparer.Plan plan = RescanComparer.plan(
                List.of(prev("https://a.example/"), prev("https://a.example/p?q={x}"), prev("javascript:alert(1)")),
                u -> true);
        assertEquals(1, plan.toScan().size());
        assertEquals(List.of("https://a.example/p?q={x}", "javascript:alert(1)"), plan.skippedInvalid());
    }

    @Test
    void aHostWithAnyOutOfScopeUrlIsFlagged() {
        RescanComparer.Plan plan = RescanComparer.plan(
                List.of(prev("https://a.example/in"), prev("https://a.example/out")),
                u -> u.endsWith("/in"));
        assertEquals(Set.of("a.example"), plan.outOfScopeHosts());
    }

    @Test
    void aScopeCheckThatThrowsCountsAsOutOfScope() {
        RescanComparer.Plan plan = RescanComparer.plan(List.of(prev("https://a.example/")), u -> {
            throw new IllegalArgumentException("Burp could not parse the URL");
        });
        assertEquals(Set.of("a.example"), plan.outOfScopeHosts());
    }

    @Test
    void thePlanTheUserConfirmsCannotBeChangedAfterwards() {
        RescanComparer.Plan plan = RescanComparer.plan(List.of(prev("https://a.example/")), u -> true);
        assertThrows(UnsupportedOperationException.class, () -> plan.hosts().add("evil.example"));
        assertThrows(UnsupportedOperationException.class, () -> plan.outOfScopeHosts().clear());
        assertThrows(UnsupportedOperationException.class, () -> plan.toScan().clear());
        List<ReportParser.PreviousResult> tooMany = new ArrayList<>();
        for (int i = 0; i <= RescanComparer.MAX_URLS; i++) {
            tooMany.add(prev("https://a.example/" + i));
        }
        assertThrows(IllegalArgumentException.class, () -> new RescanComparer.Plan(tooMany, tooMany.size(),
                new LinkedHashSet<>(List.of("a.example")), Set.of(), List.of()));
        assertThrows(IllegalArgumentException.class, () -> new RescanComparer.Plan(List.of(), 0,
                Set.of(), Set.of("not-listed.example"), List.of()));
    }

    @Test
    void aUrlThatFailedInTheOldReportComparesAsNoBaselineEndToEnd() {
        String url = "https://e.example/";
        String oldReport = io.github.ismailsanan.secheaderscout.report.ReportExporter.render(
                List.of(io.github.ismailsanan.secheaderscout.model.ScanResult.failed(url, url, "connection refused")),
                "v", java.time.ZonedDateTime.now());
        List<ReportParser.PreviousResult> previous = ReportParser.parse(oldReport);
        ManualScanner scanner = new ManualScanner(u -> HttpFetcher.Result.of(
                new io.github.ismailsanan.secheaderscout.model.ResponseSnapshot(u, "GET", 200, true,
                        io.github.ismailsanan.secheaderscout.headers.ResponseHeaders.empty(), true, false)),
                () -> new io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator(
                        io.github.ismailsanan.secheaderscout.engine.RuleSets.passiveRules(), (r, e) -> { }),
                io.github.ismailsanan.secheaderscout.util.Log.noop());
        RescanComparer.Outcome outcome = RescanComparer.compare(scanner,
                RescanComparer.plan(previous, u -> true), ProgressListener.none());
        var c = outcome.comparisons().get(0);
        assertTrue(c.noBaseline(), "a previously failed URL has no baseline");
        assertTrue(c.newlyMissing().isEmpty(), "no false NEW ISSUE wave");
    }

    @Test
    void aNonUtf8FileGetsAnExplanatoryMessage(@TempDir Path dir) throws Exception {
        Path legacy = dir.resolve("old.html");
        Files.write(legacy, new byte[]{'<', 'p', '>', (byte) 0xE9, (byte) 0xFF, '<', '/', 'p', '>'});
        RescanComparer.InvalidReportException e =
                assertThrows(RescanComparer.InvalidReportException.class, () -> RescanComparer.load(legacy));
        assertTrue(e.getMessage().contains("not UTF-8"), e.getMessage());
    }
}
