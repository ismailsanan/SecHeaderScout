package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;
import io.github.ismailsanan.secheaderscout.report.ReportParser;
import io.github.ismailsanan.secheaderscout.testsupport.RecordingLog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** S-2 / A-3: rescans from untrusted report files are planned, capped and scope-checked before sending. */
class RescanComparerTest {

    private static ReportParser.PreviousResult prev(String url, String... missing) {
        return new ReportParser.PreviousResult(url, Set.of(missing));
    }

    @Test
    void planListsHostsFlagsOutOfScopeAndDropsInvalidUrls() {
        RescanComparer.Plan plan = RescanComparer.plan(List.of(
                prev("https://app.example/a"), prev("https://app.example/a"), prev("https://app.example:8443/b"),
                prev("http://169.254.169.254/latest/meta-data/"), prev("javascript:alert(1)"), prev("not a url")),
                url -> url.startsWith("https://app.example"));
        assertEquals(3, plan.toScan().size(), "duplicates and invalid URLs removed");
        assertEquals(Set.of("app.example", "169.254.169.254"), plan.hosts());
        assertEquals(Set.of("169.254.169.254"), plan.outOfScopeHosts());
        assertFalse(plan.truncated());
    }

    @Test
    void planCapsTheNumberOfUrls() {
        List<ReportParser.PreviousResult> many = new ArrayList<>();
        for (int i = 0; i < RescanComparer.MAX_URLS + 50; i++) {
            many.add(prev("https://e.example/" + i));
        }
        RescanComparer.Plan plan = RescanComparer.plan(many, u -> true);
        assertEquals(RescanComparer.MAX_URLS, plan.toScan().size());
        assertEquals(RescanComparer.MAX_URLS + 50, plan.totalUrls());
        assertTrue(plan.truncated());
    }

    @Test
    void compareRescansExactlyThePlannedUrls() {
        List<String> requested = new ArrayList<>();
        ManualScanner scanner = new ManualScanner(url -> {
            requested.add(url);
            return HttpFetcher.Result.of(new ResponseSnapshot(url, "GET", 200, true,
                    ResponseHeaders.of("Referrer-Policy", "no-referrer"), true, false));
        }, () -> new HeaderEvaluator(io.github.ismailsanan.secheaderscout.engine.RuleSets.passiveRules(), (r, e) -> {
        }), new RecordingLog());
        RescanComparer.Plan plan = RescanComparer.plan(List.of(prev("https://e.example/p?q=1", "referrer-policy")),
                u -> true);
        RescanComparer.Outcome outcome = RescanComparer.compare(scanner, plan, ProgressListener.none());
        assertEquals(List.of("https://e.example/p?q=1"), requested, "no fallback, exact URL");
        assertEquals(List.of("referrer-policy"), outcome.comparisons().get(0).fixed());
    }

    @Test
    void loadRejectsOversizedAndForeignFiles(@TempDir Path dir) throws Exception {
        Path big = dir.resolve("big.html");
        Files.write(big, new byte[(int) RescanComparer.MAX_REPORT_BYTES + 1]);
        assertThrows(RescanComparer.InvalidReportException.class, () -> RescanComparer.load(big));
        Path foreign = dir.resolve("other.html");
        Files.writeString(foreign, "<html><body>hello</body></html>");
        assertThrows(RescanComparer.InvalidReportException.class, () -> RescanComparer.load(foreign));
    }

    /** A-2: a Deep Scan interrupted after its last host must report cancellation, not "finished". */
    @Test
    void deepScanReportsCancellationAfterLastHost() {
        SiteMapSource siteMap = new SiteMapSource() {
            @Override
            public List<String> hosts() {
                return List.of("e.example");
            }

            @Override
            public List<ResponseSnapshot> responsesFor(String host) {
                Thread.currentThread().interrupt(); // like BurpSiteMapSource stopping early
                return List.of();
            }
        };
        ManualScanner scanner = new ManualScanner(url -> HttpFetcher.Result.failed("unused"),
                () -> new HeaderEvaluator(List.of(), (r, e) -> {
                }), new RecordingLog());
        try {
            assertTrue(scanner.deepScan(List.of("e.example"), siteMap, ProgressListener.none()).cancelled());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void scanTargetHost() {
        assertEquals("e.example", ScanTarget.parse("https://e.example:8443/x").orElseThrow().host());
        assertEquals("::1", ScanTarget.parse("[::1]:80").orElseThrow().host());
    }
}
