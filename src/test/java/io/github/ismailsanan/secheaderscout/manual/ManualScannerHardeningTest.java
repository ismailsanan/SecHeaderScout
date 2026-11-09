package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator;
import io.github.ismailsanan.secheaderscout.engine.HeaderRule;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.testsupport.RecordingLog;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** CC-7 / SEC-7: batch robustness, cancellation during a request, and log redaction at every call site. */
class ManualScannerHardeningTest {

    private final RecordingLog log = new RecordingLog();

    private static ResponseSnapshot ok(String url) {
        return new ResponseSnapshot(url, "GET", 200, url.startsWith("https"), ResponseHeaders.empty(), true, false);
    }

    /** A rule that crashes for URLs containing "boom"; the evaluator rethrows, simulating a bug past the guard. */
    private static HeaderEvaluator crashingFor(String marker) {
        return crashingFor(marker, (r, e) -> {
            throw e;
        });
    }

    private static HeaderEvaluator crashingFor(String marker, HeaderEvaluator.RuleErrorHandler handler) {
        HeaderRule rule = new HeaderRule() {
            @Override
            public String header() {
                return "X-Test";
            }

            @Override
            public boolean expectedOn(EvaluationContext context) {
                return false;
            }

            @Override
            public List<Finding> evaluate(ResponseHeaders headers, EvaluationContext context) {
                if (context.url().contains(marker)) {
                    throw new IllegalStateException("bug");
                }
                return List.of();
            }
        };
        return new HeaderEvaluator(List.of(rule), handler);
    }

    @Test
    void anAnalysisBugForOneTargetDoesNotDiscardTheRestOfTheBatch() {
        ManualScanner scanner = new ManualScanner(url -> HttpFetcher.Result.of(ok(url)), () -> crashingFor("boom"), log);
        ScanBatch batch = scanner.quickScan(List.of("https://a.example/", "https://boom.example/", "https://c.example/"),
                false, ProgressListener.none());
        assertEquals(3, batch.results().size());
        assertFalse(batch.results().get(0).hasError());
        assertTrue(batch.results().get(1).hasError());
        assertFalse(batch.results().get(2).hasError());
        assertEquals(1, log.errors.size());
    }

    @Test
    void cancellingDuringTheHttpsRequestSendsNoFallbackAndRecordsNoFakeError() {
        List<String> requested = new ArrayList<>();
        ManualScanner scanner = new ManualScanner(url -> {
            requested.add(url);
            Thread.currentThread().interrupt(); // the user pressed Cancel while this request was in flight
            return HttpFetcher.Result.failed("request failed: interrupted");
        }, () -> new HeaderEvaluator(List.of(), (r, e) -> { }), log);
        try {
            ScanBatch batch = scanner.quickScan(List.of("a.example", "b.example"), true, ProgressListener.none());
            assertEquals(List.of("https://a.example/"), requested, "no HTTP fallback after cancel");
            assertTrue(batch.cancelled());
            assertTrue(batch.results().isEmpty(), "the interrupted request is not an ERROR row");
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void logsNeverContainQueryStringsOrFragments() {
        String secretUrl = "https://e.example/reset?token=SECRET#frag";
        // fallback path (HTTPS fails, HTTP fails) + invalid target + throwing fetcher
        ManualScanner failing = new ManualScanner(url -> HttpFetcher.Result.failed("connection refused"),
                () -> new HeaderEvaluator(List.of(), (r, e) -> { }), log);
        failing.quickScan(List.of("e.example/reset?token=SECRET", secretUrl, "bad target?token=SECRET"), true,
                ProgressListener.none());
        ManualScanner throwing = new ManualScanner(url -> {
            throw new IllegalStateException("bug");
        }, () -> new HeaderEvaluator(List.of(), (r, e) -> { }), log);
        throwing.quickScan(List.of(secretUrl), false, ProgressListener.none());
        // per-target analysis bug and deep-scan analysis bug
        new ManualScanner(url -> HttpFetcher.Result.of(ok(url)), () -> crashingFor("token"), log)
                .quickScan(List.of(secretUrl), false, ProgressListener.none());
        new ManualScanner(url -> HttpFetcher.Result.failed("unused"), () -> crashingFor("token"), log)
                .deepScan(List.of("e.example"), new SiteMapSource() {
                    @Override
                    public List<String> hosts() {
                        return List.of("e.example");
                    }

                    @Override
                    public List<ResponseSnapshot> responsesFor(String host) {
                        return List.of(ok(secretUrl));
                    }
                }, ProgressListener.none());

        List<String> all = Stream.of(log.infos, log.warnings, log.errors).flatMap(List::stream).toList();
        assertFalse(all.isEmpty());
        assertTrue(all.stream().noneMatch(m -> m.contains("SECRET") || m.contains("frag")), all.toString());
    }

    @Test
    void anIncompleteEvaluationIsNeverReportedAsClean() {
        HeaderEvaluator guarded = crashingFor("e.example", (r, e) -> { }); // the production guard swallows + marks
        ScanResult r = new ManualScanner(url -> HttpFetcher.Result.of(ok(url)), () -> guarded, log)
                .quickScan(List.of("https://e.example/"), false, ProgressListener.none()).results().get(0);
        assertTrue(r.evaluationIncomplete());
        assertTrue(r.findings().isEmpty());
        assertFalse(r.isClean(), "no findings because a rule crashed is not 'clean'");
        assertTrue(r.notes().stream().anyMatch(n -> n.contains("NOT assessed")));
    }
}
