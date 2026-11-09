package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.definitions.DefinitionsRepository;
import io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator;
import io.github.ismailsanan.secheaderscout.engine.RuleSets;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.testsupport.RecordingLog;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** FR-7, FR-8, SEC-5: fallback boundaries, rescans, and evaluator lifecycle. */
class ManualScannerFallbackBoundaryTest {

    private final RecordingLog log = new RecordingLog();
    private final List<String> requested = new ArrayList<>();
    private final Map<String, HttpFetcher.Result> responses = new HashMap<>();
    private final AtomicInteger evaluatorsBuilt = new AtomicInteger();

    private static ResponseSnapshot html(String url, int status, String... headers) {
        return new ResponseSnapshot(url, "GET", status, url.startsWith("https"), ResponseHeaders.of(headers), true, false);
    }

    private ManualScanner scanner() {
        var defs = DefinitionsRepository.fromBundledResource().current().headers();
        return new ManualScanner(url -> {
            requested.add(url);
            return responses.getOrDefault(url, HttpFetcher.Result.failed("connection refused"));
        }, () -> {
            evaluatorsBuilt.incrementAndGet();
            return new HeaderEvaluator(RuleSets.manualRules(defs), (r, e) -> log.error("rule", e));
        }, log);
    }

    @Test
    void status399DoesNotTriggerFallback() {
        responses.put("https://example.com/", HttpFetcher.Result.of(html("https://example.com/", 399)));
        ScanResult r = scanner().quickScan(List.of("example.com"), true, ProgressListener.none()).results().get(0);
        assertEquals(List.of("https://example.com/"), requested);
        assertFalse(r.httpFallback());
    }

    @Test
    void status400TriggersFallback() {
        responses.put("https://example.com/", HttpFetcher.Result.of(html("https://example.com/", 400)));
        responses.put("http://example.com/", HttpFetcher.Result.of(html("http://example.com/", 200)));
        ScanResult r = scanner().quickScan(List.of("example.com"), true, ProgressListener.none()).results().get(0);
        assertTrue(r.httpFallback());
        assertEquals(400, r.originalHttpsStatus());
        assertEquals("HTTPS returned status 400", r.fallbackReason());
        assertTrue(log.warnings.stream().anyMatch(w -> w.contains("retrying over plain HTTP")), log.warnings.toString());
    }

    @Test
    void disabledFallbackAnalysesTheHttpsErrorResponseInstead() {
        responses.put("https://example.com/", HttpFetcher.Result.of(html("https://example.com/", 503)));
        ScanResult r = scanner().quickScan(List.of("example.com"), false, ProgressListener.none()).results().get(0);
        assertEquals(List.of("https://example.com/"), requested);
        assertFalse(r.httpFallback());
        assertNull(r.originalHttpsStatus());
        assertEquals(503, r.statusCode());
        assertTrue(r.secure());
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://example.com/", "http://example.com/"})
    void rescanNeverFallsBackAndKeepsTheExactUrl(String url) {
        ScanResult r = scanner().rescanUrls(List.of(url), ProgressListener.none()).results().get(0);
        assertEquals(List.of(url), requested);
        assertTrue(r.hasError());
        assertFalse(r.httpFallback());
    }

    @Test
    void hstsOnAnHttpFallbackResponseIsNeverJudged() {
        // even a weak HSTS header sent over HTTP must not produce a finding: browsers ignore it there
        responses.put("http://example.com/", HttpFetcher.Result.of(
                html("http://example.com/", 200, "Strict-Transport-Security", "max-age=0")));
        ScanResult r = scanner().quickScan(List.of("example.com"), true, ProgressListener.none()).results().get(0);
        assertTrue(r.httpFallback());
        assertTrue(r.findings().stream().noneMatch(f -> f.header().equalsIgnoreCase("Strict-Transport-Security")),
                r.findings().toString());
    }

    @Test
    void failedResultsCarryNoFindingsAndAreNotClean() {
        ScanResult r = scanner().quickScan(List.of("example.com"), false, ProgressListener.none()).results().get(0);
        assertTrue(r.hasError());
        assertFalse(r.isClean(), "an unanalysed URL must never look clean");
        assertTrue(r.findings().isEmpty());
        assertEquals(-1, r.statusCode());
    }

    @Test
    void evaluatorIsBuiltOncePerOperationNotPerTarget() {
        scanner().quickScan(List.of("a.example", "b.example", "c.example"), false, ProgressListener.none());
        assertEquals(1, evaluatorsBuilt.get());
    }

    @Test
    void progressIsReportedForEveryTargetAndCompletes() {
        List<String> progress = new ArrayList<>();
        scanner().quickScan(List.of("a.example", "b.example"), false,
                (done, total, current) -> progress.add(done + "/" + total + ":" + current));
        assertEquals(List.of("0/2:a.example", "1/2:b.example", "2/2:"), progress);
    }

    @Test
    void deepScanSendsNoRequestsAndAnalysesEveryCapturedResponse() {
        ManualScanner s = new ManualScanner(url -> {
            throw new AssertionError("deep scan must not send requests");
        }, () -> new HeaderEvaluator(List.of(), (r, e) -> { }), log);
        SiteMapSource siteMap = new SiteMapSource() {
            @Override
            public List<String> hosts() {
                return List.of("h");
            }

            @Override
            public List<ResponseSnapshot> responsesFor(String host) {
                return List.of(html("https://h/", 200));
            }
        };
        ScanBatch b = s.deepScan(List.of("h", "h"), siteMap, ProgressListener.none());
        assertEquals(2, b.results().size());
        assertTrue(b.results().stream().allMatch(ScanResult::isClean));
    }

    @Test
    void deepScanStopsBetweenHostsWhenInterrupted() {
        AtomicInteger hostsRead = new AtomicInteger();
        SiteMapSource siteMap = new SiteMapSource() {
            @Override
            public List<String> hosts() {
                return List.of();
            }

            @Override
            public List<ResponseSnapshot> responsesFor(String host) {
                hostsRead.incrementAndGet();
                Thread.currentThread().interrupt(); // user pressed Cancel while the first host was read
                return List.of(html("https://" + host + "/", 200));
            }
        };
        try {
            ScanBatch b = scanner().deepScan(List.of("a", "b", "c"), siteMap, ProgressListener.none());
            assertTrue(b.cancelled());
            assertEquals(1, hostsRead.get());
            assertTrue(b.results().isEmpty());
        } finally {
            Thread.interrupted();
        }
    }
}
