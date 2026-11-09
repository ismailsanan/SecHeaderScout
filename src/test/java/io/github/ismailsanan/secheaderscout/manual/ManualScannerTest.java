package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.definitions.DefinitionsRepository;
import io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator;
import io.github.ismailsanan.secheaderscout.engine.RuleSets;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.testsupport.RecordingLog;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ManualScannerTest {

    private final RecordingLog log = new RecordingLog();
    private final List<String> requested = new ArrayList<>();
    private final Map<String, HttpFetcher.Result> responses = new HashMap<>();

    private static ResponseSnapshot html(String url, int status, String... headers) {
        return new ResponseSnapshot(url, "GET", status, url.startsWith("https"), ResponseHeaders.of(headers), true, false);
    }

    private ManualScanner scanner() {
        HttpFetcher fetcher = url -> {
            requested.add(url);
            return responses.getOrDefault(url, HttpFetcher.Result.failed("connection refused"));
        };
        var defs = DefinitionsRepository.fromBundledResource().current().headers();
        return new ManualScanner(fetcher,
                () -> new HeaderEvaluator(RuleSets.manualRules(defs), (r, e) -> log.error("rule", e)), log);
    }

    private ScanResult quick(String target, boolean fallback) {
        return scanner().quickScan(List.of(target), fallback, ProgressListener.none()).results().get(0);
    }

    @Test
    void httpsSuccessIsAnalysedWithoutFallback() {
        responses.put("https://example.com/", HttpFetcher.Result.of(html("https://example.com/", 200)));
        ScanResult r = quick("example.com", true);
        assertEquals(List.of("https://example.com/"), requested, "no double slash, no extra request");
        assertFalse(r.httpFallback());
        assertEquals("HTTPS", r.protocol());
        assertTrue(r.missingHeaderNames().contains("Strict-Transport-Security"));
    }

    @Test
    void fallbackOnConnectionFailureIsRecorded() {
        responses.put("http://example.com/", HttpFetcher.Result.of(html("http://example.com/", 200)));
        ScanResult r = quick("example.com", true);
        assertEquals(List.of("https://example.com/", "http://example.com/"), requested);
        assertTrue(r.httpFallback());
        assertNull(r.originalHttpsStatus());
        assertTrue(r.fallbackReason().contains("connection refused"));
        assertEquals("HTTP", r.protocol());
        assertEquals("http://example.com/", r.url(), "never presented as HTTPS");
        assertTrue(r.fallbackWarning().contains("gave no response"));
    }

    @Test
    void fallbackOnErrorStatusRecordsOriginalStatus() {
        responses.put("https://example.com/", HttpFetcher.Result.of(html("https://example.com/", 503)));
        responses.put("http://example.com/", HttpFetcher.Result.of(html("http://example.com/", 200)));
        ScanResult r = quick("example.com", true);
        assertTrue(r.httpFallback());
        assertEquals(503, r.originalHttpsStatus());
        assertTrue(r.notes().stream().anyMatch(n -> n.startsWith("HTTP fallback")));
    }

    @Test
    void hstsIsNotInferredFromHttpFallbackResponse() {
        responses.put("http://example.com/", HttpFetcher.Result.of(html("http://example.com/", 200)));
        ScanResult r = quick("example.com", true);
        assertFalse(r.missingHeaderNames().contains("Strict-Transport-Security"));
        assertTrue(r.findings().stream().noneMatch(f -> f.header().equals("Strict-Transport-Security")));
        assertTrue(r.notes().stream().anyMatch(n -> n.contains("Strict-Transport-Security was not evaluated")));
    }

    @Test
    void fallbackCanBeDisabled() {
        ScanResult r = quick("example.com", false);
        assertEquals(List.of("https://example.com/"), requested);
        assertTrue(r.hasError());
        assertTrue(r.error().contains("connection refused"));
    }

    @Test
    void explicitSchemeIsHonouredWithoutFallback() {
        quick("https://example.com/path?q=1", true);
        assertEquals(List.of("https://example.com/path?q=1"), requested);
        requested.clear();
        quick("http://example.com:8080", true);
        assertEquals(List.of("http://example.com:8080/"), requested);
    }

    @Test
    void bothProtocolsFailingGivesAnErrorResultNotFakeFindings() {
        ScanResult r = quick("example.com", true);
        assertTrue(r.hasError());
        assertTrue(r.findings().isEmpty());
        assertTrue(r.error().contains("HTTPS:") && r.error().contains("HTTP fallback:"));
    }

    @Test
    void httpsErrorStatusAnalysedWhenHttpFallbackFails() {
        responses.put("https://example.com/", HttpFetcher.Result.of(html("https://example.com/", 404)));
        ScanResult r = quick("example.com", true);
        assertFalse(r.hasError());
        assertFalse(r.httpFallback());
        assertEquals(404, r.statusCode());
    }

    @Test
    void redirectsAreNotedNotFollowed() {
        responses.put("https://example.com/", HttpFetcher.Result.of(
                html("https://example.com/", 302, "Location", "https://example.com/login")));
        ScanResult r = quick("example.com", true);
        assertEquals(1, requested.size());
        assertTrue(r.notes().stream().anyMatch(n -> n.contains("redirect (302)")));
    }

    @Test
    void invalidTargetsAreRejectedWithoutRequests() {
        for (String bad : new String[]{"", "a b", "ftp://x", "https://user@host/", "http://"}) {
            assertTrue(quick(bad, true).hasError(), bad);
        }
        assertTrue(requested.isEmpty());
    }

    @Test
    void unexpectedFetcherExceptionIsContainedAndLogged() {
        ManualScanner s = new ManualScanner(url -> {
            throw new IllegalStateException("bug");
        }, () -> new HeaderEvaluator(List.of(), (r, e) -> {
        }), log);
        ScanBatch b = s.quickScan(List.of("a.example", "b.example"), false, ProgressListener.none());
        assertEquals(2, b.results().size());
        assertTrue(b.results().stream().allMatch(ScanResult::hasError));
        assertEquals(2, log.errors.size());
    }

    @Test
    void quickScanStopsWhenCancelled() throws Exception {
        CountDownLatch firstRequest = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger();
        ManualScanner s = new ManualScanner(url -> {
            calls.incrementAndGet();
            firstRequest.countDown();
            try {
                release.await(); // Burp's sendRequest is not interruptible: simulate a blocking call
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return HttpFetcher.Result.failed("cancelled");
        }, () -> new HeaderEvaluator(List.of(), (r, e) -> {
        }), log);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<ScanBatch> f = pool.submit(() -> s.quickScan(List.of("a.example", "b.example", "c.example"),
                    false, ProgressListener.none()));
            assertTrue(firstRequest.await(5, TimeUnit.SECONDS));
            f.cancel(true);
            release.countDown();
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
            assertEquals(1, calls.get(), "no further targets requested after cancellation");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void cancellationReturnsPartialBatch() {
        Thread.currentThread().interrupt();
        try {
            ScanBatch b = scanner().quickScan(List.of("a.example", "b.example"), true, ProgressListener.none());
            assertTrue(b.cancelled());
            assertTrue(b.results().isEmpty());
            assertTrue(requested.isEmpty());
        } finally {
            Thread.interrupted(); // clear flag
        }
    }

    @Test
    void deepScanAnalysesCapturedResponsesWithoutRequests() {
        SiteMapSource siteMap = new SiteMapSource() {
            @Override
            public List<String> hosts() {
                return List.of("example.com");
            }

            @Override
            public List<ResponseSnapshot> responsesFor(String host) {
                return List.of(html("https://example.com/", 200),
                        new ResponseSnapshot("https://example.com/logo.png", "GET", 200, true,
                                ResponseHeaders.of("Content-Type", "image/png"), false, false));
            }
        };
        List<int[]> progress = new ArrayList<>();
        ScanBatch b = scanner().deepScan(List.of("example.com"), siteMap, (d, t, c) -> progress.add(new int[]{d, t}));
        assertTrue(requested.isEmpty());
        assertEquals(2, b.results().size());
        assertFalse(b.cancelled());
        assertFalse(b.results().get(1).missingHeaderNames().contains("Content-Security-Policy"),
                "document-only headers not expected on images");
        assertFalse(progress.isEmpty());
    }

    @Test
    void scanTargetParsing() {
        assertEquals("https://h:8443/a?b", ScanTarget.parse("h:8443/a?b").orElseThrow().url("https"));
        assertEquals("http://h/", ScanTarget.parse("HTTP://h").orElseThrow().url("http"));
        assertTrue(ScanTarget.parse("h").orElseThrow().fallbackPossible());
        assertFalse(ScanTarget.parse("https://h").orElseThrow().fallbackPossible());
        assertEquals("[::1]:8080", ScanTarget.parse("[::1]:8080").orElseThrow().authority());
    }
}
