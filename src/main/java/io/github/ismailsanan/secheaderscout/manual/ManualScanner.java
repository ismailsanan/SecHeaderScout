package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.util.UrlPaths;

import io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator;
import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.util.Log;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Manual (user-triggered) scanning: Quick Scan sends one GET per target (plus one
 * plain-HTTP GET when HTTPS fails and fallback is enabled); Rescan sends exactly one GET
 * per URL; Deep Scan re-analyses responses already in the site map. Independent of the
 * passive scanner and of Swing. Safe to call from any worker thread; checks
 * the thread's interrupt flag between URLs so operations can be cancelled.
 */
public final class ManualScanner {

    private final HttpFetcher fetcher;
    private final Supplier<HeaderEvaluator> evaluatorSupplier;
    private final Log log;

    /**
     * @param evaluatorSupplier supplies the evaluator for the currently active OWASP definitions;
     *                          called once per operation so a definitions refresh applies to the next scan
     */
    public ManualScanner(HttpFetcher fetcher, Supplier<HeaderEvaluator> evaluatorSupplier, Log log) {
        this.fetcher = Objects.requireNonNull(fetcher);
        this.evaluatorSupplier = Objects.requireNonNull(evaluatorSupplier);
        this.log = Objects.requireNonNull(log);
    }

    /** Quick Scan of several targets, in order. */
    public ScanBatch quickScan(List<String> targets, boolean allowHttpFallback, ProgressListener progress) {
        HeaderEvaluator evaluator = evaluatorSupplier.get();
        List<ScanResult> results = new ArrayList<>();
        for (int i = 0; i < targets.size(); i++) {
            if (Thread.currentThread().isInterrupted()) {
                return new ScanBatch(results, true);
            }
            String target = targets.get(i);
            progress.onProgress(i, targets.size(), target);
            ScanResult result = analyzeSafely("[QUICK]", target, () -> scanOne(target, allowHttpFallback, evaluator));
            if (Thread.currentThread().isInterrupted()) {
                // cancelled while this target was in flight: its outcome is an artefact of the cancel
                return new ScanBatch(results, true);
            }
            results.add(result);
        }
        progress.onProgress(targets.size(), targets.size(), "");
        return new ScanBatch(results, Thread.currentThread().isInterrupted());
    }

    /** Rescans exact URLs (used by Rescan &amp; Compare); no fallback, scheme is honoured. */
    public ScanBatch rescanUrls(List<String> urls, ProgressListener progress) {
        return quickScan(urls, false, progress);
    }

    ScanResult scanOne(String target, boolean allowHttpFallback, HeaderEvaluator evaluator) {
        Optional<ScanTarget> parsed = ScanTarget.parse(target);
        if (parsed.isEmpty()) {
            log.warn("[QUICK] Ignoring invalid target: " + Log.redact(target));
            return ScanResult.failed(target, target, "Invalid target. Use a host name, host:port or an http(s) URL.");
        }
        ScanTarget t = parsed.get();
        String primaryUrl = t.url(t.primaryScheme());
        log.info("[QUICK] Requesting " + Log.redact(primaryUrl));
        HttpFetcher.Result primary = fetchSafely(primaryUrl);
        if (Thread.currentThread().isInterrupted()) {
            // cancelled during the request: never send the fallback after the user pressed Cancel
            // (the caller discards this result because the interrupt flag is set)
            return ScanResult.failed(target, primaryUrl, "cancelled");
        }

        boolean httpsFailed = !primary.ok() || primary.response().statusCode() >= 400;
        if (allowHttpFallback && t.fallbackPossible() && httpsFailed) {
            Integer httpsStatus = primary.ok() ? primary.response().statusCode() : null;
            String reason = primary.ok()
                    ? "HTTPS returned status " + httpsStatus
                    : "HTTPS request failed (" + primary.failure() + ")";
            String httpUrl = t.url("http");
            log.warn("[QUICK] " + reason + " for " + Log.redact(primaryUrl) + "; retrying over plain HTTP: " + Log.redact(httpUrl));
            HttpFetcher.Result fallback = fetchSafely(httpUrl);
            if (fallback.ok()) {
                return ResponseAnalyzer.analyze(target, fallback.response(), evaluator,
                        new ResponseAnalyzer.Fallback(httpsStatus, reason));
            }
            log.warn("[QUICK] HTTP fallback also failed for " + Log.redact(httpUrl) + ": " + fallback.failure());
            if (!primary.ok()) {
                return ScanResult.failed(target, primaryUrl,
                        "HTTPS: " + primary.failure() + "; HTTP fallback: " + fallback.failure());
            }
            // HTTPS answered with an error status and HTTP failed: analyse the HTTPS response
        }
        if (!primary.ok()) {
            return ScanResult.failed(target, primaryUrl, primary.failure());
        }
        return ResponseAnalyzer.analyze(target, primary.response(), evaluator, null);
    }

    static final String INTERNAL_ERROR = "Internal error during analysis; see the extension error log";

    /** A bug while analysing one target must not discard the results already gathered. */
    private ScanResult analyzeSafely(String tag, String target, java.util.function.Supplier<ScanResult> analysis) {
        try {
            return analysis.get();
        } catch (RuntimeException e) {
            log.error(tag + " Unexpected error analysing " + Log.redact(target), e);
            return ScanResult.failed(target, target, INTERNAL_ERROR);
        }
    }

    /** Programming errors in a fetcher must not abort a whole batch. */
    private HttpFetcher.Result fetchSafely(String url) {
        try {
            return fetcher.fetch(url);
        } catch (RuntimeException e) {
            log.error("[QUICK] Unexpected error requesting " + Log.redact(url), e);
            return HttpFetcher.Result.failed("unexpected error: " + e.getClass().getSimpleName());
        }
    }

    /**
     * Deep Scan with every captured response analysed and nothing merged (no noise filters).
     * Kept for callers that want the raw per-URL view.
     */
    public ScanBatch deepScan(List<String> hosts, SiteMapSource siteMap, ProgressListener progress) {
        return deepScan(hosts, siteMap, DeepScanOptions.EVERYTHING, progress).batch();
    }

    /**
     * Deep Scan: analyses responses already captured for each host and groups them into
     * header profiles. Sends no requests. Noise filters run BEFORE analysis, so skipped
     * responses cost nothing; each filter's effect is counted in the result's stats.
     */
    public DeepScanResult deepScan(List<String> hosts, SiteMapSource siteMap, DeepScanOptions options,
                                   ProgressListener progress) {
        DeepScanRun run = new DeepScanRun(evaluatorSupplier.get(), options, progress);
        for (String host : hosts) {
            if (Thread.currentThread().isInterrupted()) {
                break;
            }
            run.startHost(host);
            siteMap.forEachResponse(host, run::visit); // streamed: each response is analysed, then dropped
            log.info("[DEEP] " + host + ": " + run.capturedForHost + " captured responses");
        }
        return run.result(Thread.currentThread().isInterrupted());
    }

    /** State of one Deep Scan: the noise filters, their counters and the analysed endpoints. */
    private final class DeepScanRun {
        private final HeaderEvaluator evaluator;
        private final DeepScanOptions options;
        private final ProgressListener progress;
        private final List<ProfileGrouper.Analysed> analysed = new ArrayList<>();
        private final java.util.Set<String> seenEndpoints = new java.util.HashSet<>();
        private String host;
        private int capturedForHost;
        private int captured;
        private int skippedStatic;
        private int skippedErrors;
        private int skippedRedirects;
        private int merged;
        private int skippedOther;

        DeepScanRun(HeaderEvaluator evaluator, DeepScanOptions options, ProgressListener progress) {
            this.evaluator = evaluator;
            this.options = options;
            this.progress = progress;
        }

        void startHost(String value) {
            host = value;
            capturedForHost = 0;
            seenEndpoints.clear();
        }

        /** Filters, then analyses one response. Returns {@code false} once the scan is cancelled. */
        boolean visit(int index, int total, ResponseSnapshot snapshot) {
            if (Thread.currentThread().isInterrupted()) {
                return false;
            }
            captured++;
            capturedForHost++;
            progress.onProgress(index, total, snapshot.url());
            int status = snapshot.statusCode();
            if (status < 200) {
                skippedOther++;
            } else if (status >= 300 && status < 400 && !options.includeRedirects()) {
                skippedRedirects++;
            } else if (status >= 400 && !options.includeErrors()) {
                skippedErrors++;
            } else if (!options.includeStatic() && StaticResources.isStatic(snapshot)) {
                skippedStatic++;
            } else if (options.mergeQueryVariants()
                    && !seenEndpoints.add(snapshot.method() + " " + UrlPaths.withoutQuery(snapshot.url()))) {
                merged++;
            } else {
                ScanResult result = analyzeSafely("[DEEP]", snapshot.url(),
                        () -> ResponseAnalyzer.analyze(snapshot.url(), snapshot, evaluator, null));
                analysed.add(new ProfileGrouper.Analysed(host, result));
            }
            return true;
        }

        DeepScanResult result(boolean cancelled) {
            List<ScanResult> results = analysed.stream().map(ProfileGrouper.Analysed::result).toList();
            DeepScanResult.Stats stats = new DeepScanResult.Stats(captured, results.size(), skippedStatic,
                    skippedErrors, skippedRedirects, merged, skippedOther);
            return new DeepScanResult(results, ProfileGrouper.group(analysed), stats, cancelled);
        }
    }
}
