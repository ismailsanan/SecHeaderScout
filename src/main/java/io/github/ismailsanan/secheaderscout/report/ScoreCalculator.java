package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.model.ScanResult;

import java.util.List;
import java.util.Map;

/**
 * Weighted overall risk rating for a set of manual-scan results. Missing
 * headers count with their full weight, other findings with half of it, and
 * logout/payment endpoints get a multiplier. Results with errors are excluded.
 *
 * <p>Each analysed URL gets a ratio (its weighted findings over the worst case for
 * one URL); the overall score is the <em>average</em> ratio, so it does not depend on
 * how many URLs were scanned: 100 identical pages rate the same as one.</p>
 *
 * <p>A result whose evaluation is incomplete (a rule crashed) still counts with the
 * findings that were produced, so it is never treated as clean by omission, but its
 * unassessed headers cannot contribute: the score is then a lower bound
 * ({@link #hasIncompleteEvaluations}).</p>
 */
public final class ScoreCalculator {

    public enum Score {
        INFO("INFO"),
        LOW("LOW RISK"),
        MEDIUM("MEDIUM RISK"),
        HIGH("HIGH RISK"),
        CRITICAL("CRITICAL");

        private final String label;

        Score(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /**
     * Weight per header, based on its security impact when absent. Case-insensitive, so findings
     * are looked up without normalising every header name.
     */
    private static final Map<String, Double> HEADER_WEIGHTS = caseInsensitive(Map.ofEntries(
            Map.entry("content-security-policy", 9.0),
            Map.entry("strict-transport-security", 8.0),
            Map.entry("x-frame-options", 6.5),
            Map.entry("cross-origin-opener-policy", 6.0),
            Map.entry("cross-origin-resource-policy", 6.0),
            Map.entry("cross-origin-embedder-policy", 5.5),
            Map.entry("x-content-type-options", 5.0),
            Map.entry("cache-control", 5.0),
            Map.entry("clear-site-data", 5.0),
            Map.entry("referrer-policy", 4.0),
            Map.entry("permissions-policy", 3.5),
            Map.entry("x-permitted-cross-domain-policies", 3.0),
            Map.entry("x-dns-prefetch-control", 1.5)));

    private static final double DEFAULT_WEIGHT = 2.0;
    private static final double MAX_PER_URL =
            HEADER_WEIGHTS.values().stream().mapToDouble(Double::doubleValue).sum();
    private static final double MISCONFIG_FACTOR = 0.5;
    private static final double SENSITIVE_URL_MULTIPLIER = 1.5;
    private static Map<String, Double> caseInsensitive(Map<String, Double> weights) {
        java.util.TreeMap<String, Double> map = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        map.putAll(weights);
        return java.util.Collections.unmodifiableMap(map);
    }

    private ScoreCalculator() {
    }

    public static Score calculate(List<ScanResult> results) {
        List<ScanResult> analysed = results.stream().filter(r -> !r.hasError()).toList();
        if (analysed.isEmpty()) {
            return Score.INFO;
        }
        double ratioSum = 0.0;
        for (ScanResult result : analysed) {
            double urlScore = 0.0;
            for (Finding f : result.findings()) {
                double weight = HEADER_WEIGHTS.getOrDefault(f.header(), DEFAULT_WEIGHT);
                urlScore += f.type().isMissing() ? weight : weight * MISCONFIG_FACTOR;
            }
            UrlClassifier.UrlType type = result.urlType();
            if (type == UrlClassifier.UrlType.LOGOUT || type == UrlClassifier.UrlType.PAYMENT) {
                urlScore *= SENSITIVE_URL_MULTIPLIER;
            }
            ratioSum += urlScore / MAX_PER_URL;
        }
        double normalised = Math.min(ratioSum / analysed.size() * 10.0, 10.0);
        if (normalised < 1.0) {
            return Score.INFO;
        }
        if (normalised < 4.0) {
            return Score.LOW;
        }
        if (normalised < 7.0) {
            return Score.MEDIUM;
        }
        if (normalised < 9.0) {
            return Score.HIGH;
        }
        return Score.CRITICAL;
    }

    /** {@code true} if a score from {@code results} is only a lower bound because some rules crashed. */
    public static boolean hasIncompleteEvaluations(List<ScanResult> results) {
        return results.stream().anyMatch(ScanResult::evaluationIncomplete); // invariant: never errored
    }
}
