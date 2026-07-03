import java.awt.Color;
import java.util.List;
import java.util.Map;

// calculates a weighted security score based on which specific headers are missing
public class ScoreCalculator {

    public enum Score {
        INFO,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    // weight per header based on  security impact
    // 9.0 = directly enables XSS or data theft if missing
    // 7.0 = enables protocol downgrade or cross-origin attacks
    // 5.0 = enables MIME confusion, framing, or side-channel
    // 3.0 = information leakage or weaker cross-origin controls
    // 1.5 = low impact hygiene headers
    private static final Map<String, Double> HEADER_WEIGHTS = Map.ofEntries(
            Map.entry("content-security-policy",           9.0),
            Map.entry("strict-transport-security",         8.0),
            Map.entry("x-frame-options",                   6.5),
            Map.entry("cross-origin-opener-policy",        6.0),
            Map.entry("cross-origin-resource-policy",      6.0),
            Map.entry("cross-origin-embedder-policy",      5.5),
            Map.entry("x-content-type-options",            5.0),
            Map.entry("cache-control",                     5.0),
            Map.entry("clear-site-data",                   5.0),
            Map.entry("referrer-policy",                   4.0),
            Map.entry("permissions-policy",                3.5),
            Map.entry("x-permitted-cross-domain-policies", 3.0),
            Map.entry("x-dns-prefetch-control",            1.5)
    );

    // maximum possible score if every header were missing on one URL
    private static final double MAX_POSSIBLE =
            HEADER_WEIGHTS.values().stream().mapToDouble(Double::doubleValue).sum();

    // misconfigured headers count as half the missing weight
    private static final double MISCONFIG_FACTOR = 0.5;

    // sensitive endpoints get a multiplier  missing clear-site-data on /logout is worse
    private static final double SENSITIVE_URL_MULTIPLIER = 1.5;

    public static Score calculate(List<ScanResult> results) {
        if (results == null || results.isEmpty()) return Score.INFO;

        double totalScore = 0.0;

        for (ScanResult result : results) {

            double urlScore = 0.0;

            // add weight for each missing header
            for (String header : result.getMissingHeaders()) {
                urlScore += HEADER_WEIGHTS.getOrDefault(header.toLowerCase(), 2.0);
            }

            // add half weight for each misconfigured header
            for (String issue : result.getMisconfiguredHeaders()) {
                String headerName = extractHeaderName(issue);
                urlScore += HEADER_WEIGHTS.getOrDefault(headerName, 2.0) * MISCONFIG_FACTOR;
            }

            // boost score for sensitive endpoints
            UrlClassifier.UrlType type = result.getUrlType();
            if (type == UrlClassifier.UrlType.LOGOUT ||
                    type == UrlClassifier.UrlType.PAYMENT) {
                urlScore *= SENSITIVE_URL_MULTIPLIER;
            }

            totalScore += urlScore;
        }

        // normalize against worst case cap at 10 URLs to avoid Deep Scan inflating the score
        // scanning 300 URLs shouldnt automatically give a CRITICAL score
        double worstCase = MAX_POSSIBLE * Math.min(results.size(), 10);
        double normalized = Math.min((totalScore / worstCase) * 10.0, 10.0);

        return toScore(normalized);
    }

    private static Score toScore(double score) {
        if (score < 1.0) return Score.INFO;
        if (score < 4.0) return Score.LOW;
        if (score < 7.0) return Score.MEDIUM;
        if (score < 9.0) return Score.HIGH;
        return Score.CRITICAL;
    }

    // misconfigured header strings
    // extract just the header name for weight lookup
    private static String extractHeaderName(String issue) {
        if (issue.contains(":")) return issue.split(":")[0].trim().toLowerCase();
        return issue.toLowerCase();
    }

    public static String getLabel(Score score) {
        return switch (score) {
            case INFO     -> "INFO";
            case LOW      -> "LOW RISK";
            case MEDIUM   -> "MEDIUM RISK";
            case HIGH     -> "HIGH RISK";
            case CRITICAL -> "CRITICAL";
        };
    }

    public static Color getColor(Score score) {
        return switch (score) {
            case INFO     -> new Color(100, 150, 255);
            case LOW      -> new Color(0, 150, 0);
            case MEDIUM   -> new Color(200, 150, 0);
            case HIGH     -> new Color(200, 100, 0);
            case CRITICAL -> new Color(200, 0, 0);
        };
    }
}