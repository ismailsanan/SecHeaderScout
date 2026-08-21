import java.awt.Color;
import java.util.List;
import java.util.Map;

/**
 * weighted score based on WHICH headers are missing, not how many
 *
 * weights mirror the Mozilla Observatory penalty model
 *
 *   Observatory: CSP -25, HSTS -20, X-Frame-Options -20
 *                Referrer-Policy missing scores 0 and PASSES
 *                CORS not implemented scores 0 and PASSES
 *
 * the worst single URL drives the grade rather than the sum across all URLs
 * otherwise a Deep Scan over 300 pages hits CRITICAL purely on volume
 */
public class ScoreCalculator {

    public enum Score { PASS, LOW, MEDIUM, HIGH, CRITICAL }

    private static final Map<String, Double> WEIGHTS = Map.ofEntries(
            Map.entry("content-security-policy",           25.0),
            Map.entry("strict-transport-security",         20.0),
            Map.entry("x-frame-options",                   20.0),
            Map.entry("cache-control",                     12.0),
            Map.entry("x-content-type-options",             8.0),
            Map.entry("cross-origin-opener-policy",         6.0),
            Map.entry("cross-origin-resource-policy",       6.0),
            Map.entry("clear-site-data",                    5.0),
            Map.entry("referrer-policy",                    4.0),
            Map.entry("permissions-policy",                 3.0),
            Map.entry("cross-origin-embedder-policy",       2.0),
            Map.entry("x-permitted-cross-domain-policies",  1.0),
            Map.entry("x-dns-prefetch-control",             1.0)
    );

    // a header that is present but wrong is not as bad as one that is absent
    // except for unsafe-inline in a CSP, which is handled by the keyword bonus below
    private static final double MISCONFIG_FACTOR = 0.6;

    // findings on logout and payment endpoints carry more weight
    private static final double SENSITIVE_MULTIPLIER = 1.4;

    // phrases that indicate the misconfiguration fully defeats the header
    private static final String[] SEVERE = {
            "unsafe-inline", "unsafe-eval", "max-age=0",
            "account takeover", "any origin can read",
            "httponly", "reject this combination"
    };

    public static Score calculate(List<ScanResult> results) {
        if (results == null || results.isEmpty()) return Score.PASS;

        double worst = 0.0;
        for (ScanResult r : results) worst = Math.max(worst, scoreOne(r));

        return toScore(worst);
    }

    // 0 to 100 for a single URL
    private static double scoreOne(ScanResult result) {
        double penalty = 0.0;

        for (String header : result.getMissingHeaders())
            penalty += WEIGHTS.getOrDefault(header.toLowerCase(), 3.0);

        for (String issue : result.getMisconfiguredHeaders()) {
            double w = WEIGHTS.getOrDefault(headerNameOf(issue), 3.0) * MISCONFIG_FACTOR;
            if (isSevere(issue)) w *= 2.0;
            penalty += w;
        }

        UrlClassifier.UrlType t = result.getUrlType();
        if (t == UrlClassifier.UrlType.LOGOUT || t == UrlClassifier.UrlType.PAYMENT
                || t == UrlClassifier.UrlType.LOGIN)
            penalty *= SENSITIVE_MULTIPLIER;

        return Math.min(penalty, 100.0);
    }

    private static Score toScore(double penalty) {
        if (penalty < 5)  return Score.PASS;
        if (penalty < 20) return Score.LOW;
        if (penalty < 45) return Score.MEDIUM;
        if (penalty < 70) return Score.HIGH;
        return Score.CRITICAL;
    }

    private static boolean isSevere(String issue) {
        String lower = issue.toLowerCase();
        for (String s : SEVERE) if (lower.contains(s)) return true;
        return false;
    }

    // misconfigured entries look like "Header-Name: description"
    private static String headerNameOf(String issue) {
        int c = issue.indexOf(':');
        return c == -1 ? issue.toLowerCase() : issue.substring(0, c).trim().toLowerCase();
    }

    public static String getLabel(Score s) {
        return switch (s) {
            case PASS     -> "PASS";
            case LOW      -> "LOW";
            case MEDIUM   -> "MEDIUM";
            case HIGH     -> "HIGH";
            case CRITICAL -> "CRITICAL";
        };
    }

    public static Color getColor(Score s) {
        return switch (s) {
            case PASS     -> new Color(0, 150, 0);
            case LOW      -> new Color(120, 160, 0);
            case MEDIUM   -> new Color(200, 150, 0);
            case HIGH     -> new Color(200, 100, 0);
            case CRITICAL -> new Color(200, 0, 0);
        };
    }
}