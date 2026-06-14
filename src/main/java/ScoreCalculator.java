import java.util.List;

/**
 * Calculates overall security score based on scan results
 */
public class ScoreCalculator {

    public enum Score {
        SECURE,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    public static Score calculate(List<ScanResult> results) {
        if (results.isEmpty()) return Score.SECURE;

        int totalMissing = 0;
        int totalMisconfigured = 0;
        boolean hasCriticalUrl = false;

        for (ScanResult result : results) {
            totalMissing += result.getMissingHeaders().size();
            totalMisconfigured += result.getMisconfiguredHeaders().size();

            // logout/payment pages with missing headers = critical
            UrlClassifier.UrlType type = UrlClassifier.classify(result.getUrl());
            if ((type == UrlClassifier.UrlType.LOGOUT ||
                    type == UrlClassifier.UrlType.PAYMENT) &&
                    !result.getMissingHeaders().isEmpty()) {
                hasCriticalUrl = true;
            }
        }

        if (hasCriticalUrl) return Score.CRITICAL;
        if (totalMissing == 0 && totalMisconfigured == 0) return Score.SECURE;
        if (totalMissing <= 2) return Score.LOW;
        if (totalMissing <= 5) return Score.MEDIUM;
        if (totalMissing <= 8) return Score.HIGH;
        return Score.CRITICAL;
    }

    public static String getLabel(Score score) {
        return switch (score) {
            case SECURE   -> " SECURE";
            case LOW      -> " LOW RISK";
            case MEDIUM   -> " MEDIUM RISK";
            case HIGH     -> " HIGH RISK";
            case CRITICAL -> " CRITICAL";
        };
    }

    public static java.awt.Color getColor(Score score) {
        return switch (score) {
            case SECURE   -> new java.awt.Color(0, 150, 0);
            case LOW      -> new java.awt.Color(200, 150, 0);
            case MEDIUM   -> new java.awt.Color(200, 100, 0);
            case HIGH     -> new java.awt.Color(200, 0, 0);
            case CRITICAL -> new java.awt.Color(150, 0, 0);
        };
    }
}