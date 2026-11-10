package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.model.HeaderProfile;

import io.github.ismailsanan.secheaderscout.model.ScanResult;

import java.util.List;

/**
 * Outcome of a Deep Scan.
 *
 * @param results   one result per analysed endpoint (after filtering)
 * @param profiles  the results grouped into header profiles, most important first
 * @param stats     how many captured responses each filter skipped
 * @param cancelled whether the scan stopped early
 */
public record DeepScanResult(List<ScanResult> results, List<HeaderProfile> profiles, Stats stats, boolean cancelled) {

    public DeepScanResult {
        results = List.copyOf(results);
        profiles = List.copyOf(profiles);
    }

    /** The per-URL view, for the existing table, report and comparison code. */
    public ScanBatch batch() {
        return new ScanBatch(results, cancelled);
    }

    /**
     * Filter accounting: {@code captured} = {@code analysed} + every skipped count.
     */
    public record Stats(int captured, int analysed, int skippedStatic, int skippedErrors, int skippedRedirects,
                        int mergedQueryVariants, int skippedOther) {

        public String summary() {
            String skipped = skippedSummary();
            return "analysed " + analysed + " of " + captured + " captured responses"
                    + (skipped.isEmpty() ? "" : " (skipped: " + skipped + ")");
        }

        /** What the filters skipped, e.g. "3 static files, 2 error responses"; "" if nothing. */
        public String skippedSummary() {
            List<String> parts = new java.util.ArrayList<>();
            add(parts, skippedStatic, "static files");
            add(parts, skippedErrors, "error responses");
            add(parts, skippedRedirects, "redirects");
            add(parts, mergedQueryVariants, "query-string variants");
            add(parts, skippedOther, "informational responses");
            return String.join(", ", parts);
        }

        private static void add(List<String> parts, int n, String what) {
            if (n > 0) {
                parts.add(n + " " + what);
            }
        }
    }
}
