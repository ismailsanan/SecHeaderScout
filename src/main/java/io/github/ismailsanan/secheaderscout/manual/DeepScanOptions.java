package io.github.ismailsanan.secheaderscout.manual;

/**
 * Noise filters applied to captured responses BEFORE analysis, so skipped
 * responses cost nothing.
 *
 * @param includeStatic       analyse images, scripts, stylesheets, fonts and media
 * @param includeErrors       analyse 4xx/5xx responses (error pages)
 * @param includeRedirects    analyse 3xx responses
 * @param mergeQueryVariants  analyse each method + URL path once, ignoring query-string variants
 */
public record DeepScanOptions(boolean includeStatic, boolean includeErrors, boolean includeRedirects,
                              boolean mergeQueryVariants) {

    /** Defaults for the UI: pages and API responses that matter, once per endpoint. */
    public static final DeepScanOptions DEFAULT = new DeepScanOptions(false, false, false, true);

    /** Everything that was captured, nothing merged (the pre-2.0 behaviour). */
    public static final DeepScanOptions EVERYTHING = new DeepScanOptions(true, true, true, false);
}
