package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;

import java.util.List;

/** Read-only access to responses already captured by Burp. Never sends requests. */
public interface SiteMapSource {

    /** Receives captured responses one at a time. */
    @FunctionalInterface
    interface ResponseVisitor {
        /**
         * @param index position among the host's site map entries (for progress)
         * @param total number of site map entries for the host
         * @return {@code false} to stop early (e.g. the scan was cancelled)
         */
        boolean visit(int index, int total, ResponseSnapshot snapshot);
    }

    /** Distinct host names present in the site map, in first-seen order. */
    List<String> hosts();

    /** Captured responses whose request targeted {@code host} (case-insensitive). */
    List<ResponseSnapshot> responsesFor(String host);

    /**
     * Streams the captured responses for {@code host}, so a caller that analyses and drops each
     * one never holds them all at once. The default reads {@link #responsesFor}.
     */
    default void forEachResponse(String host, ResponseVisitor visitor) {
        List<ResponseSnapshot> all = responsesFor(host);
        for (int i = 0; i < all.size(); i++) {
            if (!visitor.visit(i, all.size(), all.get(i))) {
                return;
            }
        }
    }
}
