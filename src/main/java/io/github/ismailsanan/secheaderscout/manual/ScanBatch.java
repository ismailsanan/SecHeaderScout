package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.model.ScanResult;

import java.util.List;

/**
 * Results of one manual scan operation.
 *
 * @param results   results gathered (partial if cancelled)
 * @param cancelled whether the operation stopped early because it was cancelled
 */
public record ScanBatch(List<ScanResult> results, boolean cancelled) {
    public ScanBatch {
        results = List.copyOf(results);
    }
}
