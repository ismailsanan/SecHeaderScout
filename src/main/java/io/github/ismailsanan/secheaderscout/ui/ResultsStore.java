package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.model.ScanResult;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Holds the latest scan results as an immutable snapshot.
 *
 * <p>Writers replace the whole list atomically and readers get an immutable
 * list, so a reader on any thread (EDT rendering, export worker) can never see
 * a half-updated list or hit a {@code ConcurrentModificationException}. This
 * fits the workload, where results are published once per operation and read
 * often, better than {@code CopyOnWriteArrayList}, which would copy the array on
 * every one of thousands of incremental adds during a deep scan.</p>
 */
public final class ResultsStore {

    private final AtomicReference<List<ScanResult>> snapshot = new AtomicReference<>(List.of());

    public List<ScanResult> snapshot() {
        return snapshot.get();
    }

    public void replace(List<ScanResult> results) {
        snapshot.set(List.copyOf(results));
    }

    public void clear() {
        snapshot.set(List.of());
    }

    public boolean isEmpty() {
        return snapshot.get().isEmpty();
    }
}
