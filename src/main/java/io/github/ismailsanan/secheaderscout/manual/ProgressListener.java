package io.github.ismailsanan.secheaderscout.manual;

/** Receives progress updates from a running scan. Called on the worker thread. */
@FunctionalInterface
public interface ProgressListener {

    void onProgress(int done, int total, String current);

    static ProgressListener none() {
        return (done, total, current) -> {
        };
    }
}
