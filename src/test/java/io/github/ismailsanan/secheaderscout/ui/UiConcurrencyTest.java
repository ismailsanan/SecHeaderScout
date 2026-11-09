package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.model.ScanResult;
import io.github.ismailsanan.secheaderscout.testsupport.RecordingLog;
import io.github.ismailsanan.secheaderscout.util.BackgroundTasks;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static io.github.ismailsanan.secheaderscout.model.Results.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UiConcurrencyTest {

    @Test
    void resultsStoreSupportsConcurrentWritersAndReaders() throws Exception {
        ResultsStore store = new ResultsStore();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int w = 0; w < 4; w++) {
                int n = w;
                futures.add(pool.submit(() -> {
                    for (int i = 0; i < 500; i++) {
                        List<ScanResult> batch = new ArrayList<>();
                        for (int j = 0; j <= n; j++) {
                            batch.add(result("https://e.example/" + j, List.of(missing("X")), Set.of()));
                        }
                        store.replace(batch);
                    }
                }));
            }
            for (int r = 0; r < 4; r++) {
                futures.add(pool.submit(() -> {
                    for (int i = 0; i < 2_000; i++) {
                        List<ScanResult> snap = store.snapshot();
                        int count = 0;
                        for (ScanResult s : snap) { // would throw CME on a shared mutable list
                            count += s.findings().size();
                        }
                        if (count != snap.size()) {
                            throw new AssertionError("torn snapshot");
                        }
                        (snap.isEmpty() ? result("https://x/", List.of(), Set.of()) : snap.get(0)).missing();
                    }
                }));
            }
            for (Future<?> f : futures) {
                f.get(30, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    /** Records listener calls; asserts they happen on the EDT. */
    private static final class Events implements OperationRunner.Listener {
        final List<String> events = new CopyOnWriteArrayList<>();
        final AtomicBoolean offEdt = new AtomicBoolean();
        final CountDownLatch idle = new CountDownLatch(1);

        @Override
        public void busyChanged(boolean busy, String operation) {
            offEdt.compareAndSet(false, !SwingUtilities.isEventDispatchThread());
            events.add(busy ? "busy" : "idle");
            if (!busy) {
                idle.countDown();
            }
        }

        @Override
        public void status(String message) {
            offEdt.compareAndSet(false, !SwingUtilities.isEventDispatchThread());
            events.add(message);
        }
    }

    private static <T> T onEdt(java.util.concurrent.Callable<T> c) throws Exception {
        AtomicReference<T> ref = new AtomicReference<>();
        AtomicReference<Exception> err = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                ref.set(c.call());
            } catch (Exception e) {
                err.set(e);
            }
        });
        if (err.get() != null) {
            throw err.get();
        }
        return ref.get();
    }

    @Test
    void runnerAllowsOneOperationAtATimeAndSupportsCancellation() throws Exception {
        BackgroundTasks tasks = new BackgroundTasks("SHS-ui", 2, new RecordingLog());
        Events events = new Events();
        OperationRunner runner = onEdt(() -> new OperationRunner(tasks, new RecordingLog(), events));
        CountDownLatch running = new CountDownLatch(1);
        AtomicReference<String> delivered = new AtomicReference<>();

        assertTrue(onEdt(() -> runner.start("Refresh", () -> {
            running.countDown();
            Thread.sleep(60_000);
            return "never";
        }, delivered::set)));
        assertTrue(running.await(5, TimeUnit.SECONDS));
        assertFalse(onEdt(() -> runner.start("Refresh", () -> "second", delivered::set)), "duplicate refresh rejected");

        onEdt(() -> {
            runner.cancel();
            return null;
        });
        assertTrue(events.idle.await(5, TimeUnit.SECONDS));
        SwingUtilities.invokeAndWait(() -> { }); // flush pending EDT events
        assertEquals(null, delivered.get());
        assertFalse(onEdt(runner::isBusy));
        assertTrue(events.events.contains("Refresh cancelled."), events.events.toString());
        assertFalse(events.offEdt.get(), "listener called off the EDT");
        tasks.shutdown(2, TimeUnit.SECONDS);
    }

    @Test
    void runnerReportsFailuresAndDeliversSuccessOnEdt() throws Exception {
        BackgroundTasks tasks = new BackgroundTasks("SHS-ui2", 1, new RecordingLog());
        RecordingLog log = new RecordingLog();
        Events events = new Events();
        OperationRunner runner = onEdt(() -> new OperationRunner(tasks, log, events));
        onEdt(() -> runner.start("Export", () -> {
            throw new OperationRunner.OperationException("disk full");
        }, x -> { }));
        assertTrue(events.idle.await(5, TimeUnit.SECONDS));
        SwingUtilities.invokeAndWait(() -> { });
        assertTrue(events.events.contains("Export failed: disk full"), events.events.toString());
        assertTrue(log.errors.isEmpty(), "expected operational error is not logged as a bug");

        Events second = new Events();
        OperationRunner runner2 = onEdt(() -> new OperationRunner(tasks, log, second));
        AtomicBoolean successOnEdt = new AtomicBoolean();
        onEdt(() -> runner2.start("Scan", () -> 42, v -> successOnEdt.set(SwingUtilities.isEventDispatchThread() && v == 42)));
        assertTrue(second.idle.await(5, TimeUnit.SECONDS));
        SwingUtilities.invokeAndWait(() -> { });
        assertTrue(successOnEdt.get());
        tasks.shutdown(2, TimeUnit.SECONDS);
    }
}
