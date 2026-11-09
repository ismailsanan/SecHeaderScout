package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.testsupport.RecordingLog;
import io.github.ismailsanan.secheaderscout.util.BackgroundTasks;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** CC-4, CC-5, CC-7: OperationRunner edge cases (queued cancel, unexpected errors, interruption, unload). */
class OperationRunnerLifecycleTest {

    private final RecordingLog log = new RecordingLog();
    private final CountDownLatch release = new CountDownLatch(1);
    private BackgroundTasks tasks;

    @AfterEach
    void tearDown() {
        release.countDown();
        if (tasks != null) {
            tasks.shutdown(5, TimeUnit.SECONDS);
        }
    }

    private static final class Events implements OperationRunner.Listener {
        final List<String> events = new CopyOnWriteArrayList<>();
        final AtomicBoolean offEdt = new AtomicBoolean();
        volatile CountDownLatch idle = new CountDownLatch(1);

        @Override
        public void busyChanged(boolean busy, String operation) {
            offEdt.compareAndSet(false, !SwingUtilities.isEventDispatchThread());
            events.add(busy ? "busy:" + operation : "idle:" + operation);
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

    private static <T> T onEdt(Callable<T> c) throws Exception {
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

    private static void flushEdt() throws Exception {
        SwingUtilities.invokeAndWait(() -> { });
    }

    @Test
    void cancellingAQueuedOperationFreesTheRunnerImmediatelyAndItNeverRuns() throws Exception {
        tasks = new BackgroundTasks("SHS-op", 1, log);
        CountDownLatch blocking = new CountDownLatch(1);
        tasks.submit("other work", () -> {
            blocking.countDown();
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
        assertTrue(blocking.await(5, TimeUnit.SECONDS));

        Events events = new Events();
        OperationRunner runner = onEdt(() -> new OperationRunner(tasks, log, events));
        AtomicBoolean ran = new AtomicBoolean();
        assertTrue(onEdt(() -> runner.start("Deep Scan", () -> {
            ran.set(true);
            return 1;
        }, v -> { })));
        assertTrue(onEdt(runner::isBusy));

        onEdt(() -> {
            runner.cancel();
            return null;
        });
        assertFalse(onEdt(runner::isBusy), "queued operation cancelled: runner must be free at once");
        assertTrue(events.events.contains("Deep Scan cancelled."), events.events.toString());

        release.countDown();
        // a new operation can start and completes normally
        events.idle = new CountDownLatch(1);
        AtomicReference<Integer> delivered = new AtomicReference<>();
        assertTrue(onEdt(() -> runner.start("Quick Scan", () -> 7, delivered::set)));
        assertTrue(events.idle.await(5, TimeUnit.SECONDS));
        flushEdt();
        assertEquals(7, delivered.get());
        assertFalse(ran.get(), "cancelled queued work must never run");
        assertFalse(events.offEdt.get());
    }

    @Test
    void unexpectedExceptionIsLoggedWithStackTraceAndShownInUi() throws Exception {
        tasks = new BackgroundTasks("SHS-op", 1, log);
        Events events = new Events();
        OperationRunner runner = onEdt(() -> new OperationRunner(tasks, log, events));
        AtomicBoolean successCalled = new AtomicBoolean();
        onEdt(() -> runner.start("Export", () -> {
            throw new NullPointerException("bug");
        }, v -> successCalled.set(true)));
        assertTrue(events.idle.await(5, TimeUnit.SECONDS));
        flushEdt();
        assertEquals(1, log.errors.size());
        assertTrue(log.causes.get(0) instanceof NullPointerException);
        assertTrue(events.events.contains("Export failed unexpectedly (NullPointerException); see the extension error log."),
                events.events.toString());
        assertFalse(successCalled.get());
        assertFalse(onEdt(runner::isBusy));
    }

    @Test
    void interruptedExceptionFromWorkIsReportedAsCancellationNotError() throws Exception {
        tasks = new BackgroundTasks("SHS-op", 1, log);
        Events events = new Events();
        OperationRunner runner = onEdt(() -> new OperationRunner(tasks, log, events));
        onEdt(() -> runner.start("Refresh", () -> {
            throw new InterruptedException();
        }, v -> { }));
        assertTrue(events.idle.await(5, TimeUnit.SECONDS));
        flushEdt();
        assertTrue(events.events.contains("Refresh cancelled."), events.events.toString());
        assertTrue(log.errors.isEmpty());
        assertTrue(log.warnings.isEmpty());
    }

    @Test
    void startAfterShutdownIsRejectedAndLeavesTheRunnerIdle() throws Exception {
        tasks = new BackgroundTasks("SHS-op", 1, log);
        assertTrue(tasks.shutdown(5, TimeUnit.SECONDS));
        Events events = new Events();
        OperationRunner runner = onEdt(() -> new OperationRunner(tasks, log, events));
        assertFalse(onEdt(() -> runner.start("Quick Scan", () -> 1, v -> { })));
        assertFalse(onEdt(runner::isBusy));
        assertEquals(List.of("busy:Quick Scan", "idle:Quick Scan",
                "Cannot start \"Quick Scan\": the extension is unloading."), events.events);
    }

    @Test
    void cancelWhenIdleIsANoOp() throws Exception {
        tasks = new BackgroundTasks("SHS-op", 1, log);
        Events events = new Events();
        OperationRunner runner = onEdt(() -> new OperationRunner(tasks, log, events));
        onEdt(() -> {
            runner.cancel();
            return null;
        });
        assertTrue(events.events.isEmpty());
    }

    @Test
    void rejectedDuplicateStartExplainsWhichOperationIsRunning() throws Exception {
        tasks = new BackgroundTasks("SHS-op", 2, log);
        Events events = new Events();
        OperationRunner runner = onEdt(() -> new OperationRunner(tasks, log, events));
        CountDownLatch running = new CountDownLatch(1);
        onEdt(() -> runner.start("Deep Scan", () -> {
            running.countDown();
            release.await();
            return 0;
        }, v -> { }));
        assertTrue(running.await(5, TimeUnit.SECONDS));
        assertFalse(onEdt(() -> runner.start("Export", () -> 1, v -> { })));
        assertTrue(events.events.contains("\"Deep Scan\" is still running; cancel it or wait for it to finish."),
                events.events.toString());
        release.countDown();
        assertTrue(events.idle.await(5, TimeUnit.SECONDS));
        flushEdt();
        assertFalse(onEdt(runner::isBusy));
    }
}
