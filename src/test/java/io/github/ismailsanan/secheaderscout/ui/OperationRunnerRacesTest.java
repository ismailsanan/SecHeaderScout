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
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CC-4 / CC-7: result delivery, chained operations and error reporting in OperationRunner.
 */
class OperationRunnerRacesTest {

    private final RecordingLog log = new RecordingLog();
    private BackgroundTasks tasks;

    @AfterEach
    void tearDown() {
        if (tasks != null) {
            tasks.shutdown(5, TimeUnit.SECONDS);
        }
    }

    private static final class Events implements OperationRunner.Listener {
        final List<String> events = new CopyOnWriteArrayList<>();

        @Override
        public void busyChanged(boolean busy, String operation) {
            events.add(busy ? "busy:" + operation : "idle:" + operation);
        }

        @Override
        public void status(String message) {
            events.add(message);
        }

        boolean idleAfter(String operation) {
            return events.contains("idle:" + operation);
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

    /** Waits (bounded) until the condition holds, flushing the EDT between checks. */
    private static void await(java.util.function.BooleanSupplier condition) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) {
            SwingUtilities.invokeAndWait(() -> { });
            Thread.onSpinWait();
        }
        assertTrue(condition.getAsBoolean(), "condition not reached in time");
    }

    @Test
    void secondOperationStartedFromOnSuccessViaInvokeLaterIsAccepted() throws Exception {
        // pins the deferral ScanPanel relies on for "Load report" -> "Rescan & Compare"
        tasks = new BackgroundTasks("SHS-chain", 1, log);
        Events events = new Events();
        OperationRunner runner = onEdt(() -> new OperationRunner(tasks, log, events));
        AtomicReference<String> second = new AtomicReference<>();
        AtomicReference<Boolean> directStart = new AtomicReference<>();
        onEdt(() -> runner.start("A", () -> "a", a -> {
            directStart.set(runner.start("direct", () -> "x", x -> { }));
            SwingUtilities.invokeLater(() -> runner.start("B", () -> "b", second::set));
        }));
        await(() -> "b".equals(second.get()));
        assertEquals(Boolean.FALSE, directStart.get(), "starting from onSuccess directly is rejected");
        assertTrue(events.events.stream().anyMatch(e -> e.contains("\"A\" is still running")), events.events.toString());
    }

    @Test
    void cancellingRunningWorkThatReturnsNormallyDeliversThePartialResult() throws Exception {
        tasks = new BackgroundTasks("SHS-partial", 1, log);
        Events events = new Events();
        OperationRunner runner = onEdt(() -> new OperationRunner(tasks, log, events));
        CountDownLatch running = new CountDownLatch(1);
        AtomicReference<String> delivered = new AtomicReference<>();
        onEdt(() -> runner.start("Scan", () -> {
            running.countDown();
            while (!Thread.currentThread().isInterrupted()) {
                Thread.onSpinWait();
            }
            return "partial"; // like ManualScanner returning ScanBatch(cancelled = true)
        }, delivered::set));
        assertTrue(running.await(5, TimeUnit.SECONDS));
        onEdt(() -> {
            runner.cancel();
            return null;
        });
        await(() -> events.idleAfter("Scan"));
        assertEquals("partial", delivered.get(), "partial results of a running operation are still shown");
        assertFalse(events.events.contains("Scan cancelled."), events.events.toString());
        assertFalse(onEdt(runner::isBusy));
    }

    @Test
    void anErrorInTheWorkIsReportedToTheUser() throws Exception {
        tasks = new BackgroundTasks("SHS-error", 1, log);
        Events events = new Events();
        OperationRunner runner = onEdt(() -> new OperationRunner(tasks, log, events));
        onEdt(() -> runner.start("Deep Scan", () -> {
            throw new StackOverflowError("simulated");
        }, x -> { }));
        await(() -> events.idleAfter("Deep Scan"));
        assertTrue(events.events.stream().anyMatch(e -> e.startsWith("Deep Scan failed unexpectedly (StackOverflowError)")),
                events.events.toString());
        await(() -> !log.errors.isEmpty()); // BackgroundTasks logs the Error with its stack trace
    }

    @Test
    void anExceptionWhileApplyingTheResultIsLoggedAndReported() throws Exception {
        tasks = new BackgroundTasks("SHS-apply", 1, log);
        Events events = new Events();
        OperationRunner runner = onEdt(() -> new OperationRunner(tasks, log, events));
        onEdt(() -> runner.start("Export", () -> "x", x -> {
            throw new IllegalStateException("render bug");
        }));
        await(() -> events.idleAfter("Export"));
        assertTrue(events.events.stream().anyMatch(e -> e.startsWith("Export finished, but displaying the result failed")),
                events.events.toString());
        assertTrue(log.errors.stream().anyMatch(e -> e.contains("applying the result failed")), log.errors.toString());
    }
}
