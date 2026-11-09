package io.github.ismailsanan.secheaderscout.util;

import io.github.ismailsanan.secheaderscout.testsupport.RecordingLog;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** CC-4, CC-5, CC-7: task tracking, cancellation of queued work, bounded shutdown, error logging. */
class BackgroundTasksLifecycleTest {

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

    /** Blocks the single worker until {@link #release} opens; returns once it is running. */
    private void occupyWorker() throws InterruptedException {
        CountDownLatch running = new CountDownLatch(1);
        tasks.submit("blocker", () -> {
            running.countDown();
            awaitUninterruptibly(release);
        });
        assertTrue(running.await(5, TimeUnit.SECONDS));
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        boolean interrupted = false;
        while (true) {
            try {
                latch.await();
                break;
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    @Test
    void completedTasksAreNoLongerTracked() throws Exception {
        tasks = new BackgroundTasks("SHS-life", 2, log);
        tasks.submit("a", () -> { }).get(5, TimeUnit.SECONDS);
        assertThrows(ExecutionException.class, () -> tasks.submit("b", () -> {
            throw new IllegalArgumentException("x");
        }).get(5, TimeUnit.SECONDS));
        awaitActiveCount(0);
    }

    @Test
    void cancelAllPreventsQueuedTasksFromEverRunning() throws Exception {
        tasks = new BackgroundTasks("SHS-life", 1, log);
        occupyWorker();
        AtomicBoolean queuedRan = new AtomicBoolean();
        Future<?> queued = tasks.submit("queued", () -> queuedRan.set(true));
        assertEquals(2, tasks.activeCount());
        tasks.cancelAll();
        assertEquals(0, tasks.activeCount());
        assertTrue(queued.isCancelled());
        release.countDown();
        // a task submitted afterwards runs on the same (single) worker, so the queued one has had its chance
        tasks.submit("after", () -> { }).get(5, TimeUnit.SECONDS);
        assertFalse(queuedRan.get());
        assertThrows(CancellationException.class, queued::get);
    }

    @Test
    void individuallyCancelledQueuedTaskIsNotTrackedForever() throws Exception {
        tasks = new BackgroundTasks("SHS-life", 1, log);
        occupyWorker();
        Future<?> queued = tasks.submit("queued", () -> { });
        assertEquals(2, tasks.activeCount());
        assertTrue(queued.cancel(true));
        // FutureTask.cancel() runs done() synchronously, so the cancelled queued task is
        // untracked as soon as cancel() returns; only the worker-occupying task remains.
        assertEquals(1, tasks.activeCount());
        release.countDown();
        tasks.submit("after", () -> { }).get(5, TimeUnit.SECONDS);
        awaitActiveCount(0);
    }

    /**
     * FutureTask.finishCompletion() wakes threads blocked in get() BEFORE it calls done(),
     * which is where BackgroundTasks untracks the task. A task whose get() has returned may
     * therefore still be tracked for an instant, so wait (bounded) instead of asserting a race.
     */
    private void awaitActiveCount(int expected) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (tasks.activeCount() != expected && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertEquals(expected, tasks.activeCount());
    }

    @Test
    void shutdownIsBoundedWhenATaskIgnoresInterruption() throws Exception {
        tasks = new BackgroundTasks("SHS-stubborn", 1, log);
        occupyWorker(); // ignores interrupts, like a blocking network call
        assertFalse(tasks.shutdown(50, TimeUnit.MILLISECONDS), "must not wait for a stuck task");
        assertTrue(tasks.isShutdown());
        assertTrue(log.warnings.stream().anyMatch(w -> w.contains("did not stop")), log.warnings.toString());
        release.countDown();
        assertTrue(tasks.shutdown(5, TimeUnit.SECONDS), "threads exit once the blocking call returns");
    }

    @Test
    void shutdownWhenIdleTerminatesAndIsIdempotent() {
        tasks = new BackgroundTasks("SHS-idle", 2, log);
        assertTrue(tasks.shutdown(5, TimeUnit.SECONDS));
        assertTrue(tasks.shutdown(5, TimeUnit.SECONDS));
        assertTrue(log.warnings.isEmpty());
    }

    @Test
    void shutdownCalledFromAnInterruptedThreadPreservesTheFlag() {
        tasks = new BackgroundTasks("SHS-intr", 1, log);
        try {
            occupyWorker();
            Thread.currentThread().interrupt();
            assertFalse(tasks.shutdown(5, TimeUnit.SECONDS));
            assertTrue(Thread.currentThread().isInterrupted());
        } catch (InterruptedException e) {
            throw new AssertionError(e);
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void exceptionAfterInterruptionIsTreatedAsCancellationNotLogged() throws Exception {
        tasks = new BackgroundTasks("SHS-life", 1, log);
        Future<?> f = tasks.submit("cancelled-io", () -> {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("java.nio.channels.ClosedByInterruptException");
        });
        assertThrows(ExecutionException.class, () -> f.get(5, TimeUnit.SECONDS));
        assertTrue(log.errors.isEmpty(), log.errors.toString());
    }

    @Test
    void errorsAreLoggedWithTheirCause() throws Exception {
        tasks = new BackgroundTasks("SHS-life", 1, log);
        Future<?> f = tasks.submit("oom", () -> {
            throw new AssertionError("simulated Error");
        });
        assertThrows(ExecutionException.class, () -> f.get(5, TimeUnit.SECONDS));
        assertEquals(1, log.errors.size());
        assertTrue(log.errors.get(0).contains("oom"));
        assertTrue(log.causes.get(0) instanceof AssertionError);
    }

    @Test
    void nullTaskIsRejected() {
        tasks = new BackgroundTasks("SHS-life", 1, log);
        assertThrows(NullPointerException.class, () -> tasks.submit("n", null));
        assertEquals(0, tasks.activeCount());
    }
}
