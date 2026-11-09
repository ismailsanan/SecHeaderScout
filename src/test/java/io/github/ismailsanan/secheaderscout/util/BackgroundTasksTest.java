package io.github.ismailsanan.secheaderscout.util;

import io.github.ismailsanan.secheaderscout.testsupport.RecordingLog;
import io.github.ismailsanan.secheaderscout.testsupport.Threads;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BackgroundTasksTest {

    private final RecordingLog log = new RecordingLog();

    @Test
    void threadsAreNamedDaemonThreads() throws Exception {
        BackgroundTasks tasks = new BackgroundTasks("SHS-test", 1, log);
        AtomicReference<Thread> thread = new AtomicReference<>();
        tasks.submit("t", () -> thread.set(Thread.currentThread())).get(5, TimeUnit.SECONDS);
        assertTrue(thread.get().getName().startsWith("SHS-test-"));
        assertTrue(thread.get().isDaemon());
        tasks.shutdown(1, TimeUnit.SECONDS);
    }

    @Test
    void uncaughtExceptionsAreLoggedWithStackTrace() throws Exception {
        BackgroundTasks tasks = new BackgroundTasks("SHS-test", 1, log);
        var future = tasks.submit("explode", () -> {
            throw new IllegalStateException("boom");
        });
        // wait for completion first: shutdown() would cancel a task that has not started yet
        java.util.concurrent.ExecutionException thrown =
                assertThrows(java.util.concurrent.ExecutionException.class, () -> future.get(5, TimeUnit.SECONDS));
        assertTrue(thrown.getCause() instanceof IllegalStateException);
        tasks.shutdown(5, TimeUnit.SECONDS);
        assertEquals(1, log.errors.size());
        assertTrue(log.errors.get(0).contains("explode"));
        assertTrue(log.causes.get(0) instanceof IllegalStateException);
    }

    @Test
    void cancelAllInterruptsRunningTasks() throws Exception {
        BackgroundTasks tasks = new BackgroundTasks("SHS-test", 2, log);
        CountDownLatch started = new CountDownLatch(1);
        AtomicBoolean interrupted = new AtomicBoolean();
        CountDownLatch done = new CountDownLatch(1);
        tasks.submit("sleeper", () -> {
            started.countDown();
            try {
                Thread.sleep(60_000);
            } catch (InterruptedException e) {
                interrupted.set(true);
            } finally {
                done.countDown();
            }
        });
        assertTrue(started.await(5, TimeUnit.SECONDS));
        assertEquals(1, tasks.activeCount());
        tasks.cancelAll();
        assertTrue(done.await(5, TimeUnit.SECONDS));
        assertTrue(interrupted.get());
        tasks.shutdown(1, TimeUnit.SECONDS);
    }

    @Test
    void shutdownStopsAllThreadsAndRejectsNewWork() throws Exception {
        BackgroundTasks tasks = new BackgroundTasks("SHS-shutdown", 2, log);
        CountDownLatch started = new CountDownLatch(2);
        for (int i = 0; i < 2; i++) {
            tasks.submit("busy" + i, () -> {
                started.countDown();
                while (!Thread.currentThread().isInterrupted()) {
                    Thread.onSpinWait();
                }
            });
        }
        assertTrue(started.await(5, TimeUnit.SECONDS));
        assertTrue(tasks.shutdown(5, TimeUnit.SECONDS));
        assertTrue(tasks.isShutdown());
        Threads.assertNoLiveThreads("SHS-shutdown");
        assertThrows(RejectedExecutionException.class, () -> tasks.submit("late", () -> {
        }));
        assertTrue(log.errors.isEmpty(), "interruption is cancellation, not an error");
    }
}
