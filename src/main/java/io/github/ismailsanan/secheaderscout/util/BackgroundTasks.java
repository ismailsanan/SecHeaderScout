package io.github.ismailsanan.secheaderscout.util;

import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The extension's single owner of background threads. Replaces ad-hoc
 * {@code new Thread(...).start()} calls.
 *
 * <ul>
 *     <li>Threads are named ({@code <prefix>-N}) and are daemon threads, so they never keep the JVM alive.</li>
 *     <li>Submitted tasks are tracked until they finish, so {@link #cancelAll()} can interrupt them.</li>
 *     <li>Uncaught exceptions are logged with their stack trace instead of disappearing silently.</li>
 *     <li>{@link #shutdown} is called from the extension unloading handler.</li>
 * </ul>
 */
public final class BackgroundTasks {

    private final ExecutorService executor;
    private final Set<Future<?>> running = ConcurrentHashMap.newKeySet();
    private final Log log;

    public BackgroundTasks(String threadNamePrefix, int threads, Log log) {
        this.log = Objects.requireNonNull(log);
        AtomicInteger counter = new AtomicInteger();
        ThreadFactory factory = runnable -> {
            Thread t = new Thread(runnable, threadNamePrefix + "-" + counter.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
        this.executor = Executors.newFixedThreadPool(threads, factory);
    }

    /**
     * Submits {@code task}. Unexpected exceptions are logged; interruption is
     * treated as cancellation.
     *
     * @throws java.util.concurrent.RejectedExecutionException after {@link #shutdown}
     */
    public Future<?> submit(String name, Runnable task) {
        Objects.requireNonNull(task);
        FutureTask<Void> future = new FutureTask<>(() -> {
            try {
                task.run();
            } catch (RuntimeException | Error e) {
                if (!Thread.currentThread().isInterrupted()) {
                    log.error("Background task '" + name + "' failed", e);
                }
                throw e;
            }
        }, null) {
            @Override
            protected void done() {
                // runs on completion, failure AND cancellation (including cancel-before-start),
                // so cancelled queued tasks are never tracked forever
                running.remove(this);
            }
        };
        running.add(future);
        try {
            executor.execute(future);
        } catch (RuntimeException e) {
            running.remove(future);
            throw e;
        }
        return future;
    }

    /** Interrupts every running or queued task. */
    public void cancelAll() {
        for (Future<?> f : running) {
            f.cancel(true);
        }
        running.clear();
    }

    public int activeCount() {
        return running.size();
    }

    /**
     * Cancels everything, stops the executor and waits up to {@code timeout}
     * for worker threads to exit.
     *
     * @return {@code true} if all threads terminated in time
     */
    public boolean shutdown(long timeout, TimeUnit unit) {
        cancelAll();
        executor.shutdownNow();
        try {
            boolean terminated = executor.awaitTermination(timeout, unit);
            if (!terminated) {
                log.warn("Background threads did not stop within " + unit.toMillis(timeout)
                        + " ms (a request may still be blocked on the network); they are daemon threads and "
                        + "will not keep Burp alive.");
            }
            return terminated;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    public boolean isShutdown() {
        return executor.isShutdown();
    }
}
