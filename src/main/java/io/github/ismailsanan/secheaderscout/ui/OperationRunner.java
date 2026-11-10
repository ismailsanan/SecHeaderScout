package io.github.ismailsanan.secheaderscout.ui;

import io.github.ismailsanan.secheaderscout.util.BackgroundTasks;
import io.github.ismailsanan.secheaderscout.util.Log;

import javax.swing.SwingUtilities;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Runs one long-running UI operation at a time on {@link BackgroundTasks}.
 *
 * <p>Threading contract: {@link #start}, {@link #cancel} and {@link #isBusy} are
 * called on the EDT only, so the busy state needs no locking. Work runs on a
 * worker thread; success, failure and completion callbacks run on the EDT.</p>
 */
final class OperationRunner {

    /** UI hooks, invoked on the EDT. */
    interface Listener {
        void busyChanged(boolean busy, String operation);

        void status(String message);
    }

    private final BackgroundTasks tasks;
    private final Log log;
    private final Listener listener;
    /** The running operation: name, its future, and whether its body has begun. EDT-confined. */
    private record Op(String name, Future<?> future, AtomicBoolean started) {
    }

    private Op current;

    OperationRunner(BackgroundTasks tasks, Log log, Listener listener) {
        this.tasks = tasks;
        this.log = log;
        this.listener = listener;
    }

    boolean isBusy() {
        return current != null;
    }

    /**
     * Starts {@code work} unless another operation is running.
     *
     * @return {@code false} if rejected because an operation is already running or the extension is unloading
     */
    <T> boolean start(String name, Callable<T> work, Consumer<T> onSuccess) {
        if (current != null) {
            listener.status("\"" + current.name() + "\" is still running; cancel it or wait for it to finish.");
            return false;
        }
        listener.busyChanged(true, name);
        AtomicBoolean started = new AtomicBoolean();
        AtomicReference<Future<?>> self = new AtomicReference<>();
        try {
            Future<?> future = tasks.submit(name, () -> {
                started.set(true);
                execute(name, work, onSuccess, self);
            });
            self.set(future);
            current = new Op(name, future, started);
        } catch (RejectedExecutionException e) {
            listener.busyChanged(false, name);
            listener.status("Cannot start \"" + name + "\": the extension is unloading.");
            return false;
        }
        return true;
    }

    private <T> void execute(String name, Callable<T> work, Consumer<T> onSuccess,
                             AtomicReference<Future<?>> self) {
        Runnable outcome = () -> { };
        try {
            // cancel() can land after FutureTask.run() began but before this body: the interrupt is
            // already set, so do not start the work at all
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException();
            }
            T result = work.call();
            outcome = () -> deliver(name, result, onSuccess, self.get());
        } catch (InterruptedException | CancellationException e) {
            Thread.currentThread().interrupt();
            outcome = () -> listener.status(name + " cancelled.");
        } catch (OperationException e) {
            // expected operational problem (bad file, network failure): no stack trace needed
            log.warn(name + " failed: " + e.getMessage());
            String message = e.getMessage();
            outcome = () -> listener.status(name + " failed: " + message);
        } catch (Exception e) {
            log.error(name + " failed unexpectedly", e);
            outcome = unexpected(name, e);
        } catch (Error e) {
            // BackgroundTasks logs the Error with its stack trace; make sure the user is told too
            outcome = unexpected(name, e);
            throw e;
        } finally {
            // one EDT task per outcome: report it, THEN clear the busy state. Anything the outcome
            // defers with invokeLater (e.g. "Load report" -> "Rescan & Compare") therefore finds this
            // operation finished instead of being rejected as "still running".
            Runnable report = outcome;
            SwingUtilities.invokeLater(() -> {
                report.run();
                finished(self.get());
            });
        }
    }

    private Runnable unexpected(String name, Throwable t) {
        String type = t.getClass().getSimpleName();
        return () -> listener.status(name + " failed unexpectedly (" + type + "); see the extension error log.");
    }

    private boolean isCurrent(Future<?> operation) {
        return current != null && operation != null && current.future() == operation;
    }

    /**
     * Applies a result on the EDT, but only while {@code operation} is still the current one:
     * an operation that was cancelled (and possibly superseded by a new one) must not overwrite
     * newer results. Partial results of an operation cancelled while running are still
     * delivered, because it stays current until its completion callback runs.
     */
    private <T> void deliver(String name, T result, Consumer<T> onSuccess, Future<?> operation) {
        if (!isCurrent(operation)) {
            log.info(name + ": result discarded because the operation was cancelled.");
            return;
        }
        try {
            onSuccess.accept(result);
        } catch (RuntimeException e) {
            log.error(name + ": applying the result failed", e);
            listener.status(name + " finished, but displaying the result failed ("
                    + e.getClass().getSimpleName() + "); see the extension error log.");
        }
    }

    /** Clears the busy state if {@code operation} is still the current one (idempotent). EDT only. */
    private void finished(Future<?> operation) {
        if (!isCurrent(operation)) {
            return;
        }
        String name = current.name();
        current = null;
        listener.busyChanged(false, name);
    }

    /** Requests cancellation of the running operation (interrupts its thread). */
    void cancel() {
        if (current == null) {
            return;
        }
        Op op = current;
        boolean cancelled = op.future().cancel(true);
        listener.status("Cancelling " + op.name() + "...");
        if (cancelled && !op.started().get()) {
            // cancelled while still queued: the body never runs, so its completion callback never fires
            listener.status(op.name() + " cancelled.");
            finished(op.future());
        }
    }

    /** An expected, user-facing failure with a message safe to display. */
    static final class OperationException extends Exception {
        private static final long serialVersionUID = 1L;

        OperationException(String message) {
            super(message);
        }

        OperationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
