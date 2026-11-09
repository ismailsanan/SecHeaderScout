package io.github.ismailsanan.secheaderscout.testsupport;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** Thread-lifecycle assertions for executor tests. */
public final class Threads {

    private Threads() {
    }

    /**
     * Asserts that no live thread whose name starts with {@code prefix} remains.
     *
     * <p>{@code ThreadPoolExecutor.awaitTermination} returns once the pool is
     * TERMINATED, and the last worker reaches that state from its own exit path,
     * a moment before the thread actually dies. Checking {@code isAlive()} right
     * after shutdown is therefore racy (roughly one failure in twenty runs). This
     * helper joins each matching thread with a bound first, so it still fails
     * when a worker really survives.</p>
     */
    public static void assertNoLiveThreads(String prefix) throws InterruptedException {
        List<Thread> matching = Thread.getAllStackTraces().keySet().stream()
                .filter(t -> t.getName().startsWith(prefix))
                .toList();
        for (Thread t : matching) {
            t.join(5_000);
        }
        List<String> alive = matching.stream().filter(Thread::isAlive).map(Thread::getName).toList();
        assertTrue(alive.isEmpty(), "threads still alive after shutdown: " + alive);
    }
}
