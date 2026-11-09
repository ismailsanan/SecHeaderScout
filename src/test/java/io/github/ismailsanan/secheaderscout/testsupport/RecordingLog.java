package io.github.ismailsanan.secheaderscout.testsupport;

import io.github.ismailsanan.secheaderscout.util.Log;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** Thread-safe {@link Log} that records messages for assertions. */
public final class RecordingLog implements Log {
    public final List<String> infos = new CopyOnWriteArrayList<>();
    public final List<String> warnings = new CopyOnWriteArrayList<>();
    public final List<String> errors = new CopyOnWriteArrayList<>();
    public final List<Throwable> causes = new CopyOnWriteArrayList<>();

    @Override
    public void info(String message) {
        infos.add(message);
    }

    @Override
    public void warn(String message) {
        warnings.add(message);
    }

    @Override
    public void error(String message, Throwable cause) {
        errors.add(message);
        causes.add(cause);
    }
}
