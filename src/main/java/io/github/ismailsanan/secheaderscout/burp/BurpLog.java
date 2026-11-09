package io.github.ismailsanan.secheaderscout.burp;

import burp.api.montoya.logging.Logging;
import io.github.ismailsanan.secheaderscout.util.Log;

/**
 * {@link Log} backed by Burp's extension output and error streams.
 *
 * <p>This is the single place that writes to Burp's logs, so it also redacts: URL query
 * strings and fragments (which often carry tokens) are removed from every message and
 * from the messages of logged exceptions and their causes. Call sites cannot forget it.</p>
 */
public final class BurpLog implements Log {

    private final Logging logging;

    public BurpLog(Logging logging) {
        this.logging = logging;
    }

    @Override
    public void info(String message) {
        logging.logToOutput(Log.redactText(message));
    }

    @Override
    public void warn(String message) {
        logging.logToOutput("[WARN] " + Log.redactText(message));
    }

    @Override
    public void error(String message, Throwable cause) {
        logging.logToError("[ERROR] " + Log.redactText(message), redacted(cause));
    }

    /**
     * Returns {@code t} unchanged unless a message in its cause chain contains a URL with a
     * query or fragment; then returns a copy with redacted messages and the same stack traces.
     */
    static Throwable redacted(Throwable t) {
        if (t == null || !needsRedaction(t)) {
            return t;
        }
        Throwable copy = new Throwable(t.getClass().getName() + ": " + Log.redactText(t.getMessage()),
                redacted(t.getCause()));
        copy.setStackTrace(t.getStackTrace());
        return copy;
    }

    private static boolean needsRedaction(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            String m = c.getMessage();
            if (m != null && !m.equals(Log.redactText(m))) {
                return true;
            }
            if (c.getCause() == c) {
                break;
            }
        }
        return false;
    }
}
