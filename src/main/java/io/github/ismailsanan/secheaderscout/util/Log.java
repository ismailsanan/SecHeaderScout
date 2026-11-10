package io.github.ismailsanan.secheaderscout.util;

/**
 * Minimal logging facade so Burp-independent code can log without depending
 * on the Montoya API. The extension supplies an adapter backed by Burp's
 * {@code Logging}.
 */
public interface Log {

    void info(String message);

    /** Expected operational problem (network failure, invalid input): message only. */
    void warn(String message);

    /** Unexpected problem: logged with its stack trace. */
    void error(String message, Throwable cause);

    /**
     * Removes the query string and fragment from a URL before logging, because they
     * often carry tokens (password-reset links, session IDs).
     */
    static String redact(String url) {
        if (url == null) {
            return "null";
        }
        String base = UrlPaths.withoutQuery(url);
        return base.length() < url.length() ? base + "?[redacted]" : url;
    }

    /** URLs carrying a query string or fragment inside free text (e.g. exception messages). */
    java.util.regex.Pattern URL_WITH_QUERY = java.util.regex.Pattern.compile("https?://[^\\s?#]*[?#]\\S*");

    /** Redacts every URL query string or fragment that appears inside free text. */
    static String redactText(String text) {
        if (text == null || text.indexOf("://") < 0) {
            return text;
        }
        return URL_WITH_QUERY.matcher(text).replaceAll(m -> java.util.regex.Matcher.quoteReplacement(redact(m.group())));
    }

    /** A logger that discards everything. */
    static Log noop() {
        return new Log() {
            @Override
            public void info(String message) {
            }

            @Override
            public void warn(String message) {
            }

            @Override
            public void error(String message, Throwable cause) {
            }
        };
    }
}
