package io.github.ismailsanan.secheaderscout.engine;

/**
 * Classification of URLs by path, used to decide which headers are relevant (e.g.
 * Clear-Site-Data on logout endpoints) and to highlight sensitive endpoints. The patterns
 * are {@link EndpointRules}: built-in keywords ({@code /logout}, {@code /login}, ...) that the
 * user can disable, plus the user's own, which take precedence. Only the path is inspected
 * unless a pattern has a query, so {@code ?next=/logout} does not make a page a logout.
 */
public final class UrlClassifier {

    /** Endpoint types, declared in priority order (most important first): sorting uses this order. */
    public enum UrlType {
        LOGOUT, LOGIN, PAYMENT, ADMIN, API, NORMAL;

        /** Short label for tables and reports; empty for {@link #NORMAL}. */
        public String label() {
            return this == NORMAL ? "" : name();
        }

        /** Name for choosers where an empty label would be confusing. */
        public String displayName() {
            return this == NORMAL ? "NOT SENSITIVE" : name();
        }

        /** Any type other than {@link #NORMAL}; drives the strict Cache-Control check and URL highlighting. */
        public boolean isSensitive() {
            return this != NORMAL;
        }

        /** Logout, login, payment or admin: the endpoints Deep Scan lists first. API is sensitive but not ranked. */
        public boolean isHighValue() {
            return isSensitive() && this != API;
        }
    }

    /**
     * The active endpoint patterns (built-in keywords plus the user's own). Written on the EDT,
     * read by scans and by Burp's passive-scan threads: an immutable snapshot behind a volatile
     * reference, so readers always see a complete, consistent rule set without locking.
     */
    private static volatile EndpointRules rules = EndpointRules.DEFAULT;

    private UrlClassifier() {
    }

    /** Publishes a new rule set; it applies to every classification from now on. */
    public static void setRules(EndpointRules value) {
        rules = value == null ? EndpointRules.DEFAULT : value;
    }

    public static EndpointRules rules() {
        return rules;
    }

    /** The type of the first matching enabled pattern, {@link UrlType#NORMAL} if none matches. */
    public static UrlType classify(String url) {
        return rules.typeOf(url).orElse(UrlType.NORMAL);
    }
}
