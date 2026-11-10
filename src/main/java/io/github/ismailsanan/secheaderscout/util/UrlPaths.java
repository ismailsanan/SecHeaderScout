package io.github.ismailsanan.secheaderscout.util;

/**
 * Lenient URL splitting for captured URLs, which {@link java.net.URI} may reject (they often
 * contain {@code {}, {@code |} or spaces). Every method accepts {@code null} and never throws.
 */
public final class UrlPaths {

    private UrlPaths() {
    }

    /** {@code scheme://authority} of {@code url}, or "" if it has none. */
    public static String origin(String url) {
        if (url == null) {
            return "";
        }
        int scheme = url.indexOf("://");
        return scheme < 0 ? "" : url.substring(0, endOf(url, scheme + 3, "/?#"));
    }

    /** The path of {@code url} (never empty; "/" when absent), without query or fragment. */
    public static String path(String url) {
        if (url == null) {
            return "/";
        }
        int start = origin(url).length();
        String path = url.substring(start, endOf(url, start, "?#"));
        return path.isEmpty() ? "/" : path;
    }

    /** The query string of {@code url} (without '?'), or "" if none. A '?' inside the fragment is not a query. */
    public static String query(String url) {
        if (url == null) {
            return "";
        }
        int cut = endOf(url, 0, "?#");
        if (cut >= url.length() || url.charAt(cut) != '?') {
            return "";
        }
        return url.substring(cut + 1, endOf(url, cut + 1, "#"));
    }

    /** {@code url} without its query string and fragment. */
    public static String withoutQuery(String url) {
        return url == null ? "" : url.substring(0, endOf(url, 0, "?#"));
    }

    /** The host of {@code url} (no user info, port or IPv6 brackets), or "" if none. */
    public static String host(String url) {
        if (url == null) {
            return "";
        }
        int scheme = url.indexOf("://");
        int start = scheme < 0 ? 0 : scheme + 3;
        String authority = url.substring(start, endOf(url, start, "/?#"));
        authority = authority.substring(authority.lastIndexOf('@') + 1);
        if (authority.startsWith("[")) {
            int close = authority.indexOf(']');
            return close > 0 ? authority.substring(1, close) : authority;
        }
        int colon = authority.indexOf(':');
        return colon >= 0 ? authority.substring(0, colon) : authority;
    }

    /** Index of the first character of {@code stops} at or after {@code from}, or the length. */
    private static int endOf(String url, int from, String stops) {
        int i = from;
        while (i < url.length() && stops.indexOf(url.charAt(i)) < 0) {
            i++;
        }
        return i;
    }
}
