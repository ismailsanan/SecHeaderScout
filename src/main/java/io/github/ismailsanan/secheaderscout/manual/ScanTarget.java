package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.util.UrlPaths;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Optional;

/**
 * A normalised manual-scan target. Accepts {@code host}, {@code host:port},
 * {@code host/path} or a full {@code http(s)://} URL.
 *
 * @param explicitScheme {@code "http"} or {@code "https"} if the user typed one, otherwise {@code null}
 * @param authority      host[:port]
 * @param pathAndQuery   path plus optional query, always starting with {@code /}
 */
public record ScanTarget(String explicitScheme, String authority, String pathAndQuery) {

    /** Enforces what {@link #parse} guarantees, so hand-built targets cannot skew fallback decisions. */
    public ScanTarget {
        if (explicitScheme != null && !explicitScheme.equals("http") && !explicitScheme.equals("https")) {
            throw new IllegalArgumentException("scheme must be http, https or absent");
        }
        if (authority == null || authority.isEmpty() || authority.indexOf('@') >= 0
                || authority.chars().anyMatch(c -> c <= 0x20 || c == '/' || c == '?' || c == '#')) {
            throw new IllegalArgumentException("invalid authority");
        }
        if (pathAndQuery == null || !pathAndQuery.startsWith("/")) {
            throw new IllegalArgumentException("path must start with '/'");
        }
    }

    public static Optional<ScanTarget> parse(String input) {
        if (input == null) {
            return Optional.empty();
        }
        String trimmed = input.trim();
        if (trimmed.isEmpty() || trimmed.chars().anyMatch(c -> Character.isWhitespace(c) || c < 0x20)) {
            return Optional.empty();
        }
        String scheme = null;
        String rest = trimmed;
        String lower = trimmed.toLowerCase(Locale.ROOT);
        if (lower.startsWith("https://")) {
            scheme = "https";
            rest = trimmed.substring(8);
        } else if (lower.startsWith("http://")) {
            scheme = "http";
            rest = trimmed.substring(7);
        } else if (lower.contains("://")) {
            return Optional.empty(); // unsupported scheme
        }
        try {
            URI uri = new URI("https://" + rest);
            String host = uri.getHost();
            if (host == null || host.isEmpty() || uri.getRawUserInfo() != null) {
                return Optional.empty();
            }
            String authority = uri.getRawAuthority();
            String path = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
            String query = uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery();
            return Optional.of(new ScanTarget(scheme, authority, path + query));
        } catch (URISyntaxException e) {
            return Optional.empty();
        }
    }

    /** Host without port; IPv6 literals without brackets. */
    public String host() {
        return UrlPaths.host(authority);
    }

    /** Host of {@code input} when it is a valid target, otherwise {@code input} itself. */
    public static String hostOrRaw(String input) {
        return parse(input).map(ScanTarget::host).orElse(input);
    }

    public String url(String scheme) {
        return scheme + "://" + authority + pathAndQuery;
    }

    /** Scheme to try first: the explicit one, otherwise HTTPS. */
    public String primaryScheme() {
        return explicitScheme != null ? explicitScheme : "https";
    }

    /** HTTP fallback is only possible when the user did not pin a scheme. */
    public boolean fallbackPossible() {
        return explicitScheme == null;
    }
}
