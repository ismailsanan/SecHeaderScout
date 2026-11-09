package io.github.ismailsanan.secheaderscout.model;

import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.Objects;

/**
 * Burp-independent view of one request/response pair: everything the
 * evaluation engine needs, and nothing more.
 *
 * @param url                 request URL
 * @param method              request method
 * @param statusCode          response status code
 * @param secure              {@code true} if the exchange used HTTPS
 * @param headers             response headers
 * @param htmlDocument        {@code true} if the response is an HTML document
 * @param credentialedRequest {@code true} if the request carried Cookie or Authorization
 */
public record ResponseSnapshot(
        String url,
        String method,
        int statusCode,
        boolean secure,
        ResponseHeaders headers,
        boolean htmlDocument,
        boolean credentialedRequest
) {
    public ResponseSnapshot {
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(headers, "headers");
        Objects.requireNonNull(method, "method");
        if (!isValidStatus(statusCode)) {
            throw new IllegalArgumentException("status out of range: " + statusCode);
        }
        if (secure != isHttpsUrl(url)) {
            throw new IllegalArgumentException("'secure' must match the URL scheme: " + url);
        }
    }

    /** {@code true} if {@code url} uses the https scheme (case-insensitive). */
    public static boolean isHttpsUrl(String url) {
        return url.regionMatches(true, 0, "https://", 0, 8);
    }

    /** {@code true} for a status line a browser would process (100-599). */
    public static boolean isValidStatus(int statusCode) {
        return statusCode >= 100 && statusCode <= 599;
    }

    /** The evaluation context for this response (URL classification, protocol, content type, credentials). */
    public EvaluationContext toContext() {
        return EvaluationContext.of(url, secure, htmlDocument, credentialedRequest);
    }
}
