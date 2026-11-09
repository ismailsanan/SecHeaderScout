package io.github.ismailsanan.secheaderscout.engine;

import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.List;

/**
 * Evaluates one security header. Implementations must be stateless and
 * thread-safe: the passive scanner calls them concurrently from Burp's scanner
 * threads.
 */
public interface HeaderRule {

    /** Canonical header name, e.g. {@code Cross-Origin-Opener-Policy}. */
    String header();

    /** Whether the absence of the header is worth reporting for this response. */
    boolean expectedOn(EvaluationContext context);

    /** Returns the findings for this header; never {@code null}. */
    List<Finding> evaluate(ResponseHeaders headers, EvaluationContext context);

    /**
     * Optional transparency notes, e.g. "HSTS not evaluated because the response
     * was received over HTTP". Notes are not findings.
     */
    default List<String> notes(ResponseHeaders headers, EvaluationContext context) {
        return List.of();
    }
}
