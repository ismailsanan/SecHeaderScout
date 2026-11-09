package io.github.ismailsanan.secheaderscout.model;

import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Immutable result of analysing one URL in the manual scanner.
 *
 * @param target              what the user asked to scan (host or URL)
 * @param url                 URL whose response was actually analysed (reflects the real protocol)
 * @param method              request method, or {@code null} when nothing was received
 * @param statusCode          status of the analysed response, or -1 if there was none
 * @param secure              {@code true} if the analysed response came over HTTPS
 * @param httpFallback        {@code true} if HTTPS failed and the result comes from plain HTTP
 * @param originalHttpsStatus status of the failed HTTPS attempt, or {@code null} if it got no response
 * @param fallbackReason      why the fallback happened, or {@code null}
 * @param error               why the URL could not be analysed, or {@code null}
 * @param urlType             heuristic URL classification
 * @param findings            findings
 * @param notes               transparency notes (e.g. HSTS not evaluated over HTTP)
 * @param presentHeaders      lower-cased names of headers present in the response
 * @param evaluationIncomplete {@code true} if at least one rule failed internally, so the
 *                            absence of findings does NOT mean the response is clean
 */
public record ScanResult(
        String target,
        String url,
        String method,
        int statusCode,
        boolean secure,
        boolean httpFallback,
        Integer originalHttpsStatus,
        String fallbackReason,
        String error,
        UrlClassifier.UrlType urlType,
        List<Finding> findings,
        List<String> notes,
        Set<String> presentHeaders,
        boolean evaluationIncomplete
) {
    /**
     * Enforces the states a result can legally be in, so consumers (UI, report,
     * comparison) never have to defend against contradictions such as an errored
     * result carrying findings or an HTTP-fallback result marked as HTTPS.
     */
    public ScanResult {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(urlType, "urlType");
        findings = List.copyOf(findings);
        notes = List.copyOf(notes);
        presentHeaders = presentHeaders.stream().map(ResponseHeaders::normalize)
                .collect(Collectors.toUnmodifiableSet());
        if (error != null) {
            require(findings.isEmpty() && notes.isEmpty() && presentHeaders.isEmpty(),
                    "an errored result carries no findings, notes or headers");
            require(method == null && statusCode == -1, "an errored result has no method or status");
            require(!httpFallback && !evaluationIncomplete, "an errored result has no fallback or evaluation state");
        } else {
            require(method != null, "an analysed result needs a method");
            require(ResponseSnapshot.isValidStatus(statusCode), "status out of range: " + statusCode);
            require(secure == ResponseSnapshot.isHttpsUrl(url),
                    "'secure' must match the scheme of the analysed URL");
        }
        if (httpFallback) {
            require(!secure, "an HTTP-fallback result cannot be secure");
            require(fallbackReason != null, "an HTTP-fallback result needs a reason");
        } else {
            require(originalHttpsStatus == null && fallbackReason == null,
                    "fallback details without httpFallback");
        }
    }

    /** Convenience constructor for a complete evaluation. */
    public ScanResult(String target, String url, String method, int statusCode, boolean secure,
                      boolean httpFallback, Integer originalHttpsStatus, String fallbackReason, String error,
                      UrlClassifier.UrlType urlType, List<Finding> findings, List<String> notes,
                      Set<String> presentHeaders) {
        this(target, url, method, statusCode, secure, httpFallback, originalHttpsStatus, fallbackReason, error,
                urlType, findings, notes, presentHeaders, false);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException("Invalid ScanResult: " + message);
        }
    }

    /** A result for a URL that could not be analysed. */
    public static ScanResult failed(String target, String url, String error) {
        return new ScanResult(target, url, null, -1, ResponseSnapshot.isHttpsUrl(url), false, null, null,
                Objects.requireNonNull(error, "error"), UrlClassifier.classify(url), List.of(), List.of(), Set.of(),
                false);
    }

    public boolean hasError() {
        return error != null;
    }

    public List<Finding> missing() {
        return findings.stream().filter(f -> f.type().isMissing()).toList();
    }

    public List<Finding> misconfigured() {
        return findings.stream().filter(f -> !f.type().isMissing()).toList();
    }

    /** Header names reported as missing, as published (e.g. {@code Referrer-Policy}). */
    public List<String> missingHeaderNames() {
        return missing().stream().map(Finding::header).distinct().toList();
    }

    /** The overall outcome; output formats switch on this instead of re-deriving it from flags. */
    public enum Status {
        /** Could not be analysed (see {@link #error()}). */
        ERROR,
        /** Analysed, but at least one rule failed: findings may be missing. */
        INCOMPLETE,
        /** Every rule ran and nothing was found. */
        CLEAN,
        /** Every rule ran and there are findings. */
        FINDINGS
    }

    public Status status() {
        if (error != null) {
            return Status.ERROR;
        }
        if (evaluationIncomplete) {
            return Status.INCOMPLETE;
        }
        return findings.isEmpty() ? Status.CLEAN : Status.FINDINGS;
    }

    /** No error, every rule ran, and nothing was found. */
    public boolean isClean() {
        return status() == Status.CLEAN;
    }

    public String protocol() {
        return secure ? "HTTPS" : "HTTP";
    }

    /** Short warning for the UI and the report, or an empty string. */
    public String fallbackWarning() {
        if (!httpFallback) {
            return "";
        }
        return "HTTP fallback: HTTPS " + (originalHttpsStatus == null ? "gave no response" : "returned " + originalHttpsStatus)
                + "; these results were obtained over plain HTTP";
    }
}
