package io.github.ismailsanan.secheaderscout.burp;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import io.github.ismailsanan.secheaderscout.definitions.DefinitionsRepository;
import io.github.ismailsanan.secheaderscout.manual.HttpFetcher;

import java.io.IOException;

/**
 * Sends requests through Burp's HTTP stack, so Burp's upstream proxy, SOCKS and
 * TLS settings apply. Every request:
 * <ul>
 *     <li>verifies the upstream TLS certificate ({@code withUpstreamTLSVerification});
 *         an invalid certificate gives a failed result, never a silently accepted one,</li>
 *     <li>has a response timeout,</li>
 *     <li>does not follow redirects, so the analysed response always belongs to the requested URL.</li>
 * </ul>
 * This class is only used by user-triggered operations (Quick Scan, Rescan &amp;
 * Compare, Sync OWASP Headers), never by the passive scanner.
 */
public final class BurpHttpFetcher implements HttpFetcher, DefinitionsRepository.Downloader {

    static final long DEFAULT_TIMEOUT_MS = 10_000;
    /** The upstream definitions file is ~5 KB; anything far larger is not it. */
    static final int MAX_DOWNLOAD_BYTES = 256 * 1024;

    private final Http http;
    private final long timeoutMs;

    public BurpHttpFetcher(Http http) {
        this(http, DEFAULT_TIMEOUT_MS);
    }

    public BurpHttpFetcher(Http http, long timeoutMs) {
        this.http = http;
        this.timeoutMs = timeoutMs;
    }

    RequestOptions options() {
        return RequestOptions.requestOptions()
                .withUpstreamTLSVerification()
                .withResponseTimeout(timeoutMs)
                .withRedirectionMode(RedirectionMode.NEVER);
    }

    @Override
    public Result fetch(String url) {
        HttpRequest request;
        try {
            request = HttpRequest.httpRequestFromUrl(url);
        } catch (RuntimeException e) {
            return Result.failed("invalid URL");
        }
        HttpRequestResponse rr;
        try {
            rr = http.sendRequest(request, options());
        } catch (RuntimeException e) {
            // Burp signals some network/TLS problems by throwing; treat them as operational failures
            return Result.failed("request failed: " + describe(e));
        }
        if (!BurpMessages.hasResponse(rr)) {
            return Result.failed("no response (connection failure, timeout after " + timeoutMs
                    + " ms, or TLS certificate verification failure)");
        }
        return BurpMessages.analysableSnapshot(rr).map(Result::of).orElseGet(() ->
                Result.failed("invalid HTTP status line (status " + rr.response().statusCode() + ")"));
    }

    /** Same TLS-verified, non-redirecting request as {@link #fetch}; only a bounded HTTP 200 body is accepted. */
    @Override
    public String download(String url) throws IOException {
        HttpRequestResponse rr;
        try {
            rr = http.sendRequest(HttpRequest.httpRequestFromUrl(url), options());
        } catch (RuntimeException e) {
            throw new IOException("request failed: " + describe(e), e);
        }
        if (!BurpMessages.hasResponse(rr)) {
            throw new IOException("no response (connection failure, timeout or TLS certificate verification failure)");
        }
        int status = rr.response().statusCode();
        if (status != 200) {
            throw new IOException("unexpected HTTP status " + status);
        }
        if (rr.response().body().length() > MAX_DOWNLOAD_BYTES) {
            throw new IOException("response too large");
        }
        return rr.response().bodyToString();
    }

    private static String describe(RuntimeException e) {
        String message = io.github.ismailsanan.secheaderscout.util.Log.redactText(e.getMessage());
        return e.getClass().getSimpleName() + (message == null ? "" : ": " + message);
    }
}
