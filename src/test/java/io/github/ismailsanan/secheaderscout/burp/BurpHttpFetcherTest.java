package io.github.ismailsanan.secheaderscout.burp;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import io.github.ismailsanan.secheaderscout.manual.HttpFetcher;
import io.github.ismailsanan.secheaderscout.testsupport.FakeMontoya;
import io.github.ismailsanan.secheaderscout.testsupport.Strict;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BurpHttpFetcherTest {

    @BeforeAll
    static void install() {
        FakeMontoya.install();
    }

    /** Http fake that only supports sendRequest(HttpRequest, RequestOptions) and records the options. */
    private static Http http(List<RequestOptions> seen, java.util.function.Supplier<HttpRequestResponse> reply) {
        return Strict.of(Http.class).answers("sendRequest", a -> {
            if (a.length != 2 || !(a[1] instanceof RequestOptions)) {
                throw new AssertionError("must use sendRequest(request, RequestOptions)");
            }
            seen.add((RequestOptions) a[1]);
            return reply.get();
        }).build();
    }

    @Test
    void everyRequestVerifiesTlsHasTimeoutAndDoesNotFollowRedirects() {
        List<RequestOptions> seen = new ArrayList<>();
        BurpHttpFetcher fetcher = new BurpHttpFetcher(http(seen,
                () -> io.github.ismailsanan.secheaderscout.testsupport.Http.exchange().build()), 7_000);
        HttpFetcher.Result result = fetcher.fetch("https://example.com/");
        assertTrue(result.ok());
        FakeMontoya.RecordedOptions options = FakeMontoya.lastOptions();
        assertTrue(options.calls.contains("withUpstreamTLSVerification"));
        assertEquals(7_000L, options.timeoutMs);
        assertEquals(RedirectionMode.NEVER, options.redirectionMode);
        assertEquals(1, seen.size());
    }

    @Test
    void tlsOrConnectionFailureWithoutResponseIsAFailureNotAResult() {
        BurpHttpFetcher fetcher = new BurpHttpFetcher(http(new ArrayList<>(),
                () -> io.github.ismailsanan.secheaderscout.testsupport.Http.noResponse("https://bad-cert.example/")));
        HttpFetcher.Result result = fetcher.fetch("https://bad-cert.example/");
        assertFalse(result.ok());
        assertTrue(result.failure().contains("TLS certificate verification failure"));
        assertTrue(result.failure().contains("timeout"));
    }

    @Test
    void exceptionsFromBurpBecomeFailures() {
        BurpHttpFetcher fetcher = new BurpHttpFetcher(http(new ArrayList<>(), () -> {
            throw new IllegalStateException("UnknownHostException: nx.example");
        }));
        HttpFetcher.Result result = fetcher.fetch("https://nx.example/");
        assertFalse(result.ok());
        assertTrue(result.failure().contains("nx.example"));
        assertFalse(fetcher.fetch("not a url").ok());
    }

    @Test
    void urlsEchoedInBurpExceptionMessagesAreRedacted() {
        BurpHttpFetcher fetcher = new BurpHttpFetcher(http(new ArrayList<>(), () -> {
            throw new IllegalStateException("cannot connect to https://e.example/reset?token=SECRET#frag");
        }));
        HttpFetcher.Result result = fetcher.fetch("https://e.example/reset?token=SECRET");
        assertFalse(result.failure().contains("SECRET"), result.failure());
        assertTrue(result.failure().contains("https://e.example/reset?[redacted]"), result.failure());
    }

    @Test
    void anInvalidStatusLineIsAFailureNotACrash() {
        BurpHttpFetcher fetcher = new BurpHttpFetcher(http(new ArrayList<>(),
                () -> io.github.ismailsanan.secheaderscout.testsupport.Http.exchange().status(0).build()));
        HttpFetcher.Result result = fetcher.fetch("https://example.com/");
        assertFalse(result.ok());
        assertTrue(result.failure().contains("invalid HTTP status"), result.failure());
    }

    @Test
    void siteMapHostExtractionIsLenient() {
        assertEquals("a.example", io.github.ismailsanan.secheaderscout.util.UrlPaths.host("https://a.example/p?q={x}|y z"));
        assertEquals("a.example", io.github.ismailsanan.secheaderscout.util.UrlPaths.host("http://user@a.example:8080/"));
        assertEquals("::1", io.github.ismailsanan.secheaderscout.util.UrlPaths.host("http://[::1]:80/"));
        assertEquals("", io.github.ismailsanan.secheaderscout.util.UrlPaths.host(null));
    }
}
