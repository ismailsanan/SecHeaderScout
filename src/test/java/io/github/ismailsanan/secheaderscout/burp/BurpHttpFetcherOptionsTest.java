package io.github.ismailsanan.secheaderscout.burp;

import burp.api.montoya.http.Http;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.message.HttpRequestResponse;
import io.github.ismailsanan.secheaderscout.manual.HttpFetcher;
import io.github.ismailsanan.secheaderscout.testsupport.FakeMontoya;
import io.github.ismailsanan.secheaderscout.testsupport.Strict;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** SEC-4, SEC-5, FR-10: request option defaults, redirects not followed, bounded definitions download. */
class BurpHttpFetcherOptionsTest {

    @BeforeAll
    static void install() {
        FakeMontoya.install();
    }

    private static Http http(Supplier<HttpRequestResponse> reply) {
        return Strict.of(Http.class).answers("sendRequest", a -> reply.get()).build();
    }

    private static io.github.ismailsanan.secheaderscout.testsupport.Http.Exchange exchange() {
        return io.github.ismailsanan.secheaderscout.testsupport.Http.exchange();
    }

    @Test
    void defaultTimeoutIsTenSecondsAndOptionsAreAppliedInFull() {
        BurpHttpFetcher fetcher = new BurpHttpFetcher(http(() -> exchange().build()));
        assertTrue(fetcher.fetch("https://example.com/").ok());
        FakeMontoya.RecordedOptions o = FakeMontoya.lastOptions();
        assertEquals(BurpHttpFetcher.DEFAULT_TIMEOUT_MS, o.timeoutMs);
        assertEquals(10_000L, o.timeoutMs);
        assertEquals(RedirectionMode.NEVER, o.redirectionMode);
        assertTrue(o.calls.contains("withUpstreamTLSVerification"));
        assertTrue(o.calls.stream().noneMatch(c -> c.startsWith("withHttpMode")), o.calls.toString());
    }

    @Test
    void redirectResponseIsReturnedAsIsNotFollowed() {
        BurpHttpFetcher fetcher = new BurpHttpFetcher(http(() -> exchange().status(301)
                .header("Location", "http://evil.example/").build()));
        HttpFetcher.Result r = fetcher.fetch("https://example.com/");
        assertTrue(r.ok());
        assertEquals(301, r.response().statusCode());
        assertEquals("https://example.com/", r.response().url());
    }

    @Test
    void nullReplyIsAFailure() {
        assertFalse(new BurpHttpFetcher(http(() -> null)).fetch("https://example.com/").ok());
    }

    // ---- Sync OWASP Headers download ---------------------------------------------------------------

    @Test
    void downloadReturnsTheBodyOn200WithTheSameTlsVerifiedOptions() throws Exception {
        BurpHttpFetcher fetcher = new BurpHttpFetcher(http(() -> exchange().body("{\"headers\":[]}").build()));
        assertEquals("{\"headers\":[]}", fetcher.download("https://raw.example/x.json"));
        FakeMontoya.RecordedOptions o = FakeMontoya.lastOptions();
        assertTrue(o.calls.contains("withUpstreamTLSVerification"));
        assertEquals(RedirectionMode.NEVER, o.redirectionMode);
    }

    @Test
    void downloadRejectsRedirectsErrorsOversizedBodiesAndMissingResponses() {
        for (int status : new int[]{301, 404, 500}) {
            BurpHttpFetcher f = new BurpHttpFetcher(http(() -> exchange().status(status).build()));
            java.io.IOException e = assertThrows(java.io.IOException.class, () -> f.download("https://raw.example/"));
            assertEquals("unexpected HTTP status " + status, e.getMessage());
        }
        String big = "x".repeat(BurpHttpFetcher.MAX_DOWNLOAD_BYTES + 1);
        BurpHttpFetcher large = new BurpHttpFetcher(http(() -> exchange().body(big).build()));
        assertEquals("response too large",
                assertThrows(java.io.IOException.class, () -> large.download("https://raw.example/")).getMessage());
        assertThrows(java.io.IOException.class,
                () -> new BurpHttpFetcher(http(() -> null)).download("https://raw.example/"));
    }

    @Test
    void downloadWrapsBurpExceptionsWithRedactedMessages() {
        BurpHttpFetcher f = new BurpHttpFetcher(Strict.of(Http.class).answers("sendRequest", a -> {
            throw new IllegalStateException("failed for https://raw.example/x?token=SECRET");
        }).build());
        java.io.IOException e = assertThrows(java.io.IOException.class, () -> f.download("https://raw.example/x"));
        assertFalse(e.getMessage().contains("SECRET"), e.getMessage());
    }
}
