package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.model.HeaderProfile;

import io.github.ismailsanan.secheaderscout.definitions.DefinitionsRepository;
import io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator;
import io.github.ismailsanan.secheaderscout.engine.RuleSets;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;
import io.github.ismailsanan.secheaderscout.util.Log;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Deep Scan noise filters, path-based header profiles and priority of sensitive endpoints. */
class DeepScanProfilesTest {

    /** Headers of a well-configured HTML page (only HSTS, CSP, XFO... present). */
    private static final String[] GOOD_PAGE = {
            "Content-Type", "text/html",
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains",
            "Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options", "nosniff",
            "Cache-Control", "no-store",
            "Referrer-Policy", "no-referrer"};

    private static ResponseSnapshot snap(String url, int status, String... headers) {
        return new ResponseSnapshot(url, "GET", status, url.startsWith("https"), ResponseHeaders.of(headers),
                List.of(headers).contains("text/html"), false);
    }

    private static String[] without(String[] headers, String name) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < headers.length; i += 2) {
            if (!headers[i].equals(name)) {
                out.add(headers[i]);
                out.add(headers[i + 1]);
            }
        }
        return out.toArray(new String[0]);
    }

    private static DeepScanResult scan(DeepScanOptions options, ResponseSnapshot... responses) {
        var defs = DefinitionsRepository.fromBundledResource().current().headers();
        ManualScanner scanner = new ManualScanner(url -> HttpFetcher.Result.failed("deep scan sends nothing"),
                () -> new HeaderEvaluator(RuleSets.manualRules(defs), (r, e) -> { }), Log.noop());
        return scanner.deepScan(List.of("e.example"), new SiteMapSource() {
            @Override
            public List<String> hosts() {
                return List.of("e.example");
            }

            @Override
            public List<ResponseSnapshot> responsesFor(String host) {
                return List.of(responses);
            }
        }, options, ProgressListener.none());
    }

    @Test
    void staticResourcesAreRecognisedByContentTypeThenExtension() {
        assertFalse(StaticResources.isStatic(snap("https://e.example/", 200, "Content-Type", "text/html")));
        assertFalse(StaticResources.isStatic(snap("https://e.example/x", 200, "Content-Type", "application/json")));
        assertTrue(StaticResources.isStatic(snap("https://e.example/x", 200, "Content-Type", "image/svg+xml")));
        assertTrue(StaticResources.isStatic(snap("https://e.example/app.js?v=3", 200)));
        assertTrue(StaticResources.isStatic(snap("https://e.example/x", 200, "Content-Type", "text/css")));
        assertTrue(StaticResources.isStatic(snap("https://e.example/a", 200, "Content-Type", "text/javascript")));
        assertFalse(StaticResources.isStatic(snap("https://e.example/logo.png", 200, "Content-Type", "text/plain")),
                "a declared Content-Type wins over the extension");
        assertFalse(StaticResources.isStatic(snap("https://e.example/report.pdf", 200, "Content-Type", "application/pdf")));
        assertEquals("png", StaticResources.extension("https://e.example/a/logo.PNG?x=1"));
        assertEquals("", StaticResources.extension("https://e.example/v1.2/users"));
    }

    @Test
    void noiseFiltersRunBeforeAnalysisAndAreAccounted() {
        DeepScanResult r = scan(DeepScanOptions.DEFAULT,
                snap("https://e.example/", 200, GOOD_PAGE),
                snap("https://e.example/search?q=a", 200, GOOD_PAGE),
                snap("https://e.example/search?q=b", 200, GOOD_PAGE),          // query variant: merged
                snap("https://e.example/logo.png", 200, "Content-Type", "image/png"), // static: skipped
                snap("https://e.example/old", 301, "Location", "/new"),       // redirect: skipped
                snap("https://e.example/missing", 404, GOOD_PAGE));           // error: skipped
        DeepScanResult.Stats s = r.stats();
        assertEquals(6, s.captured());
        assertEquals(2, s.analysed());
        assertEquals(1, s.skippedStatic());
        assertEquals(1, s.skippedRedirects());
        assertEquals(1, s.skippedErrors());
        assertEquals(1, s.mergedQueryVariants());
        assertEquals(s.captured(), s.analysed() + s.skippedStatic() + s.skippedErrors() + s.skippedRedirects()
                + s.mergedQueryVariants() + s.skippedOther());
        assertTrue(s.summary().contains("analysed 2 of 6"), s.summary());
        assertEquals(2, r.results().size());
    }

    @Test
    void everythingOptionKeepsTheRawPerUrlBehaviour() {
        DeepScanResult r = scan(DeepScanOptions.EVERYTHING,
                snap("https://e.example/search?q=a", 200, GOOD_PAGE),
                snap("https://e.example/search?q=b", 200, GOOD_PAGE),
                snap("https://e.example/logo.png", 200, "Content-Type", "image/png"),
                snap("https://e.example/missing", 404, GOOD_PAGE));
        assertEquals(4, r.stats().analysed());
    }

    @Test
    void endpointsUnderOnePathWithTheSameIssuesFormOneGroupDespiteDifferentNonces() {
        List<ResponseSnapshot> pages = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            String[] h = GOOD_PAGE.clone();
            h[5] = "default-src 'self' 'nonce-" + i + "'; frame-ancestors 'none'"; // per-response nonce
            pages.add(snap("https://e.example/app/page" + i, 200, h));
        }
        DeepScanResult r = scan(DeepScanOptions.DEFAULT, pages.toArray(new ResponseSnapshot[0]));
        assertEquals(1, r.profiles().size(), r.profiles().toString());
        HeaderProfile p = r.profiles().get(0);
        assertEquals(50, p.size());
        assertEquals("/app/*", p.path());
        assertEquals("e.example", p.host());
    }

    @Test
    void groupsAreSplitByFirstPathSegmentAndListTheMissingHeaders() {
        DeepScanResult r = scan(DeepScanOptions.DEFAULT,
                snap("https://e.example/api/v1/users", 200, "Content-Type", "application/json"),
                snap("https://e.example/api/v1/orders?id=3", 200, "Content-Type", "application/json"),
                snap("https://e.example/app/home", 200, GOOD_PAGE),
                snap("https://e.example/app/about", 200, GOOD_PAGE));
        assertEquals(2, r.profiles().size(), r.profiles().toString());
        HeaderProfile api = r.profiles().stream().filter(p -> p.path().equals("/api/*")).findFirst().orElseThrow();
        assertEquals(2, api.size());
        assertTrue(api.missingHeaders().contains("Strict-Transport-Security"), api.missingHeaders().toString());
        HeaderProfile app = r.profiles().stream().filter(p -> p.path().equals("/app/*")).findFirst().orElseThrow();
        assertFalse(app.missingHeaders().contains("Strict-Transport-Security"), app.missingHeaders().toString());
    }

    @Test
    void differentIssuesUnderTheSamePathAreSeparateGroups() {
        List<HeaderProfile> profiles = scan(DeepScanOptions.DEFAULT,
                snap("https://e.example/app/a", 200, GOOD_PAGE),
                snap("https://e.example/app/b", 200, without(GOOD_PAGE, "Strict-Transport-Security"))).profiles();
        assertEquals(2, profiles.size(), profiles.toString());
        assertTrue(profiles.stream().allMatch(p -> p.size() == 1));
        assertTrue(profiles.stream().anyMatch(p -> p.path().equals("/app/b")), "one URL: its own path is shown");
    }

    @Test
    void sensitiveEndpointsComeFirstThenSeverityAndSize() {
        List<ResponseSnapshot> pages = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            pages.add(snap("https://e.example/app/p" + i, 200, GOOD_PAGE));
        }
        pages.add(snap("https://e.example/account/logout", 200, GOOD_PAGE)); // missing Clear-Site-Data
        pages.add(snap("https://e.example/login", 200, without(GOOD_PAGE, "Cache-Control")));

        List<HeaderProfile> profiles = scan(DeepScanOptions.DEFAULT, pages.toArray(new ResponseSnapshot[0])).profiles();
        assertEquals(UrlClassifier.UrlType.LOGOUT, profiles.get(0).sensitivity(), profiles.toString());
        assertEquals("/account/logout", profiles.get(0).path());
        assertEquals(UrlClassifier.UrlType.LOGIN, profiles.get(1).sensitivity(), profiles.toString());
        assertEquals(30, profiles.get(2).size(), "then the rest");
    }

    @Test
    void pathGroupUsesTheFirstSegmentAndIgnoresTheQuery() {
        assertEquals("/api/*", ProfileGrouper.pathGroup("https://e/api/v1/users?id=1"));
        assertEquals("/login", ProfileGrouper.pathGroup("https://e/login?next=/"));
        assertEquals("/", ProfileGrouper.pathGroup("https://e/"));
        assertEquals("/", ProfileGrouper.pathGroup("https://e"));
        assertEquals("/docs/*", ProfileGrouper.pathGroup("https://e/docs/"));
    }
}
