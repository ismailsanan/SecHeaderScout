package io.github.ismailsanan.secheaderscout.model;

import io.github.ismailsanan.secheaderscout.definitions.HeaderDefinition;
import io.github.ismailsanan.secheaderscout.definitions.OwaspDefinitions;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import io.github.ismailsanan.secheaderscout.manual.ScanTarget;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static io.github.ismailsanan.secheaderscout.testsupport.Results.missing;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** SEC-11: contradictory states are unrepresentable. */
class TypeInvariantsTest {

    private static final UrlClassifier.UrlType N = UrlClassifier.UrlType.NORMAL;

    @Test
    void scanResultRejectsContradictoryStates() {
        // errored but carrying findings
        assertThrows(IllegalArgumentException.class, () -> new ScanResult("t", "https://e/", null, -1, true, false,
                null, null, "down", N, List.of(missing("X")), List.of(), Set.of()));
        // HTTP fallback but marked secure
        assertThrows(IllegalArgumentException.class, () -> new ScanResult("t", "https://e/", "GET", 200, true, true,
                null, "reason", null, N, List.of(), List.of(), Set.of()));
        // fallback without a reason
        assertThrows(IllegalArgumentException.class, () -> new ScanResult("t", "http://e/", "GET", 200, false, true,
                null, null, null, N, List.of(), List.of(), Set.of()));
        // fallback details without fallback
        assertThrows(IllegalArgumentException.class, () -> new ScanResult("t", "https://e/", "GET", 200, true, false,
                503, null, null, N, List.of(), List.of(), Set.of()));
        // secure disagrees with the URL scheme
        assertThrows(IllegalArgumentException.class, () -> new ScanResult("t", "http://e/", "GET", 200, true, false,
                null, null, null, N, List.of(), List.of(), Set.of()));
        // analysed result without a valid status
        assertThrows(IllegalArgumentException.class, () -> new ScanResult("t", "https://e/", "GET", -1, true, false,
                null, null, null, N, List.of(), List.of(), Set.of()));
    }

    @Test
    void presentHeadersAreNormalisedSoComparisonsCannotMissThem() {
        ScanResult r = new ScanResult("t", "https://e/", "GET", 200, true, false, null, null, null, N,
                List.of(), List.of(), Set.of("Referrer-Policy", " X-Frame-Options "));
        assertEquals(Set.of("referrer-policy", "x-frame-options"), r.presentHeaders());
    }

    @Test
    void failedResultsAreConsistentForHttpAndHttps() {
        assertFalse(ScanResult.failed("t", "http://e/", "x").secure());
        assertEquals(true, ScanResult.failed("t", "HTTPS://e/", "x").secure());
    }

    @Test
    void snapshotsAndContextsCannotContradictTheirUrl() {
        assertThrows(IllegalArgumentException.class, () -> new ResponseSnapshot("http://e/", "GET", 200, true,
                ResponseHeaders.empty(), true, false));
        assertThrows(IllegalArgumentException.class, () -> new ResponseSnapshot("https://e/", "GET", 0, true,
                ResponseHeaders.empty(), true, false));
        assertThrows(NullPointerException.class, () -> new ResponseSnapshot("https://e/", null, 200, true,
                ResponseHeaders.empty(), true, false));
    }

    @Test
    void handBuiltScanTargetsAreValidated() {
        assertThrows(IllegalArgumentException.class, () -> new ScanTarget("ftp", "e.example", "/"));
        assertThrows(IllegalArgumentException.class, () -> new ScanTarget(null, "user@e.example", "/"));
        assertThrows(IllegalArgumentException.class, () -> new ScanTarget(null, "e.example", "no-slash"));
        assertEquals("https://e.example/x", new ScanTarget(null, "e.example", "/x").url("https"));
    }

    @Test
    void definitionsRejectDuplicateHeadersCaseInsensitively() {
        assertThrows(IllegalArgumentException.class, () -> new OwaspDefinitions(OwaspDefinitions.Source.BUNDLED, "r",
                "2026-01-01 00:00:00", List.of(new HeaderDefinition("A-B", "1"), new HeaderDefinition("a-b", "2"))));
    }
}
