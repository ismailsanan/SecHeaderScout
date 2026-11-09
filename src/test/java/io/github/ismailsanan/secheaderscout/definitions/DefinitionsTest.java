package io.github.ismailsanan.secheaderscout.definitions;

import io.github.ismailsanan.secheaderscout.util.MiniJson;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefinitionsTest {

    private static String doc(String headers) {
        return "{\"last_update_utc\":\"2026-11-01 00:00:00\",\"headers\":[" + headers + "]}";
    }

    private static String headers(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append(i == 0 ? "" : ",").append("{\"name\":\"X-H").append(i).append("\",\"value\":\"v\"}");
        }
        return sb.toString();
    }

    @Test
    void bundledDefinitionsLoadOfflineWithPinnedVersion() {
        OwaspDefinitions defs = DefinitionsRepository.fromBundledResource().current();
        assertEquals(OwaspDefinitions.Source.BUNDLED, defs.source());
        assertEquals("06b5c6f34d730e2af01ffe72184f365f2902f8e2", defs.revision());
        assertEquals(13, defs.headers().size());
        assertTrue(defs.versionLabel().startsWith("bundled 06b5c6f (2026-10-18 07:04:36 UTC"));
        assertEquals("no-referrer", defs.recommendedFor("referrer-policy"));
    }

    /** A-5: the bundled file must match the pinned SHA-256 recorded in definitions.properties. */
    @Test
    void bundledFileMatchesPinnedSha256() throws Exception {
        java.util.Properties props = new java.util.Properties();
        try (var in = DefinitionsRepository.class.getResourceAsStream("/owasp/definitions.properties")) {
            props.load(in);
        }
        byte[] json;
        try (var in = DefinitionsRepository.class.getResourceAsStream("/owasp/headers_add.json")) {
            json = in.readAllBytes();
        }
        byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(json);
        StringBuilder hex = new StringBuilder();
        for (byte b : digest) {
            hex.append(String.format("%02x", b));
        }
        assertEquals(props.getProperty("source.sha256"), hex.toString(),
                "headers_add.json changed without updating definitions.properties");
    }

    @Test
    void acceptsValidDocument() throws Exception {
        assertEquals(6, DefinitionsParser.parse(doc(headers(6)), OwaspDefinitions.Source.BUNDLED, "x").headers().size());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",
            "not json",
            "[]",
            "{\"headers\":[]}",
            "{\"last_update_utc\":\"<script>\",\"headers\":[]}",
            "{\"last_update_utc\":\"2026-11-01 00:00:00\",\"headers\":{}}",
            "{\"last_update_utc\":\"2026-11-01 00:00:00\",\"headers\":[{\"name\":\"A\",\"value\":\"v\"}]}",
    })
    void rejectsMalformedDocuments(String json) {
        assertThrows(DefinitionsParser.InvalidDefinitionsException.class,
                () -> DefinitionsParser.parse(json, OwaspDefinitions.Source.BUNDLED, "x"));
    }

    @Test
    void rejectsHostileEntries() {
        String base = headers(5) + ",";
        for (String evil : new String[]{
                "{\"name\":\"<img src=x>\",\"value\":\"v\"}",
                "{\"name\":\"X-Ok\",\"value\":\"a\\r\\nSet-Cookie: x\"}",
                "{\"name\":\"X-H0\",\"value\":\"dup\"}",
                "{\"name\":\"X-Ok\",\"value\":5}",
                "{\"name\":\"X-Ok\",\"value\":\"" + "a".repeat(5000) + "\"}"}) {
            assertThrows(DefinitionsParser.InvalidDefinitionsException.class,
                    () -> DefinitionsParser.parse(doc(base + evil), OwaspDefinitions.Source.BUNDLED, "x"), evil);
        }
        assertThrows(DefinitionsParser.InvalidDefinitionsException.class,
                () -> DefinitionsParser.parse(doc(headers(65)), OwaspDefinitions.Source.BUNDLED, "x"));
    }

    @Test
    void miniJsonIsStrictAndBoundsNesting() {
        assertEquals(java.util.List.of(1.0, "aé", true), MiniJson.parse("[1, \"a\\u00e9\", true]"));
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parse("{\"a\":1,}"));
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parse("[1] x"));
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parse("[".repeat(10_000)));
    }

    // ---- Sync OWASP Headers ------------------------------------------------------------------------

    private static OwaspDefinitions bundled(String json) {
        try {
            return DefinitionsParser.parse(json, OwaspDefinitions.Source.BUNDLED, "pinned");
        } catch (DefinitionsParser.InvalidDefinitionsException e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void syncActivatesValidDefinitionsAndReportsTheDiff() {
        DefinitionsRepository repo = new DefinitionsRepository(bundled(doc(headers(6))));
        DefinitionsRepository.SyncResult r = repo.sync(url -> {
            assertEquals(DefinitionsRepository.UPSTREAM_URL, url);
            return doc(headers(7));
        });
        assertTrue(r.updated(), r.message());
        assertEquals(java.util.Set.of("X-H6"), r.added());
        assertEquals(OwaspDefinitions.Source.SYNCED, repo.current().source());
        assertTrue(repo.current().versionLabel().startsWith("synced latest ("), repo.current().versionLabel());
        assertTrue(r.message().contains("added [X-H6]"), r.message());
    }

    @Test
    void networkFailureKeepsTheCurrentDefinitions() {
        OwaspDefinitions before = DefinitionsRepository.fromBundledResource().current();
        DefinitionsRepository repo = new DefinitionsRepository(before);
        DefinitionsRepository.SyncResult r = repo.sync(url -> {
            throw new java.io.IOException("no response (TLS certificate verification failure)");
        });
        assertTrue(!r.updated());
        assertSame(before, repo.current());
        assertTrue(r.message().startsWith("Download failed: no response"), r.message());
        assertTrue(r.message().contains("Keeping bundled"), r.message());
    }

    @ParameterizedTest
    @ValueSource(strings = {"<html>rate limited</html>", "{}", "{\"headers\":[]}", ""})
    void invalidDownloadsAreRejectedAndTheCurrentDefinitionsStay(String body) {
        OwaspDefinitions before = DefinitionsRepository.fromBundledResource().current();
        DefinitionsRepository repo = new DefinitionsRepository(before);
        DefinitionsRepository.SyncResult r = repo.sync(url -> body);
        assertTrue(!r.updated());
        assertSame(before, repo.current());
        assertTrue(r.message().startsWith("Downloaded definitions rejected"), r.message());
    }

    @Test
    void aNullBodyIsAFailedDownload() {
        DefinitionsRepository repo = DefinitionsRepository.fromBundledResource();
        assertTrue(!repo.sync(url -> null).updated());
    }
}
