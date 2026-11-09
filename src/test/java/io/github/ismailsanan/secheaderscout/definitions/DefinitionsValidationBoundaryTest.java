package io.github.ismailsanan.secheaderscout.definitions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** FR-10: boundary and hostile-input tests for definitions validation and last-known-good behaviour. */
class DefinitionsValidationBoundaryTest {

    private static final String TS = "2026-11-01 00:00:00";

    private static String doc(String ts, String headers) {
        return "{\"last_update_utc\":\"" + ts + "\",\"headers\":[" + headers + "]}";
    }

    private static String entries(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append(i == 0 ? "" : ",").append("{\"name\":\"X-H").append(i).append("\",\"value\":\"v\"}");
        }
        return sb.toString();
    }

    private static OwaspDefinitions parse(String json) throws DefinitionsParser.InvalidDefinitionsException {
        return DefinitionsParser.parse(json, OwaspDefinitions.Source.BUNDLED, "latest");
    }

    private static void rejected(String json) {
        assertThrows(DefinitionsParser.InvalidDefinitionsException.class, () -> parse(json),
                json.length() > 200 ? json.substring(0, 200) + "..." : json);
    }

    private static String withExtra(String entry) {
        return doc(TS, entries(5) + "," + entry);
    }

    @Test
    void headerCountBoundaries() throws Exception {
        rejected(doc(TS, entries(DefinitionsParser.MIN_HEADERS - 1)));
        assertEquals(DefinitionsParser.MIN_HEADERS, parse(doc(TS, entries(DefinitionsParser.MIN_HEADERS))).headers().size());
        assertEquals(DefinitionsParser.MAX_HEADERS, parse(doc(TS, entries(DefinitionsParser.MAX_HEADERS))).headers().size());
        rejected(doc(TS, entries(DefinitionsParser.MAX_HEADERS + 1)));
    }

    @Test
    void headerNameLengthBoundaries() throws Exception {
        String max = "X" + "a".repeat(63);
        assertEquals(64, max.length());
        assertDoesNotThrow(() -> parse(withExtra("{\"name\":\"" + max + "\",\"value\":\"v\"}")));
        rejected(withExtra("{\"name\":\"" + max + "a\",\"value\":\"v\"}"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"X Space", "X_Under", "1Digit", "-Dash", "X:Colon", "Xé", "X\\u0000", "X\\r\\nY", ""})
    void invalidHeaderNamesAreRejected(String name) {
        rejected(withExtra("{\"name\":\"" + name + "\",\"value\":\"v\"}"));
    }

    @Test
    void nonStringOrMissingNamesAreRejected() {
        rejected(withExtra("{\"name\":null,\"value\":\"v\"}"));
        rejected(withExtra("{\"name\":42,\"value\":\"v\"}"));
        rejected(withExtra("{\"value\":\"v\"}"));
        rejected(withExtra("{\"name\":\"X-Ok\"}"));
        rejected(withExtra("\"X-Ok\""));
        rejected(withExtra("[\"X-Ok\",\"v\"]"));
    }

    @Test
    void valueLengthBoundaries() throws Exception {
        assertDoesNotThrow(() -> parse(withExtra("{\"name\":\"X-Ok\",\"value\":\"" + "a".repeat(4096) + "\"}")));
        rejected(withExtra("{\"name\":\"X-Ok\",\"value\":\"" + "a".repeat(4097) + "\"}"));
        assertEquals("", parse(withExtra("{\"name\":\"X-Ok\",\"value\":\"\"}")).recommendedFor("x-ok"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"\\u0000", "\\t", "\\n", "\\u001f", "\\u007f"})
    void controlCharactersInValuesAreRejected(String escaped) {
        rejected(withExtra("{\"name\":\"X-Ok\",\"value\":\"a" + escaped + "b\"}"));
    }

    @Test
    void htmlInValuesIsAcceptedAsDataBecauseOutputIsEscaped() throws Exception {
        assertEquals("<b>x</b>", parse(withExtra("{\"name\":\"X-Ok\",\"value\":\"<b>x</b>\"}")).recommendedFor("X-OK"));
    }

    @Test
    void duplicatesAreDetectedCaseInsensitively() {
        rejected(withExtra("{\"name\":\"x-h0\",\"value\":\"v\"}"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"2026-11-01", "2026-11-01T00:00:00", "2026-11-01 00:00:00"})
    void acceptedTimestamps(String ts) {
        assertDoesNotThrow(() -> parse(doc(ts, entries(5))));
    }

    @ParameterizedTest
    @ValueSource(strings = {"2026-11-0", "yesterday!", "2026-11-01 00:00:00<script>", "2026-11-01 00:00:00 UTC+01:00:00:00:00"})
    void rejectedTimestamps(String ts) {
        rejected(doc(ts, entries(5)));
    }

    @Test
    void nonStringTimestampIsRejected() {
        rejected("{\"last_update_utc\":20261101,\"headers\":[" + entries(5) + "]}");
    }

    @Test
    void documentSizeBoundary() throws Exception {
        String base = doc(TS, entries(5));
        String atLimit = base + " ".repeat(DefinitionsParser.MAX_CHARS - base.length());
        assertEquals(DefinitionsParser.MAX_CHARS, atLimit.length());
        assertEquals(5, parse(atLimit).headers().size());
        rejected(atLimit + " ");
    }

    @Test
    void unknownExtraFieldsAreIgnored() throws Exception {
        String json = "{\"last_update_utc\":\"" + TS + "\",\"extra\":{\"a\":[1,2]},\"headers\":["
                + "{\"name\":\"X-A\",\"value\":\"v\",\"comment\":\"ignored\"}," + entries(4).replace("X-H", "X-B") + "]}";
        assertEquals(5, parse(json).headers().size());
    }

    @Test
    void versionLabelShowsSourceRevisionTimestampAndCount() throws Exception {
        OwaspDefinitions parsed = parse(doc(TS, entries(5)));
        assertEquals(OwaspDefinitions.Source.BUNDLED, parsed.source());
        assertTrue(parsed.versionLabel().startsWith("bundled latest (" + TS + " UTC, 5 headers)"), parsed.versionLabel());
    }

}
