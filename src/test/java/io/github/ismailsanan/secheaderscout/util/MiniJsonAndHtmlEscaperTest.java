package io.github.ismailsanan.secheaderscout.util;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MiniJsonAndHtmlEscaperTest {

    @Test
    void acceptsRfcNumbers() {
        assertEquals(List.of(0.0, -0.0, 12.0, 1.5, -2.25e3, 1e-2, 3E+1),
                MiniJson.parse("[0, -0, 12, 1.5, -2.25e3, 1e-2, 3E+1]"));
    }

    @Test
    void rejectsNonRfcNumbers() {
        for (String bad : List.of("01", "-", "1.", ".5", "+1", "1e", "1e+", "--1", "1.2.3", "0x10", "1-2", "Infinity",
                "-NaN")) {
            assertThrows(IllegalArgumentException.class, () -> MiniJson.parse(bad), bad);
            assertThrows(IllegalArgumentException.class, () -> MiniJson.parse("[" + bad + "]"), bad);
        }
    }

    @Test
    void unicodeEscapesNeedExactlyFourHexDigits() {
        assertEquals("A\u00e9", MiniJson.parse("\"\\u0041\\u00E9\""));
        for (String bad : List.of("\"\\u+041\"", "\"\\u-041\"", "\"\\u12\"", "\"\\u12g4\"",
                "\"\\u\uff11\uff12\uff13\uff14\"")) {
            assertThrows(IllegalArgumentException.class, () -> MiniJson.parse(bad), bad);
        }
    }

    @Test
    void duplicateKeysAreRejected() {
        assertEquals(Map.of("a", 1.0, "b", Map.of("a", 2.0)), MiniJson.parse("{\"a\":1,\"b\":{\"a\":2}}"));
        assertThrows(IllegalArgumentException.class, () -> MiniJson.parse("{\"a\":1,\"a\":2}"));
    }

    @Test
    void escapeIsStricterThanEscapeHtml4AndKeepsNonAscii() {
        assertEquals("&#39;é→\uFFFD", HtmlEscaper.escape("'é→\u0001"));
    }

    @Test
    void unescapeDecodesEscapeOutputAposRarrAndNumericEntities() {
        assertEquals("&<>\"''→→A\u00e9", HtmlEscaper.unescape("&amp;&lt;&gt;&quot;&#39;&apos;&rarr;&#8594;&#x41;&#xE9;"));
        assertEquals("&bogus; &#xZZ; & alone", HtmlEscaper.unescape("&bogus; &#xZZ; & alone"));
    }
}
