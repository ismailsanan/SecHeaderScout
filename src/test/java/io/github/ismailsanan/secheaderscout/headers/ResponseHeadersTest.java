package io.github.ismailsanan.secheaderscout.headers;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResponseHeadersTest {

    @Test
    void namesAreCaseInsensitive() {
        ResponseHeaders h = ResponseHeaders.of("REFERRER-policy", "no-referrer");
        assertTrue(h.has("Referrer-Policy"));
        assertTrue(h.has("referrer-policy"));
        assertEquals("no-referrer", h.first("rEfErReR-PoLiCy").orElseThrow());
    }

    @Test
    void duplicateFieldLinesArePreservedInOrder() {
        ResponseHeaders h = ResponseHeaders.of("X-A", "one", "x-a", "two");
        assertEquals(List.of("one", "two"), h.values("X-A"));
        assertEquals(2, h.count("x-a"));
        assertEquals("one, two", h.combined("X-A"));
    }

    @Test
    void listMembersSplitAcrossLinesButNotInsideQuotesOrParens() {
        ResponseHeaders h = ResponseHeaders.of(
                "Clear-Site-Data", "\"cache\", \"a,b\"",
                "Clear-Site-Data", "\"cookies\"",
                "Permissions-Policy", "geolocation=(self \"https://a.example\"), camera=()");
        assertEquals(List.of("\"cache\"", "\"a,b\"", "\"cookies\""), h.listMembers("clear-site-data"));
        assertEquals(2, h.listMembers("Permissions-Policy").size());
    }

    @Test
    void absentHeader() {
        ResponseHeaders h = ResponseHeaders.empty();
        assertFalse(h.has("x"));
        assertNull(h.combined("x"));
        assertTrue(h.values("x").isEmpty());
    }

    @Test
    void valuesAreTrimmedAndNullTolerated() {
        ResponseHeaders h = ResponseHeaders.of(List.of(new java.util.AbstractMap.SimpleEntry<>("X", null),
                new java.util.AbstractMap.SimpleEntry<>(" Y ", "  v  ")));
        assertEquals("", h.first("x").orElseThrow());
        assertEquals("v", h.first("y").orElseThrow());
    }
}
