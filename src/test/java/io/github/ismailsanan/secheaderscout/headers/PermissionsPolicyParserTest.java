package io.github.ismailsanan.secheaderscout.headers;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionsPolicyParserTest {

    @Test
    void parsesValidDictionary() {
        var r = PermissionsPolicyParser.parse("camera=(), geolocation=(self \"https://maps.example\"), usb=*, fullscreen=self");
        assertTrue(r.valid(), r.error());
        assertTrue(r.features().get("camera").isEmpty());
        assertEquals(List.of("self", "https://maps.example"), r.features().get("geolocation").members());
        assertTrue(r.features().get("usb").allowsAllOrigins());
        assertFalse(r.features().get("fullscreen").allowsAllOrigins());
    }

    @Test
    void rejectsFeaturePolicySyntax() {
        assertFalse(PermissionsPolicyParser.parse("camera 'none'; microphone 'self'").valid());
        assertFalse(PermissionsPolicyParser.parse("geolocation=('self')").valid());
    }

    @Test
    void rejectsUppercaseKeysAndUnterminatedLists() {
        assertFalse(PermissionsPolicyParser.parse("Camera=()").valid());
        assertFalse(PermissionsPolicyParser.parse("camera=(self").valid());
    }

    @Test
    void unrecognisedItemsAreNotFatal() {
        // valid RFC 8941 dictionaries: only the affected feature's entry is ignored
        var none = PermissionsPolicyParser.parse("camera=(none), microphone=()");
        assertTrue(none.valid(), none.error());
        assertEquals(List.of("none"), none.unrecognisedEntries().get("camera"));
        assertTrue(none.features().get("camera").isEmpty());
        var bare = PermissionsPolicyParser.parse("camera");
        assertTrue(bare.valid(), bare.error());
        assertTrue(bare.unrecognisedEntries().containsKey("camera"));
    }

    @Test
    void lastDuplicateWins() {
        var r = PermissionsPolicyParser.parse("camera=(), camera=*");
        assertTrue(r.valid());
        assertEquals(List.of("camera"), r.duplicates());
        assertTrue(r.features().get("camera").allowsAllOrigins());
    }

    @Test
    void ignoresParameters() {
        assertTrue(PermissionsPolicyParser.parse("camera=();report-to=x").valid());
    }

    @Test
    void optionalWhitespaceAroundCommasAndAtTheEndsIsValid() {
        for (String v : List.of("camera=() ,microphone=()", "camera=()\t,\tmicrophone=()", "  camera=()  ",
                "\tcamera=(),microphone=()\t")) {
            var r = PermissionsPolicyParser.parse(v);
            assertTrue(r.valid(), v + ": " + r.error());
            assertTrue(r.features().get("camera").isEmpty(), v);
        }
    }

    @Test
    void equalsInsideQuotedOriginIsValid() {
        var r = PermissionsPolicyParser.parse("geolocation=(\"https://a.example/?x=1\")");
        assertTrue(r.valid(), r.error());
        assertEquals(List.of("https://a.example/?x=1"), r.features().get("geolocation").members());
    }

    @Test
    void repeatedSpacesInsideInnerListAreValid() {
        var r = PermissionsPolicyParser.parse("camera=( self  \"https://a\" )");
        assertTrue(r.valid(), r.error());
        assertEquals(List.of("self", "https://a"), r.features().get("camera").members());
        assertFalse(r.hasUnrecognisedEntries());
    }

    @Test
    void quotedParameterMayContainParenthesis() {
        var r = PermissionsPolicyParser.parse("camera=*;report-to=\"a)b\"");
        assertTrue(r.valid(), r.error());
        assertTrue(r.features().get("camera").allowsAllOrigins());
        var list = PermissionsPolicyParser.parse("camera=(self);report-to=\"a)b\", microphone=()");
        assertTrue(list.valid(), list.error());
        assertEquals(List.of("self"), list.features().get("camera").members());
    }

    @Test
    void fatalErrorsCarrySpecificMessages() {
        assertError("camera=('self')", "Feature-Policy syntax");
        assertError("camera 'none'; microphone 'self'", "Feature-Policy syntax");
        assertError("camera = ()", "whitespace around '='");
        assertError("camera= ()", "whitespace around '='");
        assertError("camera=(),", "empty dictionary member");
        assertError("camera=(), , microphone=()", "empty dictionary member");
        assertError(",camera=()", "empty dictionary member");
        assertError("camera=(self", "unterminated inner list");
        assertError("camera=(\"https://a", "unterminated string");
        assertError("Camera=()", "invalid feature name 'Camera'");
        assertError("=()", "invalid feature name ''");
        assertError("camera=", "has '=' but no value");
        assertError("camera=(self\tsrc)", "separated by spaces");
        assertError("camera=() microphone=()", "unexpected character 'm'");
        assertError("", "empty value");
    }

    @Test
    void unrecognisedEntriesAreRecordedPerFeature() {
        var r = PermissionsPolicyParser.parse("camera=none, microphone=(self;x=1), usb, geolocation=(\"self\" self)");
        assertTrue(r.valid(), r.error());
        assertEquals(List.of("camera", "microphone", "usb", "geolocation"),
                List.copyOf(r.unrecognisedEntries().keySet()));
        assertEquals(List.of("none"), r.unrecognisedEntries().get("camera"));
        assertTrue(r.unrecognisedEntries().get("microphone").get(0).contains("self;x=1"));
        assertEquals(List.of("\"self\""), r.unrecognisedEntries().get("geolocation"));
        // recognised items are kept; unrecognised ones contribute nothing
        assertEquals(List.of("self"), r.features().get("microphone").members());
        assertEquals(List.of("self"), r.features().get("geolocation").members());
        assertTrue(r.features().get("camera").isEmpty());
        assertTrue(r.features().get("usb").isEmpty());
    }

    @Test
    void laterCleanDeclarationClearsEarlierUnrecognisedEntries() {
        var r = PermissionsPolicyParser.parse("camera=none, camera=()");
        assertTrue(r.valid(), r.error());
        assertFalse(r.hasUnrecognisedEntries());
        assertEquals(List.of("camera"), r.duplicates());
    }

    private static void assertError(String value, String expectedFragment) {
        var r = PermissionsPolicyParser.parse(value);
        assertFalse(r.valid(), value);
        assertTrue(r.error().contains(expectedFragment), value + " -> " + r.error());
    }
}
