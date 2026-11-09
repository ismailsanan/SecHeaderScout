package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.model.ScanResult;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.List;
import java.util.Set;

import static io.github.ismailsanan.secheaderscout.model.Results.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReportParserAndComparisonTest {

    @Test
    void roundTripsCurrentFormatIncludingSpecialCharacters() {
        String url = "https://example.com/a?b=1&c=\"<x>\"";
        String html = ReportExporter.render(List.of(
                result(url, List.of(missing("Referrer-Policy"), missing("Permissions-Policy"), weak("X", "v")), Set.of()),
                result("https://example.com/clean", List.of(), Set.of())), "v", ZonedDateTime.now());
        List<ReportParser.PreviousResult> parsed = ReportParser.parse(html);
        assertEquals(2, parsed.size());
        assertEquals(url, parsed.get(0).url());
        assertEquals(Set.of("referrer-policy", "permissions-policy"), parsed.get(0).missingHeaders());
        assertTrue(parsed.get(1).missingHeaders().isEmpty());
    }

    @Test
    void parsesLegacyV1Reports() {
        String legacy = "<html><body><h2>Results</h2>"
                + "<div class='url-block critical'><div class='url'>https://old.example/login <span class='label'> LOGIN</span></div>"
                + "<div style='margin-top:5px'><div class='missing'>MISSING → content-security-policy | Recommended: x</div>"
                + "<div class='missing'>MISSING &rarr; x-frame-options | Recommended: y</div></div></div>"
                + "<div class='url-block'><div class='url'>https://old.example/</div>"
                + "<div class='missing'>MISSING → [ERROR] Host Unreachable | Recommended: z</div></div>"
                + "</body></html>";
        List<ReportParser.PreviousResult> parsed = ReportParser.parse(legacy);
        assertEquals(2, parsed.size());
        assertEquals("https://old.example/login", parsed.get(0).url());
        assertEquals(Set.of("content-security-policy", "x-frame-options"), parsed.get(0).missingHeaders());
        assertTrue(parsed.get(1).missingHeaders().isEmpty(), "legacy error pseudo-header ignored");
    }

    @Test
    void foreignHtmlYieldsNothing() {
        assertTrue(ReportParser.parse("<html><body><p>hello</p></body></html>").isEmpty());
    }

    @Test
    void comparisonDistinguishesFixedFromNoLongerChecked() {
        ScanResult now = result("https://example.com/",
                List.of(missing("Referrer-Policy"), missing("Permissions-Policy")),
                Set.of("cross-origin-opener-policy"));
        Comparison c = new Comparison("https://example.com/",
                Set.of("Cross-Origin-Opener-Policy", "referrer-policy", "cache-control"), now);
        assertEquals(List.of("cross-origin-opener-policy"), c.fixed());
        assertEquals(List.of("referrer-policy"), c.stillMissing());
        assertEquals(List.of("permissions-policy"), c.newlyMissing());
        assertEquals(List.of("cache-control"), c.noLongerChecked());
    }
}
