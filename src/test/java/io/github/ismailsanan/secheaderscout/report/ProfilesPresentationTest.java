package io.github.ismailsanan.secheaderscout.report;

import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.manual.ProfileGrouper;
import io.github.ismailsanan.secheaderscout.model.HeaderProfile;
import io.github.ismailsanan.secheaderscout.model.ScanResult;
import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import static io.github.ismailsanan.secheaderscout.testsupport.Results.missing;
import static io.github.ismailsanan.secheaderscout.testsupport.Results.result;
import static io.github.ismailsanan.secheaderscout.testsupport.Results.weak;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Deep Scan profiles in the HTML report and the details pane. */
class ProfilesPresentationTest {

    private static final String XSS = "<script>alert(1)</script>";

    private static List<HeaderProfile> profiles(String host, String oddPath) {
        List<ProfileGrouper.Analysed> analysed = new ArrayList<>();
        for (int i = 0; i < 5; i++) {
            analysed.add(new ProfileGrouper.Analysed(host,
                    result("https://e.example/app/p" + i, List.of(missing("Referrer-Policy")), Set.of())));
        }
        analysed.add(new ProfileGrouper.Analysed(host,
                result("https://e.example" + oddPath, List.of(missing("Referrer-Policy"),
                        missing("Strict-Transport-Security")), Set.of())));
        return ProfileGrouper.group(analysed);
    }

    @Test
    void reportShowsProfilesWithEverythingEscaped() {
        List<HeaderProfile> profiles = profiles("e.example" + XSS, "/export/" + XSS);
        List<ScanResult> results = profiles.stream().map(HeaderProfile::representative).toList();
        String html = ReportExporter.render(results, profiles, "v", ZonedDateTime.now());

        assertTrue(html.contains("<h2>Header profiles</h2>"));
        assertTrue(html.contains("Missing: Strict-Transport-Security"), html);
        assertFalse(html.toLowerCase(Locale.ROOT).contains("<script"), "profile data must be escaped");
        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assertTrue(html.indexOf("<h2>Header profiles</h2>") < html.indexOf("<h2>Results</h2>"));
        assertEquals(results.size(), ReportParser.parse(html).size(), "profile lines are not parsed as results");
    }

    @Test
    void reportWithoutProfilesHasNoProfileSection() {
        String html = ReportExporter.render(List.of(result("https://e.example/", List.of(), Set.of())), "v",
                ZonedDateTime.now());
        assertFalse(html.contains("Header profiles"));
    }

    @Test
    void detailsTextIsShortAndListsMissingThenMisconfigured() {
        List<ProfileGrouper.Analysed> analysed = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            analysed.add(new ProfileGrouper.Analysed("e.example", result("https://e.example/api/v" + i
                    + "?token=" + "A".repeat(500), List.of(missing("Referrer-Policy"), weak("X-Frame-Options", "x")),
                    Set.of())));
        }
        HeaderProfile p = ProfileGrouper.group(analysed).get(0);
        assertEquals("""
                e.example/api/*  (3 URLs)

                Missing:
                  - Referrer-Policy

                Misconfigured:
                  - X-Frame-Options
                      * Weak: x

                URLs:
                  /api/v0?...
                  /api/v1?...
                  /api/v2?...
                """, TextFormatter.profile(p));
    }

    @Test
    void sensitiveProfilesAreLabelled() {
        List<ProfileGrouper.Analysed> analysed = List.of(new ProfileGrouper.Analysed("e.example",
                result("https://e.example/logout", List.of(missing("Clear-Site-Data")), Set.of())));
        HeaderProfile p = ProfileGrouper.group(analysed).get(0);
        assertEquals(UrlClassifier.UrlType.LOGOUT, p.sensitivity());
        assertTrue(TextFormatter.profile(p).contains("Contains a LOGOUT endpoint"));
    }
}
