package io.github.ismailsanan.secheaderscout.scanner;

import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator;
import io.github.ismailsanan.secheaderscout.engine.RuleSets;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.testsupport.FakeMontoya;
import io.github.ismailsanan.secheaderscout.testsupport.Http;
import io.github.ismailsanan.secheaderscout.testsupport.RecordingLog;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Additional passive-check tests: origin normalisation and de-duplication
 * (FR-4), evidence markers and issue fields (FR-3), escaping of every
 * HTTP-derived value in issue HTML (SEC-3) and document detection (HE-6).
 */
class PassiveCheckEvidenceAndDedupTest {

    private static final String XSS = "<script>alert(document.cookie)</script>";
    private static final String ATTR = "\"><img src=x onerror=alert(1)>'";

    private RecordingLog log;
    private SecurityHeadersPassiveCheck check;

    @BeforeAll
    static void installFactory() {
        FakeMontoya.install();
    }

    @BeforeEach
    void setUp() {
        log = new RecordingLog();
        check = new SecurityHeadersPassiveCheck(
                new HeaderEvaluator(RuleSets.passiveRules(), (r, e) -> log.error("rule", e)), log);
    }

    private static Http.Exchange hardened(String url) {
        return Http.exchange().url(url).html()
                .header("Cross-Origin-Opener-Policy", "same-origin")
                .header("Cross-Origin-Embedder-Policy", "require-corp")
                .header("Cross-Origin-Resource-Policy", "same-origin")
                .header("Referrer-Policy", "no-referrer")
                .header("Permissions-Policy", "camera=(), microphone=()")
                .header("X-DNS-Prefetch-Control", "off")
                .header("X-Permitted-Cross-Domain-Policies", "none");
    }

    private List<AuditIssue> issues(HttpRequestResponse rr) {
        return check.doCheck(rr).auditIssues();
    }

    private static List<String> names(List<AuditIssue> issues) {
        return issues.stream().map(AuditIssue::name).toList();
    }

    private static AuditIssue named(List<AuditIssue> issues, String name) {
        return issues.stream().filter(i -> i.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError("no issue '" + name + "' in " + names(issues)));
    }

    // ------------------------------------------------------------ FR-4 origins

    @Test
    void originHostIsCaseInsensitiveAndDefaultPortIsTheSameOrigin() {
        assertEquals(7, issues(Http.exchange().url("https://Example.COM/a").html().build()).size());
        assertTrue(issues(Http.exchange().url("https://example.com/b").html().build()).isEmpty(),
                "host case must not create a new origin");
        assertTrue(issues(Http.exchange().url("https://example.com:443/c").html().build()).isEmpty(),
                "explicit default port is the same origin");
    }

    @Test
    void differentPortIsADifferentOrigin() {
        assertEquals(7, issues(Http.exchange().url("https://example.com/").html().build()).size());
        assertEquals(7, issues(Http.exchange().url("https://example.com:8443/").html().build()).size());
    }

    @Test
    void sameOriginStillReportsMissingDocumentHeadersFirstSeenLater() {
        // first response is an image: only resource-level headers are "missing"
        List<AuditIssue> image = issues(Http.exchange().url("https://example.com/a.png").mime(MimeType.IMAGE_PNG)
                .header("Content-Type", "image/png").build());
        assertEquals(2, image.size(), names(image).toString());
        // the first HTML page on the origin still gets the document-only missing headers, once
        List<AuditIssue> page = issues(Http.exchange().url("https://example.com/").html().build());
        assertEquals(5, page.size(), names(page).toString());
        assertFalse(names(page).contains("Cross-Origin-Resource-Policy header not set"));
    }

    @Test
    void perOriginIssuesSayTheyAreReportedOncePerHostAndPerUrlIssuesDoNot() {
        List<AuditIssue> all = issues(Http.exchange().url("https://example.com/").html()
                .header("Referrer-Policy", "unsafe-url").build());
        String missingDetail = FakeMontoya.fields(named(all, "Cross-Origin-Opener-Policy header not set")).detail();
        assertTrue(missingDetail.contains("reported once per origin"), missingDetail);
        String weakDetail = FakeMontoya.fields(named(all, "Referrer-Policy leaks full URL")).detail();
        assertFalse(weakDetail.contains("reported once per origin"), weakDetail);
    }

    @Test
    void misconfigurationsAreReportedForEveryUrlOfAnOrigin() {
        for (String path : List.of("/a", "/b", "/c")) {
            List<AuditIssue> issues = issues(hardened("https://example.com" + path)
                    .header("Referrer-Policy", "unsafe-url").build());
            // hardened() already sends one Referrer-Policy line, so a CONFLICT is reported as well
            assertEquals(List.of("Referrer-Policy header set multiple times", "Referrer-Policy leaks full URL"),
                    names(issues), path);
        }
    }

    @Test
    void logoutClearSiteDataIsUrlScopedAndRepeatsAreConsolidatedByBurp() {
        String name = "Clear-Site-Data header not set on logout";
        AuditIssue first = named(issues(hardened("https://example.com/logout").build()), name);
        AuditIssue again = named(issues(hardened("https://example.com/logout").build()), name);
        named(issues(hardened("https://example.com/admin/logout").build()), name);
        assertFalse(FakeMontoya.fields(first).detail().contains("reported once per origin"));
        assertEquals(ConsolidationAction.KEEP_EXISTING, check.consolidateIssues(first, again));
    }

    @Test
    void consolidationKeepsBothForSameIssueOnDifferentUrls() {
        AuditIssue a = named(issues(hardened("https://example.com/a").header("Referrer-Policy", "unsafe-url").build()),
                "Referrer-Policy leaks full URL");
        AuditIssue b = named(issues(hardened("https://example.com/b").header("Referrer-Policy", "unsafe-url").build()),
                "Referrer-Policy leaks full URL");
        assertEquals(ConsolidationAction.KEEP_BOTH, check.consolidateIssues(a, b));
    }

    @Test
    void nullRequestResponseIsIgnoredWithoutError() {
        assertTrue(check.doCheck(null).auditIssues().isEmpty());
        assertTrue(log.errors.isEmpty());
        assertFalse(check.checkName().isBlank());
    }

    // ------------------------------------------------------------ FR-3 evidence

    @Test
    void missingHeaderIssueCarriesTheUnmarkedMessage() {
        AuditIssue issue = named(issues(Http.exchange().html().build()), "Referrer-Policy header not set");
        assertEquals(1, issue.requestResponses().size());
        assertTrue(issue.requestResponses().get(0).responseMarkers().isEmpty());
    }

    @Test
    void markerCoversExactlyTheHeaderLineAndMatchesNameCaseInsensitively() {
        Http.Exchange ex = hardened("https://example.com/").header("referrer-policy", "unsafe-url");
        String raw = ex.raw();
        AuditIssue issue = named(issues(ex.build()), "Referrer-Policy leaks full URL");
        List<Marker> markers = issue.requestResponses().get(0).responseMarkers();
        assertEquals(2, markers.size());
        List<String> marked = markers.stream()
                .map(m -> raw.substring(m.range().startIndexInclusive(), m.range().endIndexExclusive())).toList();
        assertEquals(List.of("Referrer-Policy: no-referrer", "referrer-policy: unsafe-url"), marked);
    }

    @Test
    void markersIgnoreLongerHeaderNamesAndTheBody() {
        Http.Exchange ex = hardened("https://example.com/")
                .header("Cross-Origin-Opener-Policy-Report-Only", "same-origin")
                .header("Cross-Origin-Opener-Policy", "unsafe-none")
                .body("<html>\r\nCross-Origin-Opener-Policy: fake-in-body\r\n</html>");
        String raw = ex.raw();
        // two COOP lines -> structured-field list -> invalid
        AuditIssue issue = named(issues(ex.build()), "Cross-Origin-Opener-Policy header has multiple values");
        List<Marker> markers = issue.requestResponses().get(0).responseMarkers();
        List<String> marked = markers.stream()
                .map(m -> raw.substring(m.range().startIndexInclusive(), m.range().endIndexExclusive())).toList();
        assertEquals(List.of("Cross-Origin-Opener-Policy: same-origin", "Cross-Origin-Opener-Policy: unsafe-none"),
                marked);
    }

    @Test
    void severityAndConfidenceMappingIsTotal() {
        assertEquals(AuditIssueSeverity.HIGH, AuditIssueFactory.severity(Severity.HIGH));
        assertEquals(AuditIssueSeverity.MEDIUM, AuditIssueFactory.severity(Severity.MEDIUM));
        assertEquals(AuditIssueSeverity.LOW, AuditIssueFactory.severity(Severity.LOW));
        assertEquals(AuditIssueSeverity.INFORMATION, AuditIssueFactory.severity(Severity.INFORMATION));
        assertEquals(AuditIssueConfidence.CERTAIN, AuditIssueFactory.confidence(Confidence.CERTAIN));
        assertEquals(AuditIssueConfidence.FIRM, AuditIssueFactory.confidence(Confidence.FIRM));
        assertEquals(AuditIssueConfidence.TENTATIVE, AuditIssueFactory.confidence(Confidence.TENTATIVE));
    }

    // ------------------------------------------------------------ SEC-3

    /** Removes the only markup the factory itself emits. */
    private static String withoutOwnMarkup(String html) {
        return html.replace("<br>", "").replace("<b>", "").replace("</b>", "");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Resource-Policy", "Referrer-Policy", "Permissions-Policy", "Feature-Policy",
            "X-DNS-Prefetch-Control", "X-Permitted-Cross-Domain-Policies", "Clear-Site-Data"})
    void hostileValueInAnyHeaderIsEscapedInEveryIssueField(String header) {
        String[] payloads = {XSS, ATTR, "camera=(\"" + XSS + "\")", XSS + "=*", "\"" + XSS + "\""};
        for (String payload : payloads) {
            SecurityHeadersPassiveCheck fresh = new SecurityHeadersPassiveCheck(
                    new HeaderEvaluator(RuleSets.passiveRules(), (r, e) -> log.error("rule", e)), log);
            HttpRequestResponse rr = Http.exchange().url("https://example.com/logout").html()
                    .header(header, payload).build();
            List<AuditIssue> all = fresh.doCheck(rr).auditIssues();
            assertFalse(all.isEmpty());
            for (AuditIssue issue : all) {
                FakeMontoya.Issue f = FakeMontoya.fields(issue);
                for (String html : List.of(withoutOwnMarkup(f.detail()), f.remediation(), f.background(),
                        f.remediationBackground(), f.name())) {
                    assertFalse(html.contains("<") || html.contains(">"),
                            header + " / " + payload + ": unescaped markup in " + html);
                }
            }
        }
        assertTrue(log.errors.isEmpty(), log.errors.toString());
    }

    // ------------------------------------------------------------ HE-6 / context

    @Test
    void declaredContentTypeWinsOverBurpMimeSniffing() {
        // JSON declared, but Burp sniffed HTML: not a document
        List<String> json = names(issues(Http.exchange().url("https://a.example/data")
                .header("Content-Type", "application/json").mime(MimeType.HTML).build()));
        assertEquals(List.of("Cross-Origin-Resource-Policy header not set",
                "X-Permitted-Cross-Domain-Policies header not set"), json);
    }

    @Test
    void noContentTypeFallsBackToBurpMime() {
        assertEquals(7, issues(Http.exchange().url("https://b.example/").mime(MimeType.HTML).build()).size());
    }

    @ParameterizedTest
    @ValueSource(strings = {"TEXT/HTML", "text/html ; charset=UTF-8", "application/xhtml+xml"})
    void htmlContentTypesAreDocuments(String contentType) {
        assertEquals(7, issues(Http.exchange().url("https://c.example/")
                .header("Content-Type", contentType).mime(MimeType.UNRECOGNIZED).build()).size());
    }

    @Test
    void credentialedRequestMakesCorpCrossOriginTentativeIssue() {
        String name = "Cross-Origin-Resource-Policy allows cross-origin loading of authenticated response";
        HttpRequestResponse anonymous = hardened("https://example.com/me")
                .header("Cross-Origin-Resource-Policy", "cross-origin").build();
        assertTrue(issues(anonymous).stream().noneMatch(i -> i.name().equals(name)));
        for (String credential : List.of("Cookie", "Authorization")) {
            HttpRequestResponse authed = Http.exchange().url("https://example.com/me").json()
                    .header("Cross-Origin-Resource-Policy", "cross-origin")
                    .header("X-Permitted-Cross-Domain-Policies", "none")
                    .requestHeader(credential).build();
            AuditIssue issue = named(issues(authed), name);
            assertEquals(AuditIssueConfidence.TENTATIVE, issue.confidence(), credential);
        }
    }
}
