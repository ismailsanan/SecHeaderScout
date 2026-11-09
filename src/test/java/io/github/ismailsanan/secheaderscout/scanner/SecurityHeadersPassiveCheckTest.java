package io.github.ismailsanan.secheaderscout.scanner;

import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator;
import io.github.ismailsanan.secheaderscout.engine.RuleSets;
import io.github.ismailsanan.secheaderscout.testsupport.FakeMontoya;
import io.github.ismailsanan.secheaderscout.testsupport.Http;
import io.github.ismailsanan.secheaderscout.testsupport.RecordingLog;
import io.github.ismailsanan.secheaderscout.testsupport.Strict;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityHeadersPassiveCheckTest {

    private RecordingLog log;
    private SecurityHeadersPassiveCheck check;

    /** All eight headers, correctly configured. */
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

    private List<AuditIssue> issues(HttpRequestResponse rr) {
        AuditResult result = check.doCheck(rr);
        return result.auditIssues();
    }

    private static AuditIssue named(List<AuditIssue> issues, String name) {
        return issues.stream().filter(i -> i.name().equals(name)).findFirst()
                .orElseThrow(() -> new AssertionError("no issue '" + name + "' in " + issues.stream().map(AuditIssue::name).toList()));
    }

    @Test
    void hardenedResponseProducesNoIssues() {
        assertTrue(issues(hardened("https://example.com/").build()).isEmpty());
    }

    @Test
    void detectsMissingHeadersOnHtml() {
        List<AuditIssue> issues = issues(Http.exchange().html().build());
        List<String> names = issues.stream().map(AuditIssue::name).toList();
        assertTrue(names.containsAll(List.of(
                "Cross-Origin-Opener-Policy header not set", "Cross-Origin-Embedder-Policy header not set",
                "Cross-Origin-Resource-Policy header not set", "Referrer-Policy header not set",
                "Permissions-Policy header not set", "X-DNS-Prefetch-Control header not set",
                "X-Permitted-Cross-Domain-Policies header not set")), names.toString());
        assertEquals(7, issues.size());
    }

    @Test
    void doesNotReportBurpNativeHeaders() {
        List<String> names = issues(Http.exchange().html().build()).stream().map(AuditIssue::name).toList();
        assertTrue(names.stream().noneMatch(n -> n.contains("Content-Security-Policy")
                || n.contains("Strict-Transport-Security") || n.contains("X-Frame-Options")), names.toString());
    }

    @Test
    void issueHasCompleteFields() {
        HttpRequestResponse rr = hardened("https://example.com/page").header("Referrer-Policy", "unsafe-url").build();
        AuditIssue issue = named(issues(rr), "Referrer-Policy leaks full URL");
        FakeMontoya.Issue f = FakeMontoya.fields(issue);
        assertEquals("https://example.com/page", f.baseUrl());
        assertEquals(AuditIssueSeverity.LOW, f.severity());
        assertEquals(AuditIssueSeverity.LOW, f.typicalSeverity());
        assertEquals(AuditIssueConfidence.CERTAIN, f.confidence());
        assertFalse(f.background().isEmpty());
        assertFalse(f.remediation().isEmpty());
        assertNotNull(f.remediationBackground());
        assertTrue(f.detail().contains("unsafe-url"));
        assertEquals(1, f.requestResponses().size());
    }

    @Test
    void evidenceHighlightsTheHeaderLines() {
        HttpRequestResponse rr = hardened("https://example.com/").header("Referrer-Policy", "unsafe-url").build();
        AuditIssue issue = named(issues(rr), "Referrer-Policy leaks full URL");
        List<Marker> markers = issue.requestResponses().get(0).responseMarkers();
        assertEquals(2, markers.size(), "both Referrer-Policy lines are marked");
        assertTrue(markers.get(0).range().endIndexExclusive() > markers.get(0).range().startIndexInclusive());
    }

    @Test
    void misconfiguredHeadersDetectedWithCorrectSeverity() {
        HttpRequestResponse rr = hardened("https://example.com/")
                .header("Permissions-Policy", "geolocation 'self'") // duplicate line makes it invalid syntax
                .build();
        AuditIssue issue = named(issues(rr), "Permissions-Policy header has invalid syntax");
        assertEquals(AuditIssueSeverity.LOW, issue.severity());
        assertEquals(AuditIssueConfidence.CERTAIN, issue.confidence());
    }

    @Test
    void missingHeadersReportedOncePerOrigin() {
        int first = issues(Http.exchange().url("https://example.com/a").html().build()).size();
        List<AuditIssue> second = issues(Http.exchange().url("https://example.com/b").html().build());
        List<AuditIssue> otherOrigin = issues(Http.exchange().url("https://other.example/").html().build());
        assertEquals(7, first);
        assertTrue(second.isEmpty(), "same origin: no duplicates, got " + second.stream().map(AuditIssue::name).toList());
        assertEquals(7, otherOrigin.size());
        assertTrue(issues(Http.exchange().url("http://example.com/").html().build()).size() > 0,
                "different scheme is a different origin");
    }

    @Test
    void reportOnceIsAtomicUnderConcurrency() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int i = 0; i < 64; i++) {
                int n = i;
                futures.add(pool.submit(() ->
                        issues(Http.exchange().url("https://race.example/p" + n).html().build()).size()));
            }
            int total = 0;
            for (Future<Integer> f : futures) {
                total += f.get();
            }
            assertEquals(7, total);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void clearSiteDataReportedPerLogoutUrl() {
        assertTrue(issues(hardened("https://example.com/logout").build()).stream()
                .anyMatch(i -> i.name().equals("Clear-Site-Data header not set on logout")));
        assertTrue(issues(hardened("https://example.com/auth/signout").build()).stream()
                .anyMatch(i -> i.name().equals("Clear-Site-Data header not set on logout")));
    }

    @Test
    void consolidationKeepsExistingForSameIssueAndUrl() {
        HttpRequestResponse rr = hardened("https://example.com/x").header("Referrer-Policy", "unsafe-url").build();
        AuditIssue a = named(issues(rr), "Referrer-Policy leaks full URL");
        AuditIssue b = named(issues(rr), "Referrer-Policy leaks full URL");
        assertEquals(ConsolidationAction.KEEP_EXISTING, check.consolidateIssues(a, b));
        AuditIssue other = named(issues(hardened("https://example.com/x").header("X-DNS-Prefetch-Control", "on").build()),
                "X-DNS-Prefetch-Control header has multiple values");
        assertEquals(ConsolidationAction.KEEP_BOTH, check.consolidateIssues(a, other));
    }

    @Test
    void maliciousHeaderValuesAreEscapedInIssueHtml() {
        String payload = "<script>alert(document.cookie)</script>";
        HttpRequestResponse rr = Http.exchange().html().header("Referrer-Policy", payload)
                .header("Cross-Origin-Opener-Policy", payload).build();
        List<AuditIssue> all = issues(rr);
        for (AuditIssue issue : all) {
            FakeMontoya.Issue f = FakeMontoya.fields(issue);
            for (String html : List.of(f.detail(), f.remediation(), f.background())) {
                assertFalse(html.contains("<script"), "unescaped payload in: " + html);
            }
        }
        for (String name : List.of("Referrer-Policy header has an invalid value",
                "Cross-Origin-Opener-Policy header has an invalid value")) {
            assertTrue(FakeMontoya.fields(named(all, name)).detail().contains("&lt;script&gt;alert(document.cookie)"));
        }
    }

    @Test
    void responseWithoutBodyOrNonHtmlOnlyGetsResourceHeaders() {
        List<String> names = issues(Http.exchange().url("https://cdn.example/a.png").mime(MimeType.IMAGE_PNG)
                .header("Content-Type", "image/png").build()).stream().map(AuditIssue::name).toList();
        assertEquals(List.of("Cross-Origin-Resource-Policy header not set",
                "X-Permitted-Cross-Domain-Policies header not set"), names);
    }

    @Test
    void noResponseMeansNoIssues() {
        assertTrue(issues(Http.noResponse("https://example.com/")).isEmpty());
    }

    @Test
    void sendsNoHttpRequests() {
        // Structural guarantee: the check holds no reference to Burp's Http API or MontoyaApi.
        for (Field field : SecurityHeadersPassiveCheck.class.getDeclaredFields()) {
            String type = field.getType().getName();
            assertFalse(type.startsWith("burp.api.montoya.http.Http") || type.equals("burp.api.montoya.MontoyaApi"),
                    "unexpected dependency: " + field);
        }
        // Behavioural guarantee: the strict fakes throw on any call that was not stubbed,
        // so a request attempt would surface as an error here.
        issues(Http.exchange().html().build());
        assertTrue(log.errors.isEmpty(), log.errors.toString());
    }

    @Test
    void internalErrorsAreLoggedAndNeverPropagateToBurp() {
        HttpRequestResponse broken = Strict.of(HttpRequestResponse.class)
                .returns("hasResponse", true)
                .answers("response", a -> {
                    throw new IllegalStateException("boom");
                })
                .answers("request", a -> {
                    throw new IllegalStateException("boom");
                })
                .build();
        assertTrue(check.doCheck(broken).auditIssues().isEmpty());
        assertEquals(1, log.errors.size());
    }

    @Test
    void resetClearsDeduplicationState() {
        issues(Http.exchange().html().build());
        assertTrue(check.trackedOrigins() > 0);
        check.reset();
        assertEquals(0, check.trackedOrigins());
    }
}
