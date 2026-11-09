package io.github.ismailsanan.secheaderscout;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.sitemap.SiteMap;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.sitemap.SiteMapNode;
import io.github.ismailsanan.secheaderscout.burp.BurpLog;
import io.github.ismailsanan.secheaderscout.burp.BurpSiteMapSource;
import io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator;
import io.github.ismailsanan.secheaderscout.engine.RuleSets;
import io.github.ismailsanan.secheaderscout.scanner.SecurityHeadersPassiveCheck;
import io.github.ismailsanan.secheaderscout.testsupport.FakeMontoya;
import io.github.ismailsanan.secheaderscout.testsupport.RecordingLog;
import io.github.ismailsanan.secheaderscout.testsupport.Strict;
import io.github.ismailsanan.secheaderscout.util.HtmlEscaper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Regression tests for the /simplify pass (efficiency and redaction changes). */
class SimplifyPassRegressionTest {

    @BeforeAll
    static void install() {
        FakeMontoya.install();
    }

    @Test
    void unescapeIsLinearOnHostileAmpersandRuns() {
        String hostile = "&".repeat(2_000_000) + "&amp;";
        long start = System.nanoTime();
        String out = HtmlEscaper.unescape(hostile);
        long ms = (System.nanoTime() - start) / 1_000_000;
        assertEquals("&".repeat(2_000_001), out);
        // the old unbounded indexOf(';') per '&' needed ~2*10^12 comparisons here
        assertTrue(ms < 5_000, "unescape took " + ms + " ms");
    }

    @Test
    void burpLogRedactsMessagesAndTheWholeExceptionChain() {
        List<String> lines = new ArrayList<>();
        AtomicReference<Throwable> logged = new AtomicReference<>();
        Logging logging = Strict.of(Logging.class)
                .answers("logToOutput", a -> lines.add(String.valueOf(a[0])))
                .answers("logToError", a -> {
                    lines.add(String.valueOf(a[0]));
                    logged.set((Throwable) a[1]);
                    return null;
                }).build();
        BurpLog log = new BurpLog(logging);
        log.info("GET https://e.example/a?token=SECRET");
        log.warn("retrying http://e.example/#access_token=SECRET");
        Exception cause = new IllegalStateException("inner https://e.example/x?k=SECRET");
        Exception top = new RuntimeException("cannot reach https://e.example/reset?token=SECRET", cause);
        log.error("failed for https://e.example/?q=SECRET", top);

        assertTrue(lines.stream().noneMatch(l -> l.contains("SECRET")), lines.toString());
        StringWriter trace = new StringWriter();
        logged.get().printStackTrace(new PrintWriter(trace));
        assertFalse(trace.toString().contains("SECRET"), trace.toString());
        assertTrue(trace.toString().contains("java.lang.RuntimeException"), "original type kept in the message");
        assertEquals(top.getStackTrace().length, logged.get().getStackTrace().length, "stack trace preserved");

        Exception harmless = new IllegalStateException("plain failure");
        log.error("x", harmless);
        assertTrue(logged.get() == harmless, "exceptions without URLs are logged unchanged");
    }

    /** An exchange whose response counts toByteArray() copies. */
    private static HttpRequestResponse countingExchange(AtomicInteger copies, String... headers) {
        HttpService service = Strict.of(HttpService.class)
                .returns("host", "e.example").returns("port", 443).returns("secure", true).build();
        HttpRequest request = Strict.of(HttpRequest.class)
                .returns("url", "https://e.example/").returns("method", "GET").returns("httpService", service)
                .answers("hasHeader", a -> false).build();
        List<HttpHeader> list = new ArrayList<>();
        StringBuilder raw = new StringBuilder("HTTP/1.1 200 OK\r\n");
        for (int i = 0; i < headers.length; i += 2) {
            String n = headers[i];
            String v = headers[i + 1];
            list.add(Strict.of(HttpHeader.class).returns("name", n).returns("value", v).build());
            raw.append(n).append(": ").append(v).append("\r\n");
        }
        raw.append("\r\n");
        String text = raw.toString();
        ByteArray bytes = Strict.of(ByteArray.class).returns("length", text.length())
                .answers("indexOf", a -> {
                    String needle = ((Boolean) a[1]) ? (String) a[0] : ((String) a[0]).toLowerCase();
                    String hay = ((Boolean) a[1]) ? text : text.toLowerCase();
                    int idx = hay.indexOf(needle, (Integer) a[2]);
                    return idx >= 0 && idx + needle.length() <= (Integer) a[3] ? idx : -1;
                }).build();
        HttpResponse response = Strict.of(HttpResponse.class)
                .returns("statusCode", (short) 200).returns("headers", list).returns("mimeType", MimeType.HTML)
                .returns("bodyOffset", text.length())
                .answers("toByteArray", a -> {
                    copies.incrementAndGet();
                    return bytes;
                }).build();
        HttpRequestResponse[] self = new HttpRequestResponse[1];
        self[0] = Strict.of(HttpRequestResponse.class)
                .returns("request", request).returns("response", response).returns("hasResponse", true)
                .answers("withResponseMarkers", a -> self[0]).build();
        return self[0];
    }

    @Test
    void missingHeaderIssuesNeverCopyTheResponse() {
        AtomicInteger copies = new AtomicInteger();
        SecurityHeadersPassiveCheck check = new SecurityHeadersPassiveCheck(
                new HeaderEvaluator(RuleSets.passiveRules(), (r, e) -> { }), new RecordingLog());
        List<AuditIssue> issues = check.doCheck(countingExchange(copies, "Content-Type", "text/html")).auditIssues();
        assertEquals(7, issues.size(), "only 'header not set' issues");
        assertEquals(0, copies.get(), "a missing header has nothing to highlight: no byte copy at all");
    }

    @Test
    void theResponseIsCopiedAtMostOncePerExchange() {
        AtomicInteger copies = new AtomicInteger();
        SecurityHeadersPassiveCheck check = new SecurityHeadersPassiveCheck(
                new HeaderEvaluator(RuleSets.passiveRules(), (r, e) -> { }), new RecordingLog());
        List<AuditIssue> issues = check.doCheck(countingExchange(copies, "Content-Type", "text/html",
                "Referrer-Policy", "unsafe-url", "X-DNS-Prefetch-Control", "on",
                "X-Permitted-Cross-Domain-Policies", "all")).auditIssues();
        assertTrue(issues.size() >= 3, issues.toString());
        assertEquals(1, copies.get(), "several misconfiguration issues share one copy of the response");
    }

    @Test
    void hostRefreshMaterialisesNoSiteMapEntries() {
        AtomicInteger materialised = new AtomicInteger();
        SiteMap siteMap = Strict.of(SiteMap.class).answers("requestResponses", a -> {
            SiteMapFilter f = (SiteMapFilter) a[0];
            List<HttpRequestResponse> matched = new ArrayList<>();
            for (String url : List.of("https://a.example/", "https://a.example/x", "http://b.example:8080/y?q=1")) {
                SiteMapNode node = Strict.of(SiteMapNode.class).returns("url", url).build();
                if (f.matches(node)) {
                    materialised.incrementAndGet(); // Burp would build a request/response object
                    matched.add(null);
                }
            }
            return matched;
        }).build();
        List<String> hosts = new BurpSiteMapSource(siteMap, new RecordingLog()).hosts();
        assertEquals(List.of("a.example", "b.example"), hosts);
        assertEquals(0, materialised.get(), "the filter must match nothing, so Burp materialises no entries");
    }
}
