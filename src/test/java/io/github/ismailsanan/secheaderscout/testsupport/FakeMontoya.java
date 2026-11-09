package io.github.ismailsanan.secheaderscout.testsupport;

import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpMode;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.List;

/**
 * Installs a fake {@link MontoyaObjectFactory} so the Montoya static factories
 * ({@code AuditIssue.auditIssue}, {@code AuditResult.auditResult},
 * {@code Marker.marker}, {@code RequestOptions.requestOptions},
 * {@code HttpRequest.httpRequestFromUrl}) work in unit tests.
 */
public final class FakeMontoya {

    private FakeMontoya() {
    }

    /** Captured AuditIssue fields. */
    public record Issue(String name, String detail, String remediation, String baseUrl,
                        AuditIssueSeverity severity, AuditIssueConfidence confidence, String background,
                        String remediationBackground, AuditIssueSeverity typicalSeverity,
                        List<HttpRequestResponse> requestResponses) {
    }

    /** RequestOptions fake that records which options were applied. */
    public static final class RecordedOptions {
        public final List<String> calls = new ArrayList<>();
        public Long timeoutMs;
        public RedirectionMode redirectionMode;
    }

    public record FakeRange(int startIndexInclusive, int endIndexExclusive) implements Range {
        @Override
        public boolean contains(int index) {
            return index >= startIndexInclusive && index < endIndexExclusive;
        }
    }

    public record FakeMarker(Range range) implements Marker {
    }

    private static final Map<AuditIssue, Issue> CAPTURED = Collections.synchronizedMap(new IdentityHashMap<>());

    private static final ThreadLocal<RecordedOptions> LAST_OPTIONS = new ThreadLocal<>();

    /**
     * Burp project persistence backed by {@code store}: {@code extensionData()} supports
     * getString / setString / deleteString; anything else fails the test.
     */
    public static burp.api.montoya.persistence.Persistence persistence(java.util.Map<String, String> store) {
        burp.api.montoya.persistence.PersistedObject data = Strict.of(burp.api.montoya.persistence.PersistedObject.class)
                .answers("getString", a -> store.get((String) a[0]))
                .answers("setString", a -> {
                    store.put((String) a[0], (String) a[1]);
                    return null;
                })
                .answers("deleteString", a -> {
                    store.remove((String) a[0]);
                    return null;
                }).build();
        return Strict.of(burp.api.montoya.persistence.Persistence.class).returns("extensionData", data).build();
    }

    public static RecordedOptions lastOptions() {
        return LAST_OPTIONS.get();
    }

    public static void install() {
        ObjectFactoryLocator.FACTORY = Strict.of(MontoyaObjectFactory.class)
                .answers("auditIssue", FakeMontoya::auditIssue)
                .answers("auditResult", a -> auditResult(a[0]))
                .answers("marker", a -> new FakeMarker(new FakeRange((Integer) a[0], (Integer) a[1])))
                .answers("requestOptions", a -> requestOptions())
                .answers("httpRequestFromUrl", a -> fakeRequest((String) a[0]))
                .build();
    }

    @SuppressWarnings("unchecked")
    private static Object auditIssue(Object[] a) {
        List<HttpRequestResponse> rrs = a[9] instanceof List<?> list
                ? (List<HttpRequestResponse>) list
                : Arrays.asList((HttpRequestResponse[]) a[9]);
        Issue issue = new Issue((String) a[0], (String) a[1], (String) a[2], (String) a[3],
                (AuditIssueSeverity) a[4], (AuditIssueConfidence) a[5], (String) a[6], (String) a[7],
                (AuditIssueSeverity) a[8], List.copyOf(rrs));
        AuditIssue proxy = Strict.of(AuditIssue.class)
                .returns("name", issue.name())
                .returns("detail", issue.detail())
                .returns("remediation", issue.remediation())
                .returns("baseUrl", issue.baseUrl())
                .returns("severity", issue.severity())
                .returns("confidence", issue.confidence())
                .returns("requestResponses", issue.requestResponses())
                .returns("toString", issue.toString())
                .build();
        CAPTURED.put(proxy, issue);
        return proxy;
    }

    /** Recovers captured fields from an AuditIssue produced by the fake factory. */
    public static Issue fields(AuditIssue issue) {
        return CAPTURED.get(issue);
    }

    @SuppressWarnings("unchecked")
    private static Object auditResult(Object arg) {
        List<AuditIssue> issues = arg instanceof List<?> l ? List.copyOf((List<AuditIssue>) l)
                : Arrays.asList((AuditIssue[]) arg);
        return Strict.of(AuditResult.class).returns("auditIssues", issues).build();
    }

    private static RequestOptions requestOptions() {
        RecordedOptions recorded = new RecordedOptions();
        LAST_OPTIONS.set(recorded);
        RequestOptions[] self = new RequestOptions[1];
        self[0] = Strict.of(RequestOptions.class)
                .answers("withUpstreamTLSVerification", a -> {
                    recorded.calls.add("withUpstreamTLSVerification");
                    return self[0];
                })
                .answers("withResponseTimeout", a -> {
                    recorded.calls.add("withResponseTimeout");
                    recorded.timeoutMs = (Long) a[0];
                    return self[0];
                })
                .answers("withRedirectionMode", a -> {
                    recorded.calls.add("withRedirectionMode");
                    recorded.redirectionMode = (RedirectionMode) a[0];
                    return self[0];
                })
                .answers("withHttpMode", a -> {
                    recorded.calls.add("withHttpMode:" + (HttpMode) a[0]);
                    return self[0];
                })
                .build();
        return self[0];
    }

    private static HttpRequest fakeRequest(String url) {
        if (url == null || !url.contains("://")) {
            throw new IllegalArgumentException("bad url");
        }
        return Strict.of(HttpRequest.class).returns("url", url).returns("method", "GET").build();
    }
}
