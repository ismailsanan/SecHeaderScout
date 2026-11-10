package io.github.ismailsanan.secheaderscout.scanner;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.util.HtmlEscaper;

import java.util.ArrayList;
import java.util.List;

/**
 * Maps engine {@link Finding}s to Montoya {@link AuditIssue}s.
 *
 * <p>Burp renders issue details as HTML, and header values come from untrusted
 * servers, so every dynamic value is escaped with {@link HtmlEscaper}.</p>
 */
final class AuditIssueFactory {

    static final String REMEDIATION_BACKGROUND =
            "Security headers are a defence-in-depth measure recommended by the OWASP Secure Headers Project. "
                    + "Set them centrally (web server, reverse proxy or framework middleware) so that they are "
                    + "applied consistently to every response.";

    private AuditIssueFactory() {
    }

    static AuditIssue toAuditIssue(Finding finding, Evidence evidence, String baseUrl,
                                   boolean reportedOncePerOrigin) {
        String e = HtmlEscaper.escape(finding.header());
        StringBuilder detail = new StringBuilder();
        detail.append(HtmlEscaper.escape(finding.detail()));
        detail.append("<br><br><b>Header:</b> ").append(e);
        if (finding.observedValue() != null) {
            detail.append("<br><b>Observed value:</b> ").append(HtmlEscaper.escape(finding.observedValue()));
        }
        if (!finding.recommended().isEmpty()) {
            detail.append("<br><b>Recommended:</b> ").append(HtmlEscaper.escape(finding.recommended()));
        }
        if (reportedOncePerOrigin) {
            detail.append("<br><br>This issue is reported once per origin (scheme, host and port) to avoid flooding the "
                    + "Issues panel; other responses from this origin are likely affected too.");
        }

        AuditIssueSeverity severity = severity(finding.severity());
        return AuditIssue.auditIssue(
                finding.issueName(),
                detail.toString(),
                HtmlEscaper.escape(finding.remediation()),
                baseUrl,
                severity,
                confidence(finding.confidence()),
                HtmlEscaper.escape(finding.background()),
                REMEDIATION_BACKGROUND,
                severity,
                // a MISSING header has nothing to highlight: skip the byte search entirely
                finding.type().isMissing() ? evidence.exchange() : evidence.withHeaderMarkers(finding.header()));
    }

    static AuditIssueSeverity severity(Severity s) {
        return switch (s) {
            case HIGH -> AuditIssueSeverity.HIGH;
            case MEDIUM -> AuditIssueSeverity.MEDIUM;
            case LOW -> AuditIssueSeverity.LOW;
            case INFORMATION -> AuditIssueSeverity.INFORMATION;
        };
    }

    static AuditIssueConfidence confidence(Confidence c) {
        return switch (c) {
            case CERTAIN -> AuditIssueConfidence.CERTAIN;
            case FIRM -> AuditIssueConfidence.FIRM;
            case TENTATIVE -> AuditIssueConfidence.TENTATIVE;
        };
    }

    /**
     * The request/response used as issue evidence. The response bytes are copied lazily and
     * at most once per response (not once per issue): {@code toByteArray()} copies the whole
     * message, body included, and this runs for every proxied response.
     */
    static final class Evidence {
        private final HttpRequestResponse exchange;
        private ByteArray bytes;
        private int headerEnd;

        Evidence(HttpRequestResponse exchange) {
            this.exchange = exchange;
        }

        HttpRequestResponse exchange() {
            return exchange;
        }

        /** Highlights every field line of {@code headerName}; unchanged if the header is absent. */
        HttpRequestResponse withHeaderMarkers(String headerName) {
            if (bytes == null) {
                HttpResponse response = exchange.response();
                bytes = response.toByteArray();
                headerEnd = Math.min(response.bodyOffset(), bytes.length());
            }
            List<Marker> markers = headerMarkers(bytes, headerEnd, headerName);
            return markers.isEmpty() ? exchange : exchange.withResponseMarkers(markers);
        }
    }

    static List<Marker> headerMarkers(ByteArray bytes, int headerEnd, String headerName) {
        List<Marker> markers = new ArrayList<>();
        String needle = "\r\n" + headerName + ":";
        int from = 0;
        while (from < headerEnd) {
            int idx = bytes.indexOf(needle, false, from, headerEnd);
            if (idx < 0) {
                break;
            }
            int start = idx + 2;
            int eol = bytes.indexOf("\r\n", true, start, headerEnd);
            int end = eol < 0 ? headerEnd : eol;
            markers.add(Marker.marker(start, end));
            from = end;
        }
        return markers;
    }
}
