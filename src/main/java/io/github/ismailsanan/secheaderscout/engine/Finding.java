package io.github.ismailsanan.secheaderscout.engine;

import java.util.Objects;

/**
 * One technically justified observation about one header of one response.
 *
 * <p>All text is plain text. Consumers that render HTML (Burp issue details,
 * the HTML report) are responsible for escaping it.</p>
 *
 * @param header        canonical header name, e.g. {@code Referrer-Policy}
 * @param type          kind of problem
 * @param issueName     stable issue name; also used as the Burp issue name and for de-duplication
 * @param observedValue raw value of the header the finding is about, or of a closely related header
 *                      (e.g. Content-Security-Policy-Report-Only for "CSP only in report-only mode"),
 *                      or {@code null} when nothing relevant was observed
 * @param recommended   recommended configuration
 * @param detail        instance-specific explanation including the security impact
 * @param background    generic background for this issue type
 * @param remediation   how to fix it
 * @param severity      severity
 * @param confidence    confidence
 * @param summary       one short line for reports: what is wrong or lacking and, very briefly, why it
 *                      matters (e.g. "lacks 'no-store'; the browser may keep this response on disk"),
 *                      or empty when the rule gives none
 */
public record Finding(
        String header,
        FindingType type,
        String issueName,
        String observedValue,
        String recommended,
        String detail,
        String background,
        String remediation,
        Severity severity,
        Confidence confidence,
        String summary
) {
    /** A finding without a short summary (reports fall back to the first sentence of {@code detail}). */
    public Finding(String header, FindingType type, String issueName, String observedValue, String recommended,
                   String detail, String background, String remediation, Severity severity, Confidence confidence) {
        this(header, type, issueName, observedValue, recommended, detail, background, remediation, severity,
                confidence, "");
    }

    public Finding {
        Objects.requireNonNull(header, "header");
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(issueName, "issueName");
        Objects.requireNonNull(detail, "detail");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(confidence, "confidence");
        recommended = recommended == null ? "" : recommended;
        background = background == null ? "" : background;
        remediation = remediation == null ? "" : remediation;
        summary = summary == null ? "" : summary.strip();
    }

    /** This finding with the given short {@link #summary()}. */
    public Finding withSummary(String summary) {
        return new Finding(header, type, issueName, observedValue, recommended, detail, background, remediation,
                severity, confidence, summary);
    }
}
