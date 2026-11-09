package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.headers.HeaderSyntax;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.List;

/**
 * Strict-Transport-Security (RFC 6797). Browsers ignore HSTS received over
 * plain HTTP, so it is never reported as missing on an HTTP response and
 * nothing is inferred about the HTTPS configuration from one.
 */
public final class StrictTransportSecurityRule extends AbstractHeaderRule {

    public static final String HEADER = "Strict-Transport-Security";
    static final long ONE_YEAR = 31_536_000L;

    public StrictTransportSecurityRule() {
        super(HEADER,
                "Strict-Transport-Security (HSTS) tells browsers to reach the host only over HTTPS for the "
                        + "max-age period. This blocks SSL-stripping and downgrade attacks after the first visit.",
                "max-age=63072000; includeSubDomains",
                "Send 'Strict-Transport-Security: max-age=63072000; includeSubDomains' on all HTTPS responses.");
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return context.secure();
    }

    @Override
    public List<String> notes(ResponseHeaders headers, EvaluationContext context) {
        if (!context.secure()) {
            return List.of("Strict-Transport-Security was not evaluated: the response was received over HTTP, "
                    + "where browsers ignore HSTS. Scan the HTTPS endpoint to assess HSTS.");
        }
        return List.of();
    }

    @Override
    public List<Finding> evaluate(ResponseHeaders headers, EvaluationContext context) {
        if (!context.secure()) {
            return List.of();
        }
        return super.evaluate(headers, context);
    }

    @Override
    protected void evaluatePresent(ResponseHeaders headers, List<String> values,
                                   EvaluationContext context, List<Finding> out) {
        String raw = values.get(0);
        if (values.size() > 1) {
            out.add(finding(FindingType.CONFLICT, "Strict-Transport-Security header set multiple times",
                    String.join(" | ", values),
                    "The response sends " + values.size() + " Strict-Transport-Security headers. Per RFC 6797 "
                            + "browsers process only the first one: '" + raw + "'.",
                    Severity.INFORMATION, Confidence.CERTAIN));
        }
        HeaderSyntax.Directives d = HeaderSyntax.parseDirectives(raw, true);
        if (!d.duplicates().isEmpty()) {
            out.add(finding(FindingType.INVALID, "Strict-Transport-Security header has duplicate directives", raw,
                    "The directives " + d.duplicates() + " appear more than once. RFC 6797 requires browsers to "
                            + "ignore such a header entirely, so HSTS is not enforced.",
                    Severity.LOW, Confidence.CERTAIN));
            return;
        }
        if (!d.has("max-age")) {
            out.add(finding(FindingType.INVALID, "Strict-Transport-Security header lacks max-age", raw,
                    "The required max-age directive is missing, so browsers ignore the header.",
                    Severity.LOW, Confidence.CERTAIN));
            return;
        }
        long maxAge = parseDeltaSeconds(d.get("max-age"));
        if (maxAge < 0) {
            out.add(finding(FindingType.INVALID, "Strict-Transport-Security header has invalid max-age", raw,
                    "The max-age value '" + d.get("max-age") + "' is not a valid delta-seconds value (one or "
                            + "more digits, optionally quoted; signs, decimals and other characters are not "
                            + "allowed), so browsers ignore the header.",
                    Severity.LOW, Confidence.CERTAIN));
            return;
        }
        if (maxAge == 0) {
            out.add(finding(FindingType.WEAK, "Strict-Transport-Security disabled by max-age=0", raw,
                    "max-age=0 tells browsers to delete any stored HSTS policy for this host, which removes "
                            + "downgrade protection.",
                    Severity.LOW, Confidence.CERTAIN));
            return;
        }
        if (maxAge < ONE_YEAR) {
            out.add(finding(FindingType.WEAK, "Strict-Transport-Security max-age is short", raw,
                    "max-age is " + maxAge + " seconds (less than one year). Users who have not visited within "
                            + "that window are exposed to SSL-stripping on their next visit, and the host is not "
                            + "eligible for the browser preload list.",
                    Severity.INFORMATION, Confidence.CERTAIN));
        }
        if (!d.has("includesubdomains")) {
            out.add(finding(FindingType.WEAK, "Strict-Transport-Security does not include subdomains", raw,
                    "includeSubDomains is not set. Subdomains can still be reached over HTTP, where a network "
                            + "attacker can, for example, set cookies that are later sent to this host.",
                    Severity.INFORMATION, Confidence.FIRM));
        }
    }

    /**
     * Parses RFC 6797 delta-seconds ({@code 1*DIGIT}, optionally a quoted-string).
     * Returns -1 when the value is not delta-seconds; a digit string too large for
     * a {@code long} is treated as a very large value, not as an error.
     */
    static long parseDeltaSeconds(String value) {
        String unquoted = HeaderSyntax.unquote(value);
        String digits = unquoted != null ? unquoted : value;
        if (digits.isEmpty()) {
            return -1;
        }
        for (int i = 0; i < digits.length(); i++) {
            char c = digits.charAt(i);
            if (c < '0' || c > '9') {
                return -1;
            }
        }
        try {
            return Long.parseLong(digits);
        } catch (NumberFormatException overflow) {
            return Long.MAX_VALUE;
        }
    }
}
