package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Referrer-Policy. Per the W3C Referrer Policy spec the value is a
 * comma-separated list; unknown tokens are ignored and the <em>last</em>
 * recognised token wins (this enables fallback syntax such as
 * {@code no-referrer, strict-origin-when-cross-origin}). Only the effective
 * policy is judged.
 */
public final class ReferrerPolicyRule extends AbstractHeaderRule {

    public static final String HEADER = "Referrer-Policy";

    private static final Set<String> VALID = Set.of(
            "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
            "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url");

    public ReferrerPolicyRule() {
        super(HEADER,
                "Referrer-Policy controls how much of the current URL the browser sends in the Referer header "
                        + "when it follows links or loads subresources. Full URLs often contain session "
                        + "identifiers, reset tokens, search terms or other sensitive path and query data. If they "
                        + "are sent to third-party origins or over unencrypted connections, that data leaks.",
                "strict-origin-when-cross-origin (or no-referrer)",
                "Send 'Referrer-Policy: strict-origin-when-cross-origin', or 'no-referrer' for highly sensitive "
                        + "pages. Avoid 'unsafe-url' and 'no-referrer-when-downgrade'.");
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return context.htmlDocument();
    }

    @Override
    protected String missingDetail(EvaluationContext context) {
        return "The HTML document does not set Referrer-Policy. Current browsers default to "
                + "'strict-origin-when-cross-origin', which only sends the origin to other sites, so the main "
                + "risk is from older browsers and from defaults overridden elsewhere (for example a referrerpolicy "
                + "attribute). Setting the header explicitly makes the policy deterministic.";
    }

    @Override
    protected void evaluatePresent(ResponseHeaders headers, List<String> values,
                                   EvaluationContext context, List<Finding> out) {
        List<String> recognised = new ArrayList<>();
        for (String member : headers.listMembers(HEADER)) {
            String token = member.trim().toLowerCase(Locale.ROOT);
            if (VALID.contains(token)) {
                recognised.add(token);
            }
        }
        String raw = String.join(", ", values);
        if (recognised.isEmpty()) {
            out.add(finding(FindingType.INVALID, "Referrer-Policy header has an invalid value", raw,
                    "None of the tokens in '" + raw + "' is a valid referrer policy, so browsers ignore the header "
                            + "and use their default ('strict-origin-when-cross-origin' in current browsers).",
                    Severity.INFORMATION, Confidence.CERTAIN).withSummary("no valid policy value; the browser default applies"));
            return;
        }
        String effective = recognised.get(recognised.size() - 1);
        if (values.size() > 1 && new LinkedHashSet<>(recognised).size() > 1) {
            out.add(finding(FindingType.CONFLICT, "Referrer-Policy header set multiple times", raw,
                    "The response sends " + values.size() + " Referrer-Policy headers with different policies. "
                            + "Browsers combine them and apply the last recognised token, '" + effective
                            + "', which may not be what was intended.",
                    Severity.INFORMATION, Confidence.CERTAIN).withSummary(values.size() + " headers sent; '" + effective + "' is the one applied"));
        }
        if (effective.equals("unsafe-url")) {
            out.add(finding(FindingType.WEAK, "Referrer-Policy leaks full URL", raw,
                    "The effective policy 'unsafe-url' sends the full URL, including path and query string, to "
                            + "every origin, even when an HTTPS page links to an HTTP resource. Sensitive data in "
                            + "URLs on this site can leak to third parties and to network observers.",
                    Severity.LOW, Confidence.CERTAIN).withSummary("'unsafe-url' sends the full URL (path and query) to every site"));
        } else if (effective.equals("no-referrer-when-downgrade")) {
            out.add(finding(FindingType.WEAK, "Referrer-Policy leaks full URL to third parties", raw,
                    "The effective policy 'no-referrer-when-downgrade' sends the full URL, including path and "
                            + "query string, to every HTTPS origin, including third parties. Current browsers "
                            + "default to sending only the origin cross-origin, so this setting weakens the "
                            + "browser default.",
                    Severity.LOW, Confidence.CERTAIN).withSummary("'no-referrer-when-downgrade' sends the full URL to other HTTPS sites"));
        }
    }
}
