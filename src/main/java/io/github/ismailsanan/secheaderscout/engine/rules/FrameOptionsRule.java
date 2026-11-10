package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.headers.HeaderSyntax;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * X-Frame-Options (manual scanner only). Modern browsers ignore X-Frame-Options
 * when CSP frame-ancestors is present, so in that case the header is neither
 * required nor evaluated.
 */
public final class FrameOptionsRule extends AbstractHeaderRule {

    public static final String HEADER = "X-Frame-Options";

    public FrameOptionsRule() {
        super(HEADER,
                "X-Frame-Options stops other sites from framing a page, which prevents clickjacking. CSP "
                        + "frame-ancestors is the modern replacement and takes precedence when present.",
                "DENY (or CSP frame-ancestors 'none')",
                "Send 'X-Frame-Options: DENY' or 'SAMEORIGIN', or preferably 'Content-Security-Policy: "
                        + "frame-ancestors 'none''.");
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return context.htmlDocument() && context.urlType() != UrlClassifier.UrlType.API;
    }

    @Override
    public List<Finding> evaluate(ResponseHeaders headers, EvaluationContext context) {
        if (hasFrameAncestors(headers)) {
            return List.of();
        }
        return super.evaluate(headers, context);
    }

    private static boolean hasFrameAncestors(ResponseHeaders headers) {
        for (String policy : ContentSecurityPolicyRule.policies(headers.values(ContentSecurityPolicyRule.HEADER))) {
            if (HeaderSyntax.parseDirectives(policy, false).has("frame-ancestors")) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void evaluatePresent(ResponseHeaders headers, List<String> values,
                                   EvaluationContext context, List<Finding> out) {
        Set<String> distinct = new LinkedHashSet<>();
        for (String member : headers.listMembers(HEADER)) {
            distinct.add(member.toLowerCase(Locale.ROOT));
        }
        String raw = String.join(", ", values);
        if (distinct.size() > 1) {
            // HTML "check a navigation response's adherence to X-Frame-Options": a set of more than
            // one value blocks framing if it contains deny, sameorigin or allowall; otherwise the
            // header is invalid and framing is allowed.
            boolean blocks = distinct.contains("deny") || distinct.contains("sameorigin")
                    || distinct.contains("allowall");
            if (blocks) {
                out.add(finding(FindingType.CONFLICT, "X-Frame-Options header has conflicting values", raw,
                        "The response sends several different X-Frame-Options values " + distinct + ". Because "
                                + "the set includes DENY, SAMEORIGIN or ALLOWALL, the HTML standard requires "
                                + "browsers to block all framing, including same-origin framing, which may not "
                                + "be what was intended. Older browsers may instead ignore the header.",
                        Severity.INFORMATION, Confidence.FIRM));
            } else {
                out.add(finding(FindingType.INVALID, "X-Frame-Options header has an invalid value", raw,
                        "The response sends several different X-Frame-Options values " + distinct + ", none of "
                                + "which is DENY, SAMEORIGIN or ALLOWALL. Under the HTML standard the header is "
                                + "then invalid and ignored, so any site can frame the page.",
                        Severity.LOW, Confidence.CERTAIN));
            }
            return;
        }
        String value = distinct.isEmpty() ? "" : distinct.iterator().next();
        if (value.startsWith("allow-from")) {
            out.add(finding(FindingType.DEPRECATED, "X-Frame-Options uses deprecated ALLOW-FROM", raw,
                    "ALLOW-FROM is not supported by modern browsers, which ignore the header, so the page can be "
                            + "framed by any site unless CSP frame-ancestors is used.",
                    Severity.LOW, Confidence.CERTAIN));
        } else if (!value.equals("deny") && !value.equals("sameorigin")) {
            out.add(finding(FindingType.INVALID, "X-Frame-Options header has an invalid value", raw,
                    "'" + raw + "' is not DENY or SAMEORIGIN, so browsers ignore the header and allow framing.",
                    Severity.LOW, Confidence.CERTAIN));
        }
    }
}
