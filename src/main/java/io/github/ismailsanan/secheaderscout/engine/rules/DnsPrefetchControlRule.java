package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.List;
import java.util.Set;

/**
 * X-DNS-Prefetch-Control. Privacy hardening: missing or explicitly enabled
 * prefetching is informational; invalid or conflicting values are LOW (via
 * {@link SingleTokenRule}) because the header is then ignored.
 */
public final class DnsPrefetchControlRule extends SingleTokenRule {

    public static final String HEADER = "X-DNS-Prefetch-Control";

    public DnsPrefetchControlRule() {
        super(HEADER,
                "X-DNS-Prefetch-Control controls whether the browser resolves the domain names of links and "
                        + "resources on a page before the user follows them. Prefetching can reveal to DNS "
                        + "resolvers which third-party links appear on a page, even when the user never clicks them. "
                        + "By default, browsers prefetch on HTTP pages but not on HTTPS pages.",
                "off",
                "Send 'X-DNS-Prefetch-Control: off' on HTML documents whose links could reveal sensitive "
                        + "information.",
                Set.of("on", "off"),
                Mode.CASE_INSENSITIVE);
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return context.htmlDocument();
    }

    @Override
    protected String missingDetail(EvaluationContext context) {
        return "The HTML document does not set X-DNS-Prefetch-Control, so the browser default applies"
                + (context.secure() ? " (no hyperlink DNS prefetching on HTTPS pages in major browsers)."
                : ", which enables DNS prefetching of hyperlinks on this HTTP page.");
    }

    @Override
    protected void evaluateToken(String token, String raw, ResponseHeaders headers,
                                 EvaluationContext context, List<Finding> out) {
        if (token.equals("on")) {
            out.add(finding(FindingType.WEAK, "X-DNS-Prefetch-Control explicitly enables DNS prefetching", raw,
                    "The response explicitly turns on DNS prefetching. This overrides the browser default on HTTPS "
                            + "pages and can reveal the hostnames of links on the page to DNS resolvers.",
                    Severity.INFORMATION, Confidence.CERTAIN).withSummary("'on' enables DNS prefetching; link hostnames leak to DNS resolvers"));
        }
    }
}
