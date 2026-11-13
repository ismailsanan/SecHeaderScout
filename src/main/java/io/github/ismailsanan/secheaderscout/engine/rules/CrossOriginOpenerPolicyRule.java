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
 * Cross-Origin-Opener-Policy. Only meaningful on HTML documents. {@code
 * same-origin-allow-popups} (e.g. for OAuth or payment pop-ups) and {@code
 * noopener-allow-popups} are legitimate choices and are not reported.
 */
public final class CrossOriginOpenerPolicyRule extends SingleTokenRule {

    public static final String HEADER = "Cross-Origin-Opener-Policy";

    public CrossOriginOpenerPolicyRule() {
        super(HEADER,
                "Cross-Origin-Opener-Policy (COOP) places a document in its own browsing context group, so that "
                        + "cross-origin windows that open it, or that it opens, cannot keep a reference to it. Without "
                        + "COOP an attacker page can open the application and use the window handle for cross-site "
                        + "leaks (XS-Leaks), e.g. counting frames or observing navigations. COOP is also one of the two "
                        + "headers needed for cross-origin isolation.",
                "same-origin",
                "Send 'Cross-Origin-Opener-Policy: same-origin' on HTML documents. Use 'same-origin-allow-popups' "
                        + "if the page has to keep references to pop-ups it opens (for example OAuth or payment "
                        + "flows).",
                Set.of("unsafe-none", "same-origin-allow-popups", "same-origin", "noopener-allow-popups"),
                Mode.STRUCTURED_ITEM);
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return context.htmlDocument();
    }

    @Override
    protected String missingDetail(EvaluationContext context) {
        return "The HTML document does not set Cross-Origin-Opener-Policy, so browsers apply 'unsafe-none': "
                + "cross-origin pages that open this document (or are opened by it) keep a window reference to it.";
    }

    @Override
    protected void evaluateToken(String token, String raw, ResponseHeaders headers,
                                 EvaluationContext context, List<Finding> out) {
        if (token.equals("unsafe-none") && context.htmlDocument()) {
            out.add(finding(FindingType.WEAK, "Cross-Origin-Opener-Policy explicitly disables isolation", raw,
                    "The document explicitly sets 'unsafe-none', which opts out of browsing-context-group "
                            + "isolation. Cross-origin openers keep a window reference to the page.",
                    Severity.INFORMATION, Confidence.CERTAIN).withSummary("'unsafe-none'; cross-origin windows keep a reference to this page"));
        }
    }
}
