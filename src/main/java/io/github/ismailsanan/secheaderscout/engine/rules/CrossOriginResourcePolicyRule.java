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
 * Cross-Origin-Resource-Policy. Relevant for every response type (images,
 * scripts, JSON). An explicit {@code cross-origin} is normal for public CDN
 * assets, so it is only reported when the request was authenticated. CORP is
 * not a structured header: Fetch compares the value byte-for-byte, so it is
 * matched in {@link SingleTokenRule.Mode#EXACT} mode.
 */
public final class CrossOriginResourcePolicyRule extends SingleTokenRule {

    public static final String HEADER = "Cross-Origin-Resource-Policy";

    public CrossOriginResourcePolicyRule() {
        super(HEADER,
                "Cross-Origin-Resource-Policy (CORP) tells the browser which sites may load a resource with "
                        + "no-cors requests (img, script, video and so on). Without it, any site can make the "
                        + "browser fetch the resource into the attacker's renderer process, with the user's "
                        + "cookies attached unless their SameSite attribute prevents it. There it can be exposed "
                        + "through Spectre-style side channels or cross-site script inclusion (XSSI); Opaque "
                        + "Response Blocking (ORB/CORB) blocks some, but not all, such responses.",
                "same-origin",
                "Send 'Cross-Origin-Resource-Policy: same-origin' (or 'same-site') on responses that must not be "
                        + "embedded by other sites, especially authenticated responses. Use 'cross-origin' only "
                        + "for genuinely public resources.",
                Set.of("same-origin", "same-site", "cross-origin"),
                Mode.EXACT);
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return true;
    }

    @Override
    protected String missingDetail(EvaluationContext context) {
        return "The response does not set Cross-Origin-Resource-Policy, so any site can load it via no-cors "
                + "requests." + (context.credentialedRequest()
                ? " The request carried credentials, so the response may contain user-specific data." : "");
    }

    @Override
    protected void evaluateToken(String token, String raw, ResponseHeaders headers,
                                 EvaluationContext context, List<Finding> out) {
        if (token.equals("cross-origin") && context.credentialedRequest()) {
            out.add(finding(FindingType.WEAK, "Cross-Origin-Resource-Policy allows cross-origin loading of authenticated response",
                    raw,
                    "The response was returned to a request carrying cookies or an Authorization header, yet it "
                            + "explicitly allows any site to embed it with 'cross-origin'. If the response contains "
                            + "user-specific data, attacker pages can load it into their own process. Confirm whether "
                            + "the resource is genuinely public.",
                    Severity.INFORMATION, Confidence.TENTATIVE).withSummary("'cross-origin' on an authenticated response; any site can embed it"));
        }
    }
}
