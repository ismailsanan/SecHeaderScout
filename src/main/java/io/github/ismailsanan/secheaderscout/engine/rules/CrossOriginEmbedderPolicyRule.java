package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.headers.HeaderSyntax;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.List;
import java.util.Set;

/**
 * Cross-Origin-Embedder-Policy. On its own it is defence-in-depth: it protects
 * nothing, but together with COOP same-origin it enables cross-origin
 * isolation. An explicit {@code unsafe-none} is the default and a deliberate
 * opt-out, so it is not reported.
 */
public final class CrossOriginEmbedderPolicyRule extends SingleTokenRule {

    public static final String HEADER = "Cross-Origin-Embedder-Policy";

    public CrossOriginEmbedderPolicyRule() {
        super(HEADER,
                "Cross-Origin-Embedder-Policy (COEP) stops a document from loading cross-origin resources that "
                        + "have not opted in through CORP or CORS. Combined with 'Cross-Origin-Opener-Policy: "
                        + "same-origin' it makes the document cross-origin isolated, which keeps other sites' "
                        + "resources out of the page's process and so limits Spectre-style side-channel attacks. "
                        + "COEP does not prevent any attack by itself; it is a hardening measure.",
                "require-corp",
                "Send 'Cross-Origin-Embedder-Policy: require-corp' (or 'credentialless') on HTML documents, "
                        + "after checking that every cross-origin subresource sends CORP or CORS headers, and pair it "
                        + "with 'Cross-Origin-Opener-Policy: same-origin'.",
                Set.of("unsafe-none", "require-corp", "credentialless"),
                Mode.STRUCTURED_ITEM);
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return context.htmlDocument();
    }

    @Override
    protected String missingDetail(EvaluationContext context) {
        return "The HTML document does not set Cross-Origin-Embedder-Policy, so it cannot be cross-origin "
                + "isolated. This is hardening guidance, not a directly exploitable weakness.";
    }

    @Override
    protected void evaluateToken(String token, String raw, ResponseHeaders headers,
                                 EvaluationContext context, List<Finding> out) {
        if (token.equals("unsafe-none") || !context.htmlDocument()) {
            return;
        }
        // a COOP list (duplicate lines) fails structured-field parsing and counts as absent
        List<String> coopMembers = headers.listMembers(CrossOriginOpenerPolicyRule.HEADER);
        String coop = coopMembers.size() == 1 ? HeaderSyntax.itemToken(coopMembers.get(0)) : null;
        if (!"same-origin".equals(coop)) {
            out.add(finding(FindingType.CONFLICT, "Cross-origin isolation incomplete", raw,
                    "The document enforces COEP '" + token + "' but Cross-Origin-Opener-Policy is "
                            + (coop == null ? "not set (or invalid)" : "'" + coop + "'")
                            + ". Cross-origin isolation needs both COEP and 'Cross-Origin-Opener-Policy: "
                            + "same-origin', so the document carries COEP's compatibility cost without being "
                            + "isolated.",
                    Severity.INFORMATION, Confidence.CERTAIN).withSummary("Cross-Origin-Opener-Policy is not 'same-origin'; the page is not cross-origin isolated"));
        }
    }
}
