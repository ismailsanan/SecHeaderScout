package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.List;
import java.util.Set;

/**
 * X-Permitted-Cross-Domain-Policies. Governs Adobe clients (Acrobat/Reader,
 * legacy Flash) reading crossdomain.xml policies. {@code master-only},
 * {@code by-content-type} and {@code by-ftp-filename} are restrictive meta-policies
 * and are not reported.
 */
public final class PermittedCrossDomainPoliciesRule extends SingleTokenRule {

    public static final String HEADER = "X-Permitted-Cross-Domain-Policies";

    public PermittedCrossDomainPoliciesRule() {
        super(HEADER,
                "X-Permitted-Cross-Domain-Policies defines a meta-policy for Adobe clients (Acrobat and Reader, "
                        + "and formerly Flash). It decides whether policy files such as crossdomain.xml can grant "
                        + "other domains permission to read data from this host. A permissive policy file combined "
                        + "with a permissive meta-policy can expose authenticated data to documents from other "
                        + "domains.",
                "none",
                "Send 'X-Permitted-Cross-Domain-Policies: none' unless the application deliberately serves Adobe "
                        + "cross-domain policy files.",
                Set.of("none", "master-only", "by-content-type", "by-ftp-filename", "all", "none-this-response"),
                Mode.CASE_INSENSITIVE);
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return context.urlType() != UrlClassifier.UrlType.API;
    }

    @Override
    protected void evaluateToken(String token, String raw, ResponseHeaders headers,
                                 EvaluationContext context, List<Finding> out) {
        if (token.equals("all")) {
            out.add(finding(FindingType.WEAK, "X-Permitted-Cross-Domain-Policies allows all policy files", raw,
                    "The meta-policy 'all' allows any cross-domain policy file anywhere on this host to be honoured, "
                            + "including files uploaded by users or served from unexpected paths. Check whether "
                            + "the host serves a permissive crossdomain.xml.",
                    Severity.LOW, Confidence.FIRM).withSummary("'all' honours any cross-domain policy file on the host"));
        }
    }
}
