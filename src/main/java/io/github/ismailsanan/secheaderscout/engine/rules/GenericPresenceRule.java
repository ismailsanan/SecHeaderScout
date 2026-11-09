package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.List;

/**
 * Presence-only check for headers listed in the OWASP definitions that have no
 * dedicated rule, e.g. headers added upstream after this release. Only
 * expected on HTML documents, to avoid noise on subresources.
 */
public final class GenericPresenceRule extends AbstractHeaderRule {

    public GenericPresenceRule(String header, String recommended) {
        super(header, "Recommended by the OWASP Secure Headers Project.", recommended,
                "Configure the header as recommended by the OWASP Secure Headers Project: " + recommended);
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return context.htmlDocument();
    }

    @Override
    protected void evaluatePresent(ResponseHeaders headers, List<String> values,
                                   EvaluationContext context, List<Finding> out) {
        // presence only: no value validation without header-specific rules
    }
}
