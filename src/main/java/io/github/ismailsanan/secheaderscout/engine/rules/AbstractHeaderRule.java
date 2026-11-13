package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.HeaderRule;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Base class: reports a MISSING finding when the header is absent and
 * {@link #expectedOn} holds; otherwise delegates to {@link #evaluatePresent}.
 */
public abstract class AbstractHeaderRule implements HeaderRule {

    private final String header;
    private final String background;
    private final String recommended;
    private final String remediation;

    protected AbstractHeaderRule(String header, String background, String recommended, String remediation) {
        // fail fast on misconfigured rules: every finding must carry these texts
        this.header = Objects.requireNonNull(header, "header");
        this.background = Objects.requireNonNull(background, "background");
        this.recommended = Objects.requireNonNull(recommended, "recommended");
        this.remediation = Objects.requireNonNull(remediation, "remediation");
    }

    @Override
    public final String header() {
        return header;
    }

    public String background() {
        return background;
    }

    public String recommended() {
        return recommended;
    }

    @Override
    public List<Finding> evaluate(ResponseHeaders headers, EvaluationContext context) {
        if (!headers.has(header)) {
            return expectedOn(context) ? List.of(missing(context)) : List.of();
        }
        List<Finding> findings = new ArrayList<>();
        evaluatePresent(headers, headers.values(header), context, findings);
        return findings;
    }

    /** Called only when at least one field line for the header exists. */
    protected abstract void evaluatePresent(ResponseHeaders headers, List<String> values,
                                            EvaluationContext context, List<Finding> out);

    /** Severity/confidence of the MISSING finding; override where absence matters more. */
    protected Finding missing(EvaluationContext context) {
        return new Finding(header, FindingType.MISSING, header + " header not set", null, recommended,
                missingDetail(context), background, remediation, Severity.INFORMATION, Confidence.CERTAIN);
    }

    protected String missingDetail(EvaluationContext context) {
        return "The response does not set the " + header + " header.";
    }

    protected Finding finding(FindingType type, String issueName, String observed, String detail,
                              Severity severity, Confidence confidence) {
        return new Finding(header, type, issueName, observed, recommended, detail, background, remediation,
                severity, confidence);
    }

    /** Standard finding for a header sent more than once when it must be a single value. */
    protected Finding multipleValues(List<String> values) {
        return finding(FindingType.INVALID, header + " header has multiple values", String.join(" | ", values),
                "The response sends " + header + " with multiple values (" + values.size()
                        + " field lines or a comma-separated list). This header accepts a single value, so browsers "
                        + "fail to parse it and fall back to the default behaviour, as if the header were absent.",
                Severity.LOW, Confidence.CERTAIN).withSummary("sent " + values.size()
                + " times or as a list; browsers ignore it");
    }
}
