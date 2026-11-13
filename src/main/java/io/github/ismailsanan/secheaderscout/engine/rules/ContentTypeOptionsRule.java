package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.List;

/** X-Content-Type-Options. Per the Fetch standard only the first list member is checked. */
public final class ContentTypeOptionsRule extends AbstractHeaderRule {

    public static final String HEADER = "X-Content-Type-Options";

    public ContentTypeOptionsRule() {
        super(HEADER,
                "X-Content-Type-Options: nosniff stops browsers from MIME-sniffing a response away from its "
                        + "declared Content-Type. Without it, user-controlled content can be interpreted as script "
                        + "or HTML.",
                "nosniff",
                "Send 'X-Content-Type-Options: nosniff' on all responses.");
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return true;
    }

    @Override
    protected void evaluatePresent(ResponseHeaders headers, List<String> values,
                                   EvaluationContext context, List<Finding> out) {
        List<String> members = headers.listMembers(HEADER);
        String first = members.isEmpty() ? "" : members.get(0);
        if (!first.equalsIgnoreCase("nosniff")) {
            out.add(finding(FindingType.INVALID, "X-Content-Type-Options header has an invalid value",
                    String.join(", ", values),
                    "The first value is '" + first + "'. Browsers only honour 'nosniff', so MIME sniffing remains "
                            + "enabled.",
                    Severity.LOW, Confidence.CERTAIN).withSummary("'" + first + "' instead of 'nosniff'; MIME sniffing stays on"));
        }
    }
}
