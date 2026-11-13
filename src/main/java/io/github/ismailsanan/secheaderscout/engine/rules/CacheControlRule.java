package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Cache-Control. Caching static, public assets is desirable, so cache
 * directives are only judged on responses that are likely to be sensitive:
 * sensitive URL types or responses to authenticated requests. Absence is
 * still reported on every HTML document (and on sensitive responses), while
 * the directives of a present header are only judged on sensitive responses.
 */
public final class CacheControlRule extends AbstractHeaderRule {

    public static final String HEADER = "Cache-Control";

    public CacheControlRule() {
        super(HEADER,
                "Cache-Control decides whether browsers and intermediate caches may store a response. Storing "
                        + "authenticated or sensitive responses can expose them to other users of a shared device "
                        + "or of a shared proxy cache.",
                "no-store, max-age=0 (for sensitive responses)",
                "Send 'Cache-Control: no-store' on responses containing sensitive or user-specific data. Never "
                        + "mark such responses 'public'.");
    }

    private static boolean sensitive(EvaluationContext context) {
        return context.urlType().isSensitive() || context.credentialedRequest();
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return context.htmlDocument() || sensitive(context);
    }

    @Override
    protected void evaluatePresent(ResponseHeaders headers, List<String> values,
                                   EvaluationContext context, List<Finding> out) {
        if (!sensitive(context)) {
            return;
        }
        Set<String> directives = headers.listMembers(HEADER).stream()
                .map(m -> m.split("=", 2)[0].trim().toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
        String raw = String.join(", ", values);
        String why = context.credentialedRequest() ? "a response to an authenticated request"
                : "a sensitive endpoint (" + context.urlType().label() + ")";
        if (directives.contains("public")) {
            out.add(finding(FindingType.WEAK, "Cache-Control marks sensitive response as public", raw,
                    "This is " + why + ", but Cache-Control contains 'public', which allows shared caches to "
                            + "store it and serve it to other users.",
                    Severity.LOW, Confidence.FIRM).withSummary("contains 'public'; shared caches may serve this sensitive response to other users"));
        } else if (!directives.contains("no-store")) {
            out.add(finding(FindingType.WEAK, "Cache-Control does not prevent storage of sensitive response", raw,
                    "This is " + why + ", but Cache-Control lacks 'no-store', so the browser may write it to "
                            + "disk where it can be recovered later.",
                    Severity.INFORMATION, Confidence.TENTATIVE).withSummary("lacks the 'no-store' directive; the browser may keep this sensitive response on disk"));
        }
    }
}
