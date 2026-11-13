package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.engine.UrlClassifier;
import io.github.ismailsanan.secheaderscout.headers.HeaderSyntax;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Clear-Site-Data. Only expected on logout endpoints, which are identified
 * heuristically from the URL path, so findings that depend on that are
 * TENTATIVE. Syntax checks apply wherever the header appears.
 */
public final class ClearSiteDataRule extends AbstractHeaderRule {

    public static final String HEADER = "Clear-Site-Data";

    private static final Set<String> VALID_DIRECTIVES = Set.of(
            "cache", "cookies", "storage", "executionContexts", "clientHints", "prefetchCache",
            "prerenderCache", "*");

    public ClearSiteDataRule() {
        super(HEADER,
                "Clear-Site-Data tells the browser to delete data that the site stored on the client: cookies, "
                        + "storage (localStorage, IndexedDB, service workers and so on) and the HTTP cache. Sent on "
                        + "logout, it stops session tokens, cached authenticated pages and stored user data from "
                        + "outliving the session on shared or compromised devices.",
                "\"cache\", \"cookies\", \"storage\"",
                "Send 'Clear-Site-Data: \"cache\", \"cookies\", \"storage\"' on the logout response, over "
                        + "HTTPS. Each directive must be a quoted string.");
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return context.urlType() == UrlClassifier.UrlType.LOGOUT;
    }

    @Override
    protected Finding missing(EvaluationContext context) {
        return finding(FindingType.MISSING, "Clear-Site-Data header not set on logout", null,
                "This response appears to be a logout endpoint (based on its URL path) but does not set "
                        + "Clear-Site-Data. Cookies, client-side storage and cached authenticated pages may "
                        + "survive the logout on the user's device.",
                Severity.LOW, Confidence.TENTATIVE);
    }

    @Override
    protected void evaluatePresent(ResponseHeaders headers, List<String> values,
                                   EvaluationContext context, List<Finding> out) {
        String raw = headers.combined(HEADER);
        List<String> unquoted = new ArrayList<>();
        List<String> unknown = new ArrayList<>();
        List<String> directives = new ArrayList<>();
        for (String member : headers.listMembers(HEADER)) {
            String value = HeaderSyntax.unquote(member);
            if (value == null) {
                unquoted.add(member);
            } else if (!VALID_DIRECTIVES.contains(value)) {
                unknown.add(member);
            } else {
                directives.add(value);
            }
        }
        if (!unquoted.isEmpty()) {
            out.add(finding(FindingType.INVALID, "Clear-Site-Data directives are not quoted", raw,
                    "The directives " + unquoted + " are not double-quoted strings. Browsers ignore unquoted "
                            + "directives, so the corresponding data is not cleared.",
                    Severity.LOW, Confidence.CERTAIN).withSummary("directives " + unquoted + " are not quoted; browsers ignore them"));
        }
        if (!unknown.isEmpty()) {
            out.add(finding(FindingType.INVALID, "Clear-Site-Data contains unknown directives", raw,
                    "The directives " + unknown + " are not recognised and will be ignored.",
                    Severity.INFORMATION, Confidence.CERTAIN).withSummary("unknown directives " + unknown + "; browsers ignore them"));
        }
        if (!context.secure()) {
            out.add(finding(FindingType.INVALID, "Clear-Site-Data sent over HTTP", raw,
                    "Clear-Site-Data is only processed in secure contexts. This response was received over HTTP, "
                            + "so browsers ignore the header.",
                    Severity.LOW, Confidence.CERTAIN).withSummary("sent over HTTP; browsers only honour it over HTTPS"));
        }
        if (context.urlType() != UrlClassifier.UrlType.LOGOUT || directives.contains("*")) {
            return;
        }
        if (!directives.contains("cookies")) {
            out.add(finding(FindingType.WEAK, "Clear-Site-Data on logout does not clear cookies", raw,
                    "The logout response clears " + (directives.isEmpty() ? "nothing" : directives)
                            + " but not \"cookies\". Session and tracking cookies remain in the browser after "
                            + "logout unless they are expired explicitly.",
                    Severity.LOW, Confidence.TENTATIVE).withSummary("logout does not clear \"cookies\"; session cookies stay in the browser"));
        }
        List<String> notCleared = new ArrayList<>();
        for (String d : List.of("storage", "cache")) {
            if (!directives.contains(d)) {
                notCleared.add(d);
            }
        }
        if (!notCleared.isEmpty() && directives.contains("cookies")) {
            out.add(finding(FindingType.WEAK, "Clear-Site-Data on logout is incomplete", raw,
                    "The logout response does not clear " + notCleared + ". Client-side storage or cached "
                            + "authenticated pages may remain available after logout.",
                    Severity.INFORMATION, Confidence.TENTATIVE).withSummary("logout does not clear " + notCleared + "; that data may stay in the browser"));
        }
    }
}
