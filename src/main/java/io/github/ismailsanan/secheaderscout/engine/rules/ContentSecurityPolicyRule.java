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
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Content-Security-Policy, used by the manual scanner only (Burp's native
 * scanner already reports CSP issues). Focuses on script execution, because
 * that is where CSP mitigates XSS. Multiple policies are all enforced, so a
 * weakness is reported only if no enforced policy prevents it. Per CSP3 one
 * field line may itself carry several policies separated by commas, so every
 * field value is split on top-level commas first.
 */
public final class ContentSecurityPolicyRule extends AbstractHeaderRule {

    public static final String HEADER = "Content-Security-Policy";
    public static final String REPORT_ONLY = "Content-Security-Policy-Report-Only";

    public ContentSecurityPolicyRule() {
        super(HEADER,
                "Content-Security-Policy (CSP) limits where scripts and other resources can be loaded from and "
                        + "whether inline script may run. That greatly reduces the impact of cross-site scripting.",
                "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
                "Deploy a CSP that restricts script-src (preferably nonce- or hash-based with 'strict-dynamic'), "
                        + "avoids 'unsafe-inline', 'unsafe-eval' and wildcard sources, and sets object-src 'none' "
                        + "and base-uri 'self'.");
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return context.htmlDocument() && context.urlType() != UrlClassifier.UrlType.API;
    }

    @Override
    protected String missingDetail(EvaluationContext context) {
        return "The HTML document does not enforce a Content-Security-Policy.";
    }

    @Override
    public List<Finding> evaluate(ResponseHeaders headers, EvaluationContext context) {
        if (!headers.has(HEADER) && headers.has(REPORT_ONLY) && expectedOn(context)) {
            return List.of(finding(FindingType.MISSING, "Content-Security-Policy only in report-only mode",
                    headers.combined(REPORT_ONLY),
                    "The document sends Content-Security-Policy-Report-Only but no enforced policy. Report-only "
                            + "policies only report violations; they do not block anything.",
                    Severity.INFORMATION, Confidence.CERTAIN));
        }
        return super.evaluate(headers, context);
    }

    /**
     * The serialized CSP list: every field line split on commas, since each
     * comma-separated element is a separate, independently enforced policy.
     */
    static List<String> policies(List<String> fieldValues) {
        List<String> policies = new ArrayList<>();
        for (String value : fieldValues) {
            policies.addAll(HeaderSyntax.splitTopLevel(value, ','));
        }
        return policies;
    }

    @Override
    protected void evaluatePresent(ResponseHeaders headers, List<String> values,
                                   EvaluationContext context, List<Finding> out) {
        if (!context.htmlDocument()) {
            return; // script-related directives are irrelevant for non-document responses
        }
        boolean anyRestrictsScripts = false;
        boolean anyBlocksInline = false;
        boolean anyBlocksEval = false;
        boolean anyBlocksWildcards = false;
        List<String> duplicates = new ArrayList<>();
        for (String policy : policies(values)) {
            HeaderSyntax.Directives d = HeaderSyntax.parseDirectives(policy, false);
            duplicates.addAll(d.duplicates());
            String scriptSrc = d.has("script-src") ? d.get("script-src") : d.get("default-src");
            if (scriptSrc == null) {
                continue; // this policy does not restrict scripts
            }
            anyRestrictsScripts = true;
            List<String> sources = Arrays.stream(scriptSrc.split("\\s+"))
                    .map(s -> s.toLowerCase(Locale.ROOT)).filter(s -> !s.isEmpty()).toList();
            boolean hasNonceOrHash = sources.stream().anyMatch(s ->
                    s.startsWith("'nonce-") || s.startsWith("'sha256-") || s.startsWith("'sha384-")
                            || s.startsWith("'sha512-"));
            boolean strictDynamic = sources.contains("'strict-dynamic'");
            // 'unsafe-inline' is ignored by browsers when a nonce or hash is present
            if (!sources.contains("'unsafe-inline'") || hasNonceOrHash) {
                anyBlocksInline = true;
            }
            if (!sources.contains("'unsafe-eval'")) {
                anyBlocksEval = true;
            }
            // host/scheme sources are ignored under 'strict-dynamic' with a nonce or hash
            boolean wildcard = sources.stream().anyMatch(s ->
                    s.equals("*") || s.equals("http:") || s.equals("https:") || s.equals("data:"));
            if (!wildcard || (strictDynamic && hasNonceOrHash)) {
                anyBlocksWildcards = true;
            }
        }
        String raw = String.join(" | ", values);
        if (!duplicates.isEmpty()) {
            out.add(finding(FindingType.CONFLICT, "Content-Security-Policy has duplicate directives", raw,
                    "The directives " + duplicates + " appear more than once in a policy. Browsers use the first "
                            + "occurrence and ignore later ones, which may not be what was intended.",
                    Severity.INFORMATION, Confidence.CERTAIN));
        }
        if (!anyRestrictsScripts) {
            out.add(finding(FindingType.WEAK, "Content-Security-Policy does not restrict scripts", raw,
                    "No enforced policy has a script-src or default-src directive, so scripts can be loaded from "
                            + "any origin and the policy gives no XSS protection.",
                    Severity.LOW, Confidence.FIRM));
            return;
        }
        if (!anyBlocksInline) {
            out.add(finding(FindingType.WEAK, "Content-Security-Policy allows inline scripts", raw,
                    "The script policy contains 'unsafe-inline' with no nonce or hash, so injected inline "
                            + "<script> blocks and event handlers will run. This largely defeats CSP as an XSS "
                            + "mitigation.",
                    Severity.LOW, Confidence.FIRM));
        }
        if (!anyBlocksEval) {
            out.add(finding(FindingType.WEAK, "Content-Security-Policy allows eval", raw,
                    "The script policy contains 'unsafe-eval', so string-to-code functions such as eval() and "
                            + "new Function() are allowed. DOM XSS sinks then remain exploitable.",
                    Severity.INFORMATION, Confidence.FIRM));
        }
        if (!anyBlocksWildcards) {
            out.add(finding(FindingType.WEAK, "Content-Security-Policy allows scripts from any origin", raw,
                    "The script policy allows a wildcard or scheme-only source ('*', 'https:', 'http:' or "
                            + "'data:'), so an attacker can load script from a host they control.",
                    Severity.LOW, Confidence.FIRM));
        }
    }
}
