package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.Confidence;
import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.FindingType;
import io.github.ismailsanan.secheaderscout.engine.Severity;
import io.github.ismailsanan.secheaderscout.headers.PermissionsPolicyParser;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Permissions-Policy (and the deprecated Feature-Policy). Reports structured-field
 * syntax errors that make browsers drop the whole policy (LOW), allowlist entries
 * that browsers ignore for one feature while the rest of the policy still applies
 * (INFORMATION), duplicate features, and powerful features delegated to every
 * origin. Unknown feature names are not reported: browsers ignore them and new
 * features appear regularly.
 */
public final class PermissionsPolicyRule extends AbstractHeaderRule {

    public static final String HEADER = "Permissions-Policy";
    public static final String LEGACY_HEADER = "Feature-Policy";

    /** Features that grant access to sensitive device capabilities or user data. */
    static final Set<String> POWERFUL_FEATURES = Set.of(
            "camera", "microphone", "geolocation", "display-capture", "payment", "usb", "serial", "hid",
            "bluetooth", "clipboard-read", "publickey-credentials-get", "publickey-credentials-create",
            "otp-credentials", "identity-credentials-get", "midi", "xr-spatial-tracking", "local-fonts",
            "screen-wake-lock", "window-management");

    public PermissionsPolicyRule() {
        super(HEADER,
                "Permissions-Policy controls which browser features (camera, microphone, geolocation, payment and "
                        + "so on) the document, and any frames it embeds, may use. Without it, every feature keeps its "
                        + "browser default: same-origin frames can use it, and a cross-origin frame can use it if the "
                        + "embedding page delegates it with an iframe 'allow' attribute. An explicit policy limits "
                        + "the damage an XSS or a compromised third-party frame can do.",
                "camera=(), microphone=(), geolocation=(), payment=(), usb=() (deny every feature the "
                        + "application does not use)",
                "Send a Permissions-Policy that disables every feature the application does not use, e.g. "
                        + "'camera=(), microphone=(), geolocation=()'. Grant features only to specific origins, "
                        + "such as 'geolocation=(self \"https://maps.example\")', never to '*'. Remove the "
                        + "deprecated Feature-Policy header.");
    }

    @Override
    public boolean expectedOn(EvaluationContext context) {
        return context.htmlDocument();
    }

    @Override
    public List<Finding> evaluate(ResponseHeaders headers, EvaluationContext context) {
        List<Finding> out = new ArrayList<>(super.evaluate(headers, context));
        if (headers.has(LEGACY_HEADER)) {
            out.add(new Finding(LEGACY_HEADER, FindingType.DEPRECATED, "Deprecated Feature-Policy header in use",
                    headers.combined(LEGACY_HEADER), recommended(),
                    "The response sends the deprecated Feature-Policy header. Chromium-based browsers use "
                            + "Permissions-Policy for the features it declares and may still apply Feature-Policy "
                            + "to other features, but support for Feature-Policy is being removed, so this policy "
                            + "may not be enforced.",
                    background(),
                    "Migrate the policy to the Permissions-Policy syntax and remove Feature-Policy.",
                    Severity.INFORMATION, Confidence.CERTAIN));
        }
        return out;
    }

    @Override
    protected void evaluatePresent(ResponseHeaders headers, List<String> values,
                                   EvaluationContext context, List<Finding> out) {
        String raw = headers.combined(HEADER);
        PermissionsPolicyParser.Result parsed = PermissionsPolicyParser.parse(raw);
        if (!parsed.valid()) {
            out.add(finding(FindingType.INVALID, "Permissions-Policy header has invalid syntax", raw,
                    "The Permissions-Policy value cannot be parsed as an RFC 8941 structured-field "
                            + "dictionary (" + parsed.error() + "). Browsers discard a header that fails to parse, "
                            + "so none of its restrictions apply.",
                    Severity.LOW, Confidence.CERTAIN));
            return;
        }
        if (parsed.hasUnrecognisedEntries()) {
            // Reported, but only as INFORMATION: the dictionary is valid, so browsers apply the rest of the
            // policy and ignore just these entries. The author probably meant a restriction (e.g.
            // 'camera=none' or a bare 'camera' for "deny"), and what the feature ends up with differs from
            // what was written, so it is worth surfacing without claiming the whole policy is lost.
            List<String> described = new ArrayList<>();
            for (Map.Entry<String, List<String>> e : parsed.unrecognisedEntries().entrySet()) {
                described.add(e.getKey() + ": " + String.join(" ", e.getValue()));
            }
            out.add(finding(FindingType.INVALID, "Permissions-Policy contains unrecognised allowlist entries", raw,
                    "The allowlists of " + parsed.unrecognisedEntries().keySet() + " contain entries that are not "
                            + "'*', 'self', 'src' or a quoted origin (" + String.join("; ", described) + "). "
                            + "Browsers ignore these entries for the affected features only; the rest of the "
                            + "policy still applies. Write a denied feature as 'feature=()' and allowed origins as "
                            + "'feature=(self \"https://origin.example\")'.",
                    Severity.INFORMATION, Confidence.CERTAIN));
        }
        if (!parsed.duplicates().isEmpty()) {
            out.add(finding(FindingType.CONFLICT, "Permissions-Policy declares features more than once", raw,
                    "The features " + parsed.duplicates() + " are declared more than once. Only the last "
                            + "declaration of each takes effect, which can silently undo an earlier restriction.",
                    Severity.INFORMATION, Confidence.CERTAIN));
        }
        List<String> openToAll = new ArrayList<>();
        for (Map.Entry<String, PermissionsPolicyParser.Allowlist> e : parsed.features().entrySet()) {
            if (POWERFUL_FEATURES.contains(e.getKey()) && e.getValue().allowsAllOrigins()) {
                openToAll.add(e.getKey());
            }
        }
        if (!openToAll.isEmpty()) {
            out.add(finding(FindingType.WEAK, "Permissions-Policy grants powerful features to all origins", raw,
                    "The policy allows " + openToAll + " for every origin ('*'). Any cross-origin frame the "
                            + "page embeds, including compromised third-party or injected frames, can request "
                            + "these capabilities once the embedding page delegates them.",
                    Severity.LOW, Confidence.FIRM));
        }
    }
}
