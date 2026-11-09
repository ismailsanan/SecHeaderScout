package io.github.ismailsanan.secheaderscout.engine;

import io.github.ismailsanan.secheaderscout.definitions.HeaderDefinition;
import io.github.ismailsanan.secheaderscout.engine.rules.CacheControlRule;
import io.github.ismailsanan.secheaderscout.engine.rules.ClearSiteDataRule;
import io.github.ismailsanan.secheaderscout.engine.rules.ContentSecurityPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.ContentTypeOptionsRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CorsRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CrossOriginEmbedderPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CrossOriginOpenerPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CrossOriginResourcePolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.DnsPrefetchControlRule;
import io.github.ismailsanan.secheaderscout.engine.rules.FrameOptionsRule;
import io.github.ismailsanan.secheaderscout.engine.rules.GenericPresenceRule;
import io.github.ismailsanan.secheaderscout.engine.rules.PermissionsPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.PermittedCrossDomainPoliciesRule;
import io.github.ismailsanan.secheaderscout.engine.rules.ReferrerPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.StrictTransportSecurityRule;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Builds the rule sets for the passive scanner and the manual scanner. */
public final class RuleSets {

    private RuleSets() {
    }

    /**
     * The eight headers the Burp passive scan check covers. CSP, HSTS,
     * X-Frame-Options, CORS and caching are deliberately excluded because Burp's
     * built-in passive scanner already reports them.
     */
    public static List<HeaderRule> passiveRules() {
        return List.of(
                new CrossOriginOpenerPolicyRule(),
                new CrossOriginEmbedderPolicyRule(),
                new CrossOriginResourcePolicyRule(),
                new ReferrerPolicyRule(),
                new PermissionsPolicyRule(),
                new DnsPrefetchControlRule(),
                new PermittedCrossDomainPoliciesRule(),
                new ClearSiteDataRule());
    }

    /**
     * Every dedicated rule keyed by an OWASP header name (lower-cased). CORS is
     * not keyed here; it is added separately in {@link #manualRules}.
     */
    static Map<String, HeaderRule> allDedicatedRules() {
        Map<String, HeaderRule> rules = new LinkedHashMap<>();
        for (HeaderRule rule : passiveRules()) {
            rules.put(ResponseHeaders.normalize(rule.header()), rule);
        }
        for (HeaderRule rule : List.<HeaderRule>of(
                new ContentSecurityPolicyRule(),
                new StrictTransportSecurityRule(),
                new FrameOptionsRule(),
                new ContentTypeOptionsRule(),
                new CacheControlRule())) {
            rules.put(ResponseHeaders.normalize(rule.header()), rule);
        }
        return rules;
    }

    /**
     * Rules for the manual scanner: one per header in the OWASP definitions
     * (dedicated rule where available, otherwise a presence check), plus CORS.
     */
    public static List<HeaderRule> manualRules(List<HeaderDefinition> definitions) {
        Map<String, HeaderRule> dedicated = allDedicatedRules();
        List<HeaderRule> rules = new ArrayList<>();
        for (HeaderDefinition def : definitions) {
            HeaderRule rule = dedicated.get(ResponseHeaders.normalize(def.name()));
            rules.add(rule != null ? rule : new GenericPresenceRule(def.name(), def.recommendedValue()));
        }
        rules.add(new CorsRule());
        return rules;
    }
}
