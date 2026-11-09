package io.github.ismailsanan.secheaderscout.engine;

import io.github.ismailsanan.secheaderscout.engine.rules.ClearSiteDataRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CrossOriginEmbedderPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CrossOriginOpenerPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CrossOriginResourcePolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.DnsPrefetchControlRule;
import io.github.ismailsanan.secheaderscout.engine.rules.PermissionsPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.PermittedCrossDomainPoliciesRule;
import io.github.ismailsanan.secheaderscout.engine.rules.ReferrerPolicyRule;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static io.github.ismailsanan.secheaderscout.engine.RuleTestSupport.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Tests for the eight passive-scanner rules (FR-2, HE-2..HE-6). */
class PassiveRulesTest {

    @Test
    void passiveRuleSetIsExactlyTheEightHeadersAndExcludesBurpNativeOnes() {
        List<String> headers = RuleSets.passiveRules().stream().map(HeaderRule::header).toList();
        assertEquals(List.of("Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
                "Cross-Origin-Resource-Policy", "Referrer-Policy", "Permissions-Policy", "X-DNS-Prefetch-Control",
                "X-Permitted-Cross-Domain-Policies", "Clear-Site-Data"), headers);
    }

    @Nested
    class Coop {
        final HeaderRule rule = new CrossOriginOpenerPolicyRule();

        @Test
        void missingOnHtmlIsInformational() {
            Finding f = single(eval(rule, HTML), FindingType.MISSING);
            assertSeverity(f, Severity.INFORMATION, Confidence.CERTAIN);
            assertEquals("Cross-Origin-Opener-Policy header not set", f.issueName());
        }

        @Test
        void notExpectedOnNonHtml() {
            assertNone(eval(rule, NON_HTML));
        }

        @ParameterizedTest
        @ValueSource(strings = {"same-origin", "same-origin-allow-popups", "noopener-allow-popups",
                "same-origin; report-to=\"coop\""})
        void legitimateValuesProduceNoFinding(String value) {
            assertNone(eval(rule, HTML, "Cross-Origin-Opener-Policy", value));
        }

        @Test
        void unsafeNoneIsReported() {
            assertSeverity(single(eval(rule, HTML, "Cross-Origin-Opener-Policy", "unsafe-none"), FindingType.WEAK),
                    Severity.INFORMATION, Confidence.CERTAIN);
        }

        @Test
        void invalidTokenIsLow() {
            Finding f = single(eval(rule, HTML, "Cross-Origin-Opener-Policy", "same-site"), FindingType.INVALID);
            assertSeverity(f, Severity.LOW, Confidence.CERTAIN);
            assertEquals("same-site", f.observedValue());
        }

        @Test
        void tokensAreCaseSensitive() {
            assertSeverity(single(eval(rule, HTML, "Cross-Origin-Opener-Policy", "Same-Origin"), FindingType.INVALID),
                    Severity.LOW, Confidence.FIRM);
        }

        @Test
        void duplicateHeadersAreInvalidEvenIfIdentical() {
            single(eval(rule, HTML, "Cross-Origin-Opener-Policy", "same-origin",
                    "cross-origin-opener-policy", "same-origin"), FindingType.INVALID);
        }

        @Test
        void headerNameCaseIsIgnored() {
            assertNone(eval(rule, HTML, "CROSS-ORIGIN-OPENER-POLICY", "same-origin"));
        }
    }

    @Nested
    class Coep {
        final HeaderRule rule = new CrossOriginEmbedderPolicyRule();

        @Test
        void requireCorpWithCoopSameOriginIsClean() {
            assertNone(eval(rule, HTML, "Cross-Origin-Embedder-Policy", "require-corp",
                    "Cross-Origin-Opener-Policy", "same-origin"));
        }

        @Test
        void requireCorpWithoutCoopIsAConflict() {
            Finding f = single(eval(rule, HTML, "Cross-Origin-Embedder-Policy", "credentialless"), FindingType.CONFLICT);
            assertTrue(f.detail().contains("not set"));
        }

        @Test
        void requireCorpWithDuplicatedCoopIsAConflict() {
            single(eval(rule, HTML, "Cross-Origin-Embedder-Policy", "require-corp",
                    "Cross-Origin-Opener-Policy", "same-origin", "Cross-Origin-Opener-Policy", "same-origin"),
                    FindingType.CONFLICT);
        }

        @Test
        void explicitUnsafeNoneIsADeliberateOptOut() {
            assertNone(eval(rule, HTML, "Cross-Origin-Embedder-Policy", "unsafe-none"));
        }

        @Test
        void missingIsInformational() {
            assertSeverity(single(eval(rule, HTML), FindingType.MISSING), Severity.INFORMATION, Confidence.CERTAIN);
        }
    }

    @Nested
    class Corp {
        final HeaderRule rule = new CrossOriginResourcePolicyRule();

        @Test
        void expectedOnEveryResponseType() {
            single(eval(rule, NON_HTML), FindingType.MISSING);
        }

        @Test
        void crossOriginOnPublicAssetIsNotReported() {
            assertNone(eval(rule, NON_HTML, "Cross-Origin-Resource-Policy", "cross-origin"));
        }

        @Test
        void crossOriginOnAuthenticatedResponseIsTentative() {
            assertSeverity(single(eval(rule, AUTH_JSON, "Cross-Origin-Resource-Policy", "cross-origin"),
                    FindingType.WEAK), Severity.INFORMATION, Confidence.TENTATIVE);
        }

        @Test
        void sameSiteIsValid() {
            assertNone(eval(rule, AUTH_JSON, "Cross-Origin-Resource-Policy", "same-site"));
        }
    }

    @Nested
    class Referrer {
        final HeaderRule rule = new ReferrerPolicyRule();

        @ParameterizedTest
        @ValueSource(strings = {"no-referrer", "strict-origin-when-cross-origin", "same-origin", "strict-origin",
                "origin", "origin-when-cross-origin", "unknown-future-token, no-referrer"})
        void safePoliciesProduceNoFinding(String value) {
            assertNone(eval(rule, HTML, "Referrer-Policy", value));
        }

        @Test
        void unsafeUrlIsLow() {
            Finding f = single(eval(rule, HTML, "Referrer-Policy", "unsafe-url"), FindingType.WEAK);
            assertSeverity(f, Severity.LOW, Confidence.CERTAIN);
            assertEquals("Referrer-Policy leaks full URL", f.issueName());
        }

        @Test
        void lastRecognisedTokenWins() {
            // fallback syntax: browsers use the last valid token
            single(eval(rule, HTML, "Referrer-Policy", "no-referrer, unsafe-url"), FindingType.WEAK);
            assertNone(eval(rule, HTML, "Referrer-Policy", "unsafe-url, no-referrer"));
        }

        @Test
        void multipleHeaderLinesAreCombined() {
            List<Finding> f = eval(rule, HTML, "Referrer-Policy", "no-referrer", "Referrer-Policy", "no-referrer-when-downgrade");
            single(f, FindingType.CONFLICT);
            single(f, FindingType.WEAK);
        }

        @Test
        void allInvalidTokensIsInformational() {
            assertSeverity(single(eval(rule, HTML, "Referrer-Policy", "none"), FindingType.INVALID),
                    Severity.INFORMATION, Confidence.CERTAIN);
        }

        @Test
        void missingMentionsBrowserDefault() {
            assertTrue(single(eval(rule, HTML), FindingType.MISSING).detail().contains("strict-origin-when-cross-origin"));
        }
    }

    @Nested
    class Permissions {
        final HeaderRule rule = new PermissionsPolicyRule();

        @Test
        void restrictivePolicyIsClean() {
            assertNone(eval(rule, HTML, "Permissions-Policy", "camera=(), microphone=(), geolocation=(self)"));
        }

        @Test
        void powerfulFeatureForAllOriginsIsLow() {
            Finding f = single(eval(rule, HTML, "Permissions-Policy", "camera=*, fullscreen=*"), FindingType.WEAK);
            assertSeverity(f, Severity.LOW, Confidence.FIRM);
            assertTrue(f.detail().contains("camera"));
            assertTrue(!f.detail().contains("fullscreen"), "non-powerful features are not reported");
        }

        @Test
        void featurePolicySyntaxIsInvalid() {
            assertSeverity(single(eval(rule, HTML, "Permissions-Policy", "geolocation 'none'"), FindingType.INVALID),
                    Severity.LOW, Confidence.CERTAIN);
        }

        @Test
        void duplicateFeatureIsConflict() {
            single(eval(rule, HTML, "Permissions-Policy", "camera=()", "Permissions-Policy", "camera=(self)"),
                    FindingType.CONFLICT);
        }

        @Test
        void deprecatedFeaturePolicyHeaderIsReported() {
            List<Finding> f = eval(rule, HTML, "Feature-Policy", "camera 'none'");
            single(f, FindingType.MISSING);
            assertEquals("Feature-Policy", single(f, FindingType.DEPRECATED).header());
        }

        @Test
        void unknownFeaturesAreIgnored() {
            assertNone(eval(rule, HTML, "Permissions-Policy", "some-future-feature=*"));
        }
    }

    @Nested
    class DnsPrefetch {
        final HeaderRule rule = new DnsPrefetchControlRule();

        @Test
        void offIsClean() {
            assertNone(eval(rule, HTML, "X-DNS-Prefetch-Control", "Off"));
        }

        @Test
        void onIsInformational() {
            assertSeverity(single(eval(rule, HTML, "X-DNS-Prefetch-Control", "on"), FindingType.WEAK),
                    Severity.INFORMATION, Confidence.CERTAIN);
        }

        @Test
        void identicalDuplicatesAreTolerated() {
            assertNone(eval(rule, HTML, "X-DNS-Prefetch-Control", "off", "X-DNS-Prefetch-Control", "off"));
        }

        @Test
        void conflictingDuplicatesAreInvalid() {
            single(eval(rule, HTML, "X-DNS-Prefetch-Control", "off", "X-DNS-Prefetch-Control", "on"), FindingType.INVALID);
        }

        @Test
        void missingDetailDependsOnProtocol() {
            assertTrue(single(eval(rule, HTML_HTTP), FindingType.MISSING).detail().contains("HTTP page"));
        }
    }

    @Nested
    class CrossDomainPolicies {
        final HeaderRule rule = new PermittedCrossDomainPoliciesRule();

        @ParameterizedTest
        @ValueSource(strings = {"none", "master-only", "by-content-type", "NONE"})
        void restrictiveValuesAreClean(String v) {
            assertNone(eval(rule, HTML, "X-Permitted-Cross-Domain-Policies", v));
        }

        @Test
        void allIsLow() {
            assertSeverity(single(eval(rule, HTML, "X-Permitted-Cross-Domain-Policies", "all"), FindingType.WEAK),
                    Severity.LOW, Confidence.FIRM);
        }

        @Test
        void notExpectedOnApiUrls() {
            assertNone(eval(rule, EvaluationContext.of("https://example.com/api/users", true, false, false)));
        }
    }

    @Nested
    class ClearSiteData {
        final HeaderRule rule = new ClearSiteDataRule();

        @Test
        void onlyExpectedOnLogout() {
            assertNone(eval(rule, HTML));
            assertSeverity(single(eval(rule, LOGOUT), FindingType.MISSING), Severity.LOW, Confidence.TENTATIVE);
        }

        @Test
        void completeDirectiveSetIsClean() {
            assertNone(eval(rule, LOGOUT, "Clear-Site-Data", "\"cache\", \"cookies\", \"storage\""));
            assertNone(eval(rule, LOGOUT, "Clear-Site-Data", "\"*\""));
        }

        @Test
        void unquotedDirectivesAreInvalid() {
            List<Finding> f = eval(rule, LOGOUT, "Clear-Site-Data", "cache, cookies, storage");
            Finding invalid = f.stream().filter(x -> x.issueName().contains("not quoted")).findFirst().orElseThrow();
            assertSeverity(invalid, Severity.LOW, Confidence.CERTAIN);
        }

        @Test
        void missingCookiesOnLogoutIsLow() {
            Finding f = single(eval(rule, LOGOUT, "Clear-Site-Data", "\"cache\""), FindingType.WEAK);
            assertTrue(f.issueName().contains("cookies"));
        }

        @Test
        void incompleteButWithCookiesIsInformational() {
            assertSeverity(single(eval(rule, LOGOUT, "Clear-Site-Data", "\"cookies\""), FindingType.WEAK),
                    Severity.INFORMATION, Confidence.TENTATIVE);
        }

        @Test
        void ignoredOverHttp() {
            List<Finding> f = eval(rule, LOGOUT_HTTP, "Clear-Site-Data", "\"*\"");
            assertTrue(f.stream().anyMatch(x -> x.issueName().equals("Clear-Site-Data sent over HTTP")));
        }

        @Test
        void queryStringDoesNotMakeALogoutUrl() {
            assertNone(eval(rule, EvaluationContext.of("https://example.com/home?next=/logout", true, true, true)));
        }
    }
}
