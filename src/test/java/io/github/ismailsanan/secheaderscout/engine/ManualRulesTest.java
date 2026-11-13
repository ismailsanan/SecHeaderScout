package io.github.ismailsanan.secheaderscout.engine;

import io.github.ismailsanan.secheaderscout.definitions.HeaderDefinition;
import io.github.ismailsanan.secheaderscout.engine.rules.CacheControlRule;
import io.github.ismailsanan.secheaderscout.engine.rules.ContentSecurityPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.ContentTypeOptionsRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CorsRule;
import io.github.ismailsanan.secheaderscout.engine.rules.FrameOptionsRule;
import io.github.ismailsanan.secheaderscout.engine.rules.GenericPresenceRule;
import io.github.ismailsanan.secheaderscout.engine.rules.StrictTransportSecurityRule;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static io.github.ismailsanan.secheaderscout.engine.RuleTestSupport.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ManualRulesTest {

    @Nested
    class Hsts {
        final StrictTransportSecurityRule rule = new StrictTransportSecurityRule();

        @Test
        void neverEvaluatedOverHttp() {
            assertNone(eval(rule, HTML_HTTP));
            assertNone(eval(rule, HTML_HTTP, "Strict-Transport-Security", "max-age=0"));
            assertEquals(1, rule.notes(ResponseHeaders.empty(), HTML_HTTP).size());
        }

        @Test
        void missingOverHttps() {
            single(eval(rule, HTML), FindingType.MISSING);
        }

        @Test
        void shortMaxAgeSummarySaysWhatItIsAndWhatItShouldBe() {
            List<Finding> findings = eval(rule, HTML, "Strict-Transport-Security", "max-age=300; includeSubDomains");
            assertEquals("max-age is 300 (5 minutes), should be at least 31536000 (one year); users can be "
                    + "downgraded to HTTP", single(findings, FindingType.WEAK).summary());
        }

        @Test
        void strongPolicyIsClean() {
            assertNone(eval(rule, HTML, "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"));
            assertNone(eval(rule, HTML, "Strict-Transport-Security", "max-age=\"31536000\";includesubdomains"));
        }

        @Test
        void maxAgeZeroDisables() {
            assertSeverity(single(eval(rule, HTML, "Strict-Transport-Security", "max-age=0"), FindingType.WEAK),
                    Severity.LOW, Confidence.CERTAIN);
        }

        @Test
        void duplicateDirectivesInvalidateHeader() {
            single(eval(rule, HTML, "Strict-Transport-Security", "max-age=1; max-age=31536000"), FindingType.INVALID);
        }

        @Test
        void nonNumericMaxAge() {
            single(eval(rule, HTML, "Strict-Transport-Security", "max-age=abc"), FindingType.INVALID);
        }

        @Test
        void shortMaxAgeAndNoSubdomains() {
            List<Finding> f = eval(rule, HTML, "Strict-Transport-Security", "max-age=86400");
            assertEquals(2, f.size());
        }

        @Test
        void multipleHeadersOnlyFirstProcessed() {
            List<Finding> f = eval(rule, HTML, "Strict-Transport-Security", "max-age=63072000; includeSubDomains",
                    "Strict-Transport-Security", "max-age=0");
            single(f, FindingType.CONFLICT);
            assertTrue(f.stream().noneMatch(x -> x.type() == FindingType.WEAK));
        }
    }

    @Nested
    class Csp {
        final ContentSecurityPolicyRule rule = new ContentSecurityPolicyRule();

        @Test
        void hostWildcardSubdomainIsNotAWildcardSource() {
            assertNone(eval(rule, HTML, "Content-Security-Policy", "default-src 'self' *.example.com"));
        }

        @Test
        void unsafeInlineWithNonceIsIgnoredByBrowsers() {
            assertNone(eval(rule, HTML, "Content-Security-Policy",
                    "script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic' https:; object-src 'none'"));
        }

        @Test
        void unsafeInlineWithoutNonce() {
            assertTrue(eval(rule, HTML, "Content-Security-Policy", "default-src 'self' 'unsafe-inline'").stream()
                    .anyMatch(f -> f.issueName().equals("Content-Security-Policy allows inline scripts")));
        }

        @Test
        void policyWithoutScriptRestriction() {
            single(eval(rule, HTML, "Content-Security-Policy", "frame-ancestors 'none'"), FindingType.WEAK);
        }

        @Test
        void secondStrictPolicyCompensates() {
            assertNone(eval(rule, HTML, "Content-Security-Policy", "script-src *",
                    "Content-Security-Policy", "script-src 'self'"));
        }

        @Test
        void reportOnlyIsNotEnforcement() {
            Finding f = single(eval(rule, HTML, "Content-Security-Policy-Report-Only", "default-src 'self'"),
                    FindingType.MISSING);
            assertTrue(f.issueName().contains("report-only"));
        }

        @Test
        void notExpectedOnApiOrNonHtml() {
            assertNone(eval(rule, NON_HTML));
            assertNone(eval(rule, EvaluationContext.of("https://example.com/api/x", true, true, false)));
        }
    }

    @Nested
    class Xfo {
        final FrameOptionsRule rule = new FrameOptionsRule();

        @Test
        void frameAncestorsMakesXfoUnnecessary() {
            assertNone(eval(rule, HTML, "Content-Security-Policy", "frame-ancestors 'none'"));
            assertNone(eval(rule, HTML, "Content-Security-Policy", "frame-ancestors 'self'", "X-Frame-Options", "ALLOW-FROM x"));
        }

        @Test
        void allowFromIsDeprecated() {
            single(eval(rule, HTML, "X-Frame-Options", "ALLOW-FROM https://a.example"), FindingType.DEPRECATED);
        }

        @Test
        void validValues() {
            assertNone(eval(rule, HTML, "X-Frame-Options", "DENY"));
            assertNone(eval(rule, HTML, "X-Frame-Options", "sameorigin", "X-Frame-Options", "SAMEORIGIN"));
        }

        @Test
        void conflictingValues() {
            single(eval(rule, HTML, "X-Frame-Options", "DENY", "X-Frame-Options", "SAMEORIGIN"), FindingType.CONFLICT);
        }
    }

    @Test
    void xctoOnlyNosniffAndFirstValueCounts() {
        ContentTypeOptionsRule rule = new ContentTypeOptionsRule();
        assertNone(eval(rule, NON_HTML, "X-Content-Type-Options", "NoSniff"));
        single(eval(rule, NON_HTML, "X-Content-Type-Options", "sniff, nosniff"), FindingType.INVALID);
        single(eval(rule, NON_HTML), FindingType.MISSING);
    }

    @Test
    void cacheControlOnlyJudgedOnSensitiveResponses() {
        CacheControlRule rule = new CacheControlRule();
        assertNone(eval(rule, NON_HTML)); // static asset, not sensitive
        assertNone(eval(rule, HTML, "Cache-Control", "public, max-age=3600"));
        single(eval(rule, AUTH_JSON, "Cache-Control", "public, max-age=3600"), FindingType.WEAK);
        assertEquals("lacks the 'no-store' directive; the browser may keep this sensitive response on disk",
                single(eval(rule, AUTH_JSON, "Cache-Control", "private"), FindingType.WEAK).summary());
        assertNone(eval(rule, AUTH_JSON, "Cache-Control", "no-store"));
    }

    @Nested
    class Cors {
        final CorsRule rule = new CorsRule();

        @Test
        void absentCorsIsNeverAFinding() {
            assertNone(eval(rule, AUTH_JSON));
        }

        @Test
        void nullOriginWithCredentialsIsMedium() {
            Finding f = eval(rule, AUTH_JSON, "Access-Control-Allow-Origin", "null",
                    "Access-Control-Allow-Credentials", "true").get(0);
            assertEquals(Severity.MEDIUM, f.severity());
        }

        @Test
        void wildcardWithCredentialsIsConflict() {
            single(eval(rule, AUTH_JSON, "Access-Control-Allow-Origin", "*",
                    "Access-Control-Allow-Credentials", "true"), FindingType.CONFLICT);
        }

        @Test
        void multipleOriginsInvalid() {
            single(eval(rule, AUTH_JSON, "Access-Control-Allow-Origin", "https://a.example",
                    "Access-Control-Allow-Origin", "https://b.example"), FindingType.INVALID);
        }

        @Test
        void maxAgeIsNoLongerReported() {
            assertFalse(eval(rule, AUTH_JSON, "Access-Control-Allow-Origin", "https://a.example",
                    "Access-Control-Max-Age", "999999").stream().anyMatch(f -> f.detail().contains("Max-Age")));
        }
    }

    @Test
    void manualRulesFollowDefinitionsAndFallBackToGenericRule() {
        List<HeaderRule> rules = RuleSets.manualRules(List.of(
                new HeaderDefinition("Referrer-Policy", "no-referrer"),
                new HeaderDefinition("X-Future-Header", "on")));
        assertEquals(3, rules.size()); // 2 definitions + CORS
        assertInstanceOf(GenericPresenceRule.class, rules.get(1));
        assertInstanceOf(CorsRule.class, rules.get(2));
        single(eval(rules.get(1), HTML), FindingType.MISSING);
    }
}
