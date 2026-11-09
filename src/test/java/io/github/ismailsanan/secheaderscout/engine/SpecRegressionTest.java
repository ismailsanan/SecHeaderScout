package io.github.ismailsanan.secheaderscout.engine;

import io.github.ismailsanan.secheaderscout.engine.rules.ContentSecurityPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CrossOriginOpenerPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CrossOriginResourcePolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.FrameOptionsRule;
import io.github.ismailsanan.secheaderscout.engine.rules.PermissionsPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.StrictTransportSecurityRule;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static io.github.ismailsanan.secheaderscout.engine.RuleTestSupport.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Regression tests for spec-conformance fixes in the rules (one nested class per header). */
class SpecRegressionTest {

    @Nested
    class Corp {
        final HeaderRule rule = new CrossOriginResourcePolicyRule();

        @ParameterizedTest
        @ValueSource(strings = {"same-origin; x=1", "same-origin;report-to=\"e\"", "Same-Origin", "SAME-SITE",
                "same-origin x"})
        void anythingButAnExactTokenIsInvalid(String value) {
            Finding f = single(eval(rule, AUTH_JSON, "Cross-Origin-Resource-Policy", value), FindingType.INVALID);
            assertSeverity(f, Severity.LOW, Confidence.CERTAIN);
        }

        @Test
        void parametersExplainTheByteForByteComparison() {
            Finding f = single(eval(rule, AUTH_JSON, "Cross-Origin-Resource-Policy", "same-origin; x=1"),
                    FindingType.INVALID);
            assertTrue(f.detail().contains("byte-for-byte"), f.detail());
        }

        @Test
        void identicalDuplicateLinesAreInvalid() {
            // Fetch "gets" the combined value "same-origin, same-origin", which matches nothing
            single(eval(rule, AUTH_JSON, "Cross-Origin-Resource-Policy", "same-origin",
                    "Cross-Origin-Resource-Policy", "same-origin"), FindingType.INVALID);
        }

        @ParameterizedTest
        @ValueSource(strings = {"same-origin", "same-site", "cross-origin"})
        void exactTokensAreClean(String value) {
            assertNone(eval(rule, NON_HTML, "Cross-Origin-Resource-Policy", value));
        }

        @Test
        void expectedTokensAreListedInSortedOrder() {
            Finding f = single(eval(rule, NON_HTML, "Cross-Origin-Resource-Policy", "bogus"), FindingType.INVALID);
            assertTrue(f.detail().contains("cross-origin, same-origin, same-site"), f.detail());
        }
    }

    @Test
    void coopExpectedTokensAreListedInSortedOrder() {
        Finding f = single(eval(new CrossOriginOpenerPolicyRule(), HTML, "Cross-Origin-Opener-Policy", "bogus"),
                FindingType.INVALID);
        assertTrue(f.detail().contains("noopener-allow-popups, same-origin, same-origin-allow-popups, unsafe-none"),
                f.detail());
    }

    @Nested
    class Hsts {
        final HeaderRule rule = new StrictTransportSecurityRule();

        @ParameterizedTest
        @ValueSource(strings = {"max-age=-1", "max-age=+31536000", "max-age=1.5", "max-age=\"-1\"", "max-age=",
                "max-age=\"\"", "max-age=1e9", "max-age= 31536000x"})
        void nonDigitMaxAgeIsInvalid(String value) {
            List<Finding> f = eval(rule, HTML, "Strict-Transport-Security", value + "; includeSubDomains");
            Finding invalid = single(f, FindingType.INVALID);
            assertEquals("Strict-Transport-Security header has invalid max-age", invalid.issueName());
            assertTrue(invalid.detail().contains("delta-seconds"), invalid.detail());
            assertTrue(f.stream().noneMatch(x -> x.type() == FindingType.WEAK), f.toString());
        }

        @Test
        void hugeMaxAgeIsAVeryLongPolicyNotAnError() {
            assertNone(eval(rule, HTML, "Strict-Transport-Security",
                    "max-age=99999999999999999999999999; includeSubDomains"));
            assertNone(eval(rule, HTML, "Strict-Transport-Security",
                    "max-age=\"99999999999999999999999999\"; includeSubDomains"));
        }

        @Test
        void quotedZeroStillDisables() {
            Finding f = single(eval(rule, HTML, "Strict-Transport-Security", "max-age=\"0\""), FindingType.WEAK);
            assertEquals("Strict-Transport-Security disabled by max-age=0", f.issueName());
        }
    }

    @Nested
    class FrameOptions {
        final HeaderRule rule = new FrameOptionsRule();

        @Test
        void conflictContainingAKnownValueBlocksFraming() {
            Finding f = single(eval(rule, HTML, "X-Frame-Options", "DENY", "X-Frame-Options", "SAMEORIGIN"),
                    FindingType.CONFLICT);
            assertSeverity(f, Severity.INFORMATION, Confidence.FIRM);
            assertTrue(f.detail().contains("block all framing"), f.detail());
        }

        @Test
        void allowAllCountsAsAKnownValue() {
            single(eval(rule, HTML, "X-Frame-Options", "ALLOWALL, foo"), FindingType.CONFLICT);
        }

        @Test
        void severalUnknownValuesAreInvalidAndAllowFraming() {
            List<Finding> f = eval(rule, HTML, "X-Frame-Options", "foo", "X-Frame-Options", "bar");
            Finding invalid = single(f, FindingType.INVALID);
            assertSeverity(invalid, Severity.LOW, Confidence.CERTAIN);
            assertTrue(invalid.detail().contains("any site can frame"), invalid.detail());
            assertTrue(f.stream().noneMatch(x -> x.type() == FindingType.CONFLICT), f.toString());
        }

        @Test
        void frameAncestorsInALaterCommaSeparatedPolicyStillWins() {
            assertNone(eval(rule, HTML, "Content-Security-Policy", "default-src 'self', frame-ancestors 'none'",
                    "X-Frame-Options", "ALLOW-FROM https://a.example"));
        }
    }

    @Nested
    class Csp {
        final HeaderRule rule = new ContentSecurityPolicyRule();

        @Test
        void commaSeparatedPoliciesAreEvaluatedSeparately() {
            // two enforced policies; the first blocks wildcards, so the second's '*' is covered.
            // Parsed as one policy, '*' would look like a source of the first script-src.
            assertNone(eval(rule, HTML, "Content-Security-Policy", "script-src 'self', script-src *"));
        }

        @Test
        void secondPolicyIsNotSwallowedIntoTheFirstDirective() {
            // parsed as one policy, script-src would be part of frame-ancestors' value
            List<Finding> f = eval(rule, HTML, "Content-Security-Policy",
                    "frame-ancestors 'none', script-src 'self'");
            assertTrue(f.stream().noneMatch(x -> x.issueName().equals("Content-Security-Policy does not restrict scripts")),
                    f.toString());
        }
    }

    @Nested
    class Permissions {
        final HeaderRule rule = new PermissionsPolicyRule();

        @ParameterizedTest
        @ValueSource(strings = {"camera=() ,microphone=()", "camera=()\t,\tmicrophone=()", " camera=() ",
                "\tcamera=()\t", "geolocation=(\"https://a.example/?x=1\")", "camera=( self  \"https://a\" )",
                "camera=();report-to=\"a)b\""})
        void validDictionariesProduceNoFinding(String value) {
            assertNone(eval(rule, HTML, "Permissions-Policy", value));
        }

        @Test
        void quotedParameterContainingParenDoesNotHideAWildcard() {
            Finding f = single(eval(rule, HTML, "Permissions-Policy", "camera=*;report-to=\"a)b\""),
                    FindingType.WEAK);
            assertTrue(f.detail().contains("camera"), f.detail());
        }

        @ParameterizedTest
        @ValueSource(strings = {"camera", "camera=none", "camera=(self;x=1)", "camera=(\"self\")", "camera=?1"})
        void unrecognisedEntriesAreInformationalNotFatal(String value) {
            List<Finding> f = eval(rule, HTML, "Permissions-Policy", value + ", microphone=()");
            Finding info = single(f, FindingType.INVALID);
            assertEquals("Permissions-Policy contains unrecognised allowlist entries", info.issueName());
            assertSeverity(info, Severity.INFORMATION, Confidence.CERTAIN);
            assertTrue(info.detail().contains("camera"), info.detail());
            assertFalse(info.detail().contains("microphone"), info.detail());
            assertTrue(info.detail().contains("rest of the policy still applies"), info.detail());
        }

        @Test
        void unrecognisedEntryDoesNotHideAWildcardElsewhere() {
            List<Finding> f = eval(rule, HTML, "Permissions-Policy", "camera=none, microphone=*");
            single(f, FindingType.INVALID);
            single(f, FindingType.WEAK);
        }

        @Test
        void fatalSyntaxErrorStillDropsTheWholePolicy() {
            Finding f = single(eval(rule, HTML, "Permissions-Policy", "camera=(), microphone=('self')"),
                    FindingType.INVALID);
            assertEquals("Permissions-Policy header has invalid syntax", f.issueName());
            assertSeverity(f, Severity.LOW, Confidence.CERTAIN);
        }

        @Test
        void featurePolicyDetailDoesNotClaimItIsAlwaysIgnored() {
            Finding f = single(eval(rule, HTML, "Permissions-Policy", "camera=()", "Feature-Policy", "camera 'none'"),
                    FindingType.DEPRECATED);
            assertFalse(f.detail().contains("whenever"), f.detail());
            assertTrue(f.detail().contains("may still apply Feature-Policy"), f.detail());
        }
    }
}
