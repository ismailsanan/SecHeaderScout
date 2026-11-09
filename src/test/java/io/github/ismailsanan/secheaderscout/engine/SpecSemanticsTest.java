package io.github.ismailsanan.secheaderscout.engine;

import io.github.ismailsanan.secheaderscout.definitions.DefinitionsRepository;
import io.github.ismailsanan.secheaderscout.engine.rules.ClearSiteDataRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CrossOriginEmbedderPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CrossOriginOpenerPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.CrossOriginResourcePolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.DnsPrefetchControlRule;
import io.github.ismailsanan.secheaderscout.engine.rules.PermissionsPolicyRule;
import io.github.ismailsanan.secheaderscout.engine.rules.PermittedCrossDomainPoliciesRule;
import io.github.ismailsanan.secheaderscout.engine.rules.ReferrerPolicyRule;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static io.github.ismailsanan.secheaderscout.engine.RuleTestSupport.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Spec-semantics, negative and boundary tests for the header rules (HE-3..HE-7). */
class SpecSemanticsTest {

    // ------------------------------------------------- structured-field items (HE-4)

    /** RFC 8941 item headers. CORP is not one: Fetch compares it byte-for-byte (see SpecRegressionTest). */
    static Stream<Arguments> structuredFieldRules() {
        return Stream.of(
                Arguments.of(new CrossOriginOpenerPolicyRule(), "same-origin"),
                Arguments.of(new CrossOriginEmbedderPolicyRule(), "unsafe-none"));
    }

    /** Every single-value cross-origin header, structured item or exact match. */
    static Stream<Arguments> singleValueRules() {
        return Stream.concat(structuredFieldRules(),
                Stream.of(Arguments.of(new CrossOriginResourcePolicyRule(), "same-origin")));
    }

    @ParameterizedTest
    @MethodSource("structuredFieldRules")
    void structuredTokensAreCaseSensitive(HeaderRule rule, String token) {
        Finding f = single(eval(rule, HTML, rule.header(), token.toUpperCase(java.util.Locale.ROOT)),
                FindingType.INVALID);
        assertSeverity(f, Severity.LOW, Confidence.FIRM);
    }

    @ParameterizedTest
    @MethodSource("structuredFieldRules")
    void parametersAreAllowedIncludingQuotedCommas(HeaderRule rule, String token) {
        assertNone(eval(rule, HTML, rule.header(), token + "; report-to=\"endpoint,a\""));
        assertNone(eval(rule, HTML, rule.header(), token + ";report-to=\"e\""));
    }

    @ParameterizedTest
    @MethodSource("singleValueRules")
    void listsAreInvalidEvenWhenOnOneLine(HeaderRule rule, String token) {
        single(eval(rule, HTML, rule.header(), token + ", " + token), FindingType.INVALID);
    }

    @ParameterizedTest
    @MethodSource("singleValueRules")
    void quotedStringIsNotAToken(HeaderRule rule, String token) {
        single(eval(rule, HTML, rule.header(), "\"" + token + "\""), FindingType.INVALID);
    }

    @ParameterizedTest
    @MethodSource("singleValueRules")
    void emptyValueIsInvalidNotClean(HeaderRule rule, String token) {
        single(eval(rule, HTML, rule.header(), ""), FindingType.INVALID);
    }

    @ParameterizedTest
    @MethodSource("singleValueRules")
    void trailingCommaMakesStructuredItemInvalid(HeaderRule rule, String token) {
        single(eval(rule, HTML, rule.header(), token + ","), FindingType.INVALID);
    }

    // ------------------------------------------------- legitimate alternatives (HE-5)

    @Test
    void coepCredentiallessWithParameterisedCoopIsClean() {
        HeaderRule coep = new CrossOriginEmbedderPolicyRule();
        assertNone(eval(coep, HTML, "Cross-Origin-Embedder-Policy", "credentialless",
                "Cross-Origin-Opener-Policy", "same-origin; report-to=\"coop\""));
    }

    @Test
    void coepWithAllowPopupsCoopIsOnlyAnInformationalConflict() {
        Finding f = single(eval(new CrossOriginEmbedderPolicyRule(), HTML, "Cross-Origin-Embedder-Policy",
                "require-corp", "Cross-Origin-Opener-Policy", "same-origin-allow-popups"), FindingType.CONFLICT);
        assertSeverity(f, Severity.INFORMATION, Confidence.CERTAIN);
        assertTrue(f.detail().contains("same-origin-allow-popups"));
    }

    @Test
    void coepIsNotJudgedOnNonDocuments() {
        assertNone(eval(new CrossOriginEmbedderPolicyRule(), NON_HTML, "Cross-Origin-Embedder-Policy", "require-corp"));
    }

    @Test
    void coopUnsafeNoneOnNonDocumentIsNotReported() {
        assertNone(eval(new CrossOriginOpenerPolicyRule(), NON_HTML, "Cross-Origin-Opener-Policy", "unsafe-none"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"by-ftp-filename", "none-this-response", "Master-Only"})
    void crossDomainMetaPoliciesAreNotReported(String v) {
        assertNone(eval(new PermittedCrossDomainPoliciesRule(), HTML, "X-Permitted-Cross-Domain-Policies", v));
    }

    @Test
    void crossDomainUnknownValueIsInvalid() {
        single(eval(new PermittedCrossDomainPoliciesRule(), HTML, "X-Permitted-Cross-Domain-Policies", "some"),
                FindingType.INVALID);
    }

    @Test
    void dnsPrefetchOffOverHttpIsClean() {
        assertNone(eval(new DnsPrefetchControlRule(), HTML_HTTP, "X-DNS-Prefetch-Control", "off"));
    }

    @Test
    void corpSameOriginOnCredentialedResponseIsClean() {
        assertNone(eval(new CrossOriginResourcePolicyRule(), AUTH_JSON, "Cross-Origin-Resource-Policy", "same-origin"));
    }

    // ------------------------------------------------- Referrer-Policy

    @Test
    void identicalReferrerPolicyLinesAreNotAConflict() {
        assertNone(eval(new ReferrerPolicyRule(), HTML, "Referrer-Policy", "no-referrer",
                "Referrer-Policy", "no-referrer"));
    }

    @Test
    void fallbackListOnOneLineIsNotAConflict() {
        assertNone(eval(new ReferrerPolicyRule(), HTML, "Referrer-Policy", "no-referrer, strict-origin-when-cross-origin"));
    }

    @Test
    void unknownTokenAfterUnsafePolicyDoesNotHideIt() {
        // unknown tokens are skipped; the last *recognised* token still wins
        single(eval(new ReferrerPolicyRule(), HTML, "Referrer-Policy", "unsafe-url, future-policy"), FindingType.WEAK);
    }

    @Test
    void lastLineDecidesAcrossSeparateFieldLines() {
        List<Finding> f = eval(new ReferrerPolicyRule(), HTML, "Referrer-Policy", "unsafe-url",
                "Referrer-Policy", "no-referrer");
        single(f, FindingType.CONFLICT);
        assertTrue(f.stream().noneMatch(x -> x.type() == FindingType.WEAK), f.toString());
    }

    @Test
    void referrerPolicyIsNotExpectedOnNonDocuments() {
        assertNone(eval(new ReferrerPolicyRule(), NON_HTML));
    }

    @Test
    void emptyReferrerPolicyIsInvalid() {
        single(eval(new ReferrerPolicyRule(), HTML, "Referrer-Policy", ""), FindingType.INVALID);
    }

    // ------------------------------------------------- Permissions-Policy (RFC 8941 dictionary)

    @ParameterizedTest
    @ValueSource(strings = {
            "geolocation=(self \"https://maps.example\")",
            "camera=( )",
            "camera=();report-to=pp",
            "camera=(), microphone=(self);report-to=pp",
            "fullscreen=*, autoplay=(*)",
            "camera=self"})
    void validPermissionsPoliciesProduceNoFinding(String value) {
        assertNone(eval(new PermissionsPolicyRule(), HTML, "Permissions-Policy", value));
    }

    @Test
    void wildcardInsideInnerListIsWeak() {
        Finding f = single(eval(new PermissionsPolicyRule(), HTML, "Permissions-Policy", "microphone=(self *)"),
                FindingType.WEAK);
        assertTrue(f.detail().contains("microphone"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"Camera=()", "camera=(\"https://a\"", "camera=", "=()", "camera=('self')"})
    void malformedPermissionsPoliciesAreInvalid(String value) {
        single(eval(new PermissionsPolicyRule(), HTML, "Permissions-Policy", value), FindingType.INVALID);
    }

    @ParameterizedTest
    @ValueSource(strings = {"camera = ()", "camera= ()", "camera=(),", "camera=(), , microphone=()"})
    void rfc8941SyntaxErrorsMakeTheWholePolicyInvalid(String value) {
        single(eval(new PermissionsPolicyRule(), HTML, "Permissions-Policy", value), FindingType.INVALID);
    }

    @Test
    void featurePolicyAlongsidePermissionsPolicyIsOnlyDeprecated() {
        List<Finding> f = eval(new PermissionsPolicyRule(), HTML, "Permissions-Policy", "camera=()",
                "Feature-Policy", "camera 'none'");
        assertEquals(1, f.size(), f.toString());
        assertEquals(FindingType.DEPRECATED, f.get(0).type());
    }

    @Test
    void permissionsPolicyIsNotExpectedOnNonDocuments() {
        assertNone(eval(new PermissionsPolicyRule(), NON_HTML));
    }

    // ------------------------------------------------- Clear-Site-Data

    @Test
    void validClearSiteDataOnNonLogoutPageIsClean() {
        assertNone(eval(new ClearSiteDataRule(), HTML, "Clear-Site-Data", "\"cache\""));
    }

    @Test
    void directivesAreCaseSensitive() {
        Finding f = eval(new ClearSiteDataRule(), HTML, "Clear-Site-Data", "\"Cookies\"").stream()
                .filter(x -> x.issueName().contains("unknown directives")).findFirst().orElseThrow();
        assertSeverity(f, Severity.INFORMATION, Confidence.CERTAIN);
    }

    @Test
    void clearSiteDataOverHttpIsInvalidEvenOffLogout() {
        List<Finding> f = eval(new ClearSiteDataRule(), HTML_HTTP, "Clear-Site-Data", "\"cookies\"");
        assertEquals(List.of("Clear-Site-Data sent over HTTP"), f.stream().map(Finding::issueName).toList());
    }

    @Test
    void quotedCommaIsNotADirectiveSeparator() {
        // one (unknown) quoted directive, not two unquoted fragments
        List<Finding> f = eval(new ClearSiteDataRule(), HTML, "Clear-Site-Data", "\"cache,cookies\"");
        assertTrue(f.stream().noneMatch(x -> x.issueName().contains("not quoted")), f.toString());
        single(f, FindingType.INVALID);
    }

    // ------------------------------------------------- HE-6

    @Test
    void documentOnlyHeadersAreNeverMissingOnNonDocuments() {
        HeaderEvaluator evaluator = new HeaderEvaluator(RuleSets.passiveRules(), (r, e) -> {
            throw e;
        });
        List<String> missing = evaluator.evaluate(ResponseHeaders.empty(),
                        EvaluationContext.of("https://example.com/app.js", true, false, false)).findings().stream()
                .filter(f -> f.type() == FindingType.MISSING).map(Finding::header).toList();
        assertEquals(List.of("Cross-Origin-Resource-Policy", "X-Permitted-Cross-Domain-Policies"), missing);
    }

    // ------------------------------------------------- HE-7 invariants

    private static final String[][] PROBES = {
            {},
            {"Cross-Origin-Opener-Policy", "unsafe-none", "Cross-Origin-Embedder-Policy", "require-corp"},
            {"Cross-Origin-Opener-Policy", "x", "Cross-Origin-Resource-Policy", "cross-origin"},
            {"Referrer-Policy", "unsafe-url", "Referrer-Policy", "no-referrer-when-downgrade"},
            {"Permissions-Policy", "camera=*", "Permissions-Policy", "camera=()", "Feature-Policy", "x 'none'"},
            {"Permissions-Policy", "geolocation 'self'"},
            {"X-DNS-Prefetch-Control", "on", "X-Permitted-Cross-Domain-Policies", "all"},
            {"Clear-Site-Data", "cookies, \"bogus\""},
            {"Strict-Transport-Security", "max-age=10", "Content-Security-Policy", "script-src 'unsafe-inline'"},
            {"X-Frame-Options", "ALLOW-FROM https://a", "X-Content-Type-Options", "sniff"},
            {"Access-Control-Allow-Origin", "*", "Access-Control-Allow-Credentials", "true"},
            {"Cache-Control", "public"},
    };

    @Test
    void everyFindingCarriesTheRequiredFields() {
        List<HeaderRule> rules = new ArrayList<>(RuleSets.passiveRules());
        rules.addAll(RuleSets.manualRules(DefinitionsRepository.fromBundledResource().current().headers()));
        HeaderEvaluator evaluator = new HeaderEvaluator(rules, (r, e) -> {
            throw e;
        });
        int seen = 0;
        for (EvaluationContext ctx : List.of(HTML, HTML_HTTP, NON_HTML, AUTH_JSON, LOGOUT, LOGOUT_HTTP)) {
            for (String[] probe : PROBES) {
                for (Finding f : evaluator.evaluate(ResponseHeaders.of(probe), ctx).findings()) {
                    seen++;
                    String where = ctx.url() + " " + f;
                    assertFalse(f.header().isBlank(), where);
                    assertFalse(f.issueName().isBlank(), where);
                    assertFalse(f.detail().isBlank(), where);
                    assertFalse(f.recommended().isBlank(), where);
                    assertFalse(f.background().isBlank(), where);
                    assertFalse(f.remediation().isBlank(), where);
                    assertNotNull(f.severity(), where);
                    assertNotNull(f.confidence(), where);
                    if (f.type() == FindingType.MISSING) {
                        assertNull(f.observedValue(), where);
                    } else {
                        assertNotNull(f.observedValue(), where);
                    }
                }
            }
        }
        assertTrue(seen > 50, "probe set produced only " + seen + " findings");
    }
}
