package io.github.ismailsanan.secheaderscout.engine;

import io.github.ismailsanan.secheaderscout.engine.UrlClassifier.UrlType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** User-defined endpoint types: parsing, matching, precedence, and their effect on the rules. */
class EndpointRulesTest {

    @AfterEach
    void reset() {
        UrlClassifier.setRules(EndpointRules.DEFAULT); // global: never leak into other tests
    }

    @Test
    void exactPathMatchesAnyHostAndIgnoresQueryAndCase() {
        EndpointRules rules = EndpointRules.DEFAULT.with("/auth/session/destroy", UrlType.LOGOUT);
        assertEquals(Optional.of(UrlType.LOGOUT), rules.typeOf("https://a.example/auth/session/destroy"));
        assertEquals(Optional.of(UrlType.LOGOUT), rules.typeOf("https://b.example/AUTH/Session/Destroy?x=1"));
        assertEquals(Optional.empty(), rules.typeOf("https://a.example/auth/session/destroy/now"));
        assertEquals(Optional.empty(), rules.typeOf("https://a.example/auth/session"));
    }

    @Test
    void prefixMatchesEverythingUnderThePath() {
        EndpointRules rules = EndpointRules.DEFAULT.with("/auth/*", UrlType.LOGIN);
        assertEquals(Optional.of(UrlType.LOGIN), rules.typeOf("https://e/auth/"));
        assertEquals(Optional.of(UrlType.LOGIN), rules.typeOf("https://e/auth/sso/callback"));
        assertEquals(Optional.empty(), rules.typeOf("https://e/authors"));
    }

    @Test
    void fullUrlIsHostSpecificAndCanRequireAQuery() {
        EndpointRules rules = EndpointRules.DEFAULT.with("https://app.example.com/auth?action=logout", UrlType.LOGOUT);
        assertEquals(Optional.of(UrlType.LOGOUT), rules.typeOf("https://app.example.com/auth?action=logout&t=1"));
        assertEquals(Optional.empty(), rules.typeOf("https://app.example.com/auth?action=login"));
        assertEquals(Optional.empty(), rules.typeOf("https://other.example.com/auth?action=logout"));
    }

    @Test
    void theMostSpecificRuleWins() {
        EndpointRules rules = EndpointRules.DEFAULT
                .with("/account/*", UrlType.ADMIN)
                .with("/account/signoff", UrlType.LOGOUT)
                .with("https://special.example/account/*", UrlType.PAYMENT);
        assertEquals(Optional.of(UrlType.LOGOUT), rules.typeOf("https://e/account/signoff"), "exact beats prefix");
        assertEquals(Optional.of(UrlType.ADMIN), rules.typeOf("https://e/account/users"));
        assertEquals(Optional.of(UrlType.PAYMENT), rules.typeOf("https://special.example/account/signoff"),
                "host-specific beats any-host");
    }

    @Test
    void settingThePatternAgainReplacesAndWithoutRemoves() {
        EndpointRules rules = EndpointRules.DEFAULT.with("/x", UrlType.LOGIN).with(" /X ", UrlType.LOGOUT);
        assertEquals(1, rules.customCount());
        assertEquals(Optional.of(UrlType.LOGOUT), rules.typeOf("https://e/x"));
        assertTrue(rules.withoutCustom("/x").customCount() == 0);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "auth/end", "/a b", "/a*/b", "https:///path", "ftp://e/x"})
    void unusablePatternsAreRejectedWithAMessage(String pattern) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> EndpointRules.parse(pattern, UrlType.LOGOUT));
        assertTrue(!e.getMessage().isBlank());
    }

    @Test
    void userRulesOverrideTheKeywordHeuristicBothWays() {
        assertEquals(UrlType.NORMAL, UrlClassifier.classify("https://e/session/destroy"));
        assertEquals(UrlType.LOGOUT, UrlClassifier.classify("https://e/blog/logout-tips"));
        UrlClassifier.setRules(EndpointRules.DEFAULT
                .with("/session/destroy", UrlType.LOGOUT)
                .with("/blog/*", UrlType.NORMAL));
        assertEquals(UrlType.LOGOUT, UrlClassifier.classify("https://e/session/destroy"));
        assertEquals(UrlType.NORMAL, UrlClassifier.classify("https://e/blog/logout-tips"));
        assertEquals(UrlType.LOGIN, UrlClassifier.classify("https://e/login"), "keywords still apply elsewhere");
    }

    @Test
    void aCustomLogoutGetsTheLogoutOnlyClearSiteDataCheck() {
        HeaderRule rule = RuleSets.passiveRules().stream()
                .filter(r -> r.header().equalsIgnoreCase("Clear-Site-Data")).findFirst().orElseThrow();
        String url = "https://e.example/session/destroy";
        assertTrue(!rule.expectedOn(EvaluationContext.of(url, true, true, false)), "not a logout by keywords");

        UrlClassifier.setRules(EndpointRules.DEFAULT.with("/session/destroy", UrlType.LOGOUT));
        assertTrue(rule.expectedOn(EvaluationContext.of(url, true, true, false)));
    }

    @Test
    void builtInKeywordsAreRulesThatCanBeDisabledButNotRemoved() {
        EndpointRules rules = EndpointRules.DEFAULT;
        assertEquals(Optional.of(UrlType.LOGOUT), rules.typeOf("https://e/account/logout"));
        assertEquals(Optional.of(UrlType.API), rules.typeOf("https://e/v2/api"), "*/api suffix");
        assertEquals(Optional.of(UrlType.LOGOUT), rules.typeOf("https://e/api/logout"), "built-in order: logout first");
        EndpointRules off = rules.withEnabled("*/logout*", true, false);
        assertEquals(Optional.of(UrlType.API), off.typeOf("https://e/api/logout"));
        assertEquals(Optional.empty(), off.typeOf("https://e/account/logout"));
        assertEquals(rules.rules().size(), rules.withoutCustom("*/logout*").rules().size());
    }

    @Test
    void containsAndSuffixPatternsWorkForCustomRulesToo() {
        EndpointRules rules = EndpointRules.DEFAULT.with("*/terminate*", UrlType.LOGOUT).with("*/pay", UrlType.PAYMENT);
        assertEquals(Optional.of(UrlType.LOGOUT), rules.typeOf("https://e/user/terminate-session"));
        assertEquals(Optional.of(UrlType.PAYMENT), rules.typeOf("https://e/cart/pay"));
        assertEquals(Optional.empty(), rules.typeOf("https://e/cart/pay/later"));
    }

    @Test
    void customRulesBeatBuiltIns() {
        EndpointRules rules = EndpointRules.DEFAULT.with("/blog/*", UrlType.NORMAL);
        assertEquals(Optional.of(UrlType.NORMAL), rules.typeOf("https://e/blog/logout-tips"));
    }

    @Test
    void serializeRoundTripsCustomAndDisabledRules() {
        EndpointRules rules = EndpointRules.DEFAULT
                .with("https://app.example/auth?action=logout", UrlType.LOGOUT)
                .with("/x/*", UrlType.ADMIN)
                .withEnabled("/x/*", false, false)
                .withEnabled("*/dashboard*", true, false);
        java.util.List<String> warnings = new java.util.ArrayList<>();
        EndpointRules back = EndpointRules.deserialize(rules.serialize(), warnings::add);
        assertEquals(rules.rules(), back.rules());
        assertTrue(warnings.isEmpty(), warnings.toString());
        assertEquals("", EndpointRules.DEFAULT.serialize(), "defaults save nothing");
    }

    @Test
    void deserializeTreatsSavedDataAsUntrusted() {
        java.util.List<String> warnings = new java.util.ArrayList<>();
        String hostile = "C\t1\tLOGOUT\t/ok\n"
                + "C\t1\tNOT_A_TYPE\t/x\n"           // unknown type
                + "C\t1\tLOGOUT\t/a b\n"             // invalid pattern
                + "B\t0\t\t*/not-a-builtin*\n"        // unknown built-in
                + "X\tjunk\n";                         // unknown record
        EndpointRules rules = EndpointRules.deserialize(hostile, warnings::add);
        assertEquals(1, rules.customCount());
        assertEquals(java.util.List.of("Skipped 4 unreadable saved endpoint type(s)."), warnings);

        warnings.clear();
        assertEquals(EndpointRules.DEFAULT.rules(),
                EndpointRules.deserialize("C\t1\tLOGOUT\t/x\n".repeat(60_000), warnings::add).rules());
        assertEquals(1, warnings.size(), "oversized data is rejected as a whole");
        assertEquals(EndpointRules.DEFAULT.rules(), EndpointRules.deserialize(null, warnings::add).rules());
    }

    @Test
    void customRuleCountIsBounded() {
        EndpointRules rules = EndpointRules.DEFAULT;
        for (int i = 0; i < EndpointRules.MAX_CUSTOM_RULES; i++) {
            rules = rules.with("/p" + i, UrlType.ADMIN);
        }
        EndpointRules full = rules;
        assertThrows(IllegalArgumentException.class, () -> full.with("/one-more", UrlType.ADMIN));
        assertEquals(EndpointRules.MAX_CUSTOM_RULES, full.with("/p1", UrlType.LOGIN).customCount(), "replacing is fine");
    }
}
