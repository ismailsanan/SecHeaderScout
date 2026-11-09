package io.github.ismailsanan.secheaderscout.engine.rules;

import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Construction-time validation of rule configuration (AbstractHeaderRule / SingleTokenRule). */
class SingleTokenRuleConfigTest {

    private static final class Probe extends SingleTokenRule {
        Probe(String header, String background, Set<String> tokens, Mode mode) {
            super(header, background, "r", "rem", tokens, mode);
        }

        @Override
        public boolean expectedOn(EvaluationContext context) {
            return false;
        }

        @Override
        protected void evaluateToken(String token, String raw, ResponseHeaders headers, EvaluationContext context,
                                     List<Finding> out) {
        }
    }

    @Test
    void nullTextsAreRejected() {
        assertThrows(NullPointerException.class, () -> new Probe(null, "b", Set.of("a"), SingleTokenRule.Mode.EXACT));
        assertThrows(NullPointerException.class, () -> new Probe("H", null, Set.of("a"), SingleTokenRule.Mode.EXACT));
        assertThrows(NullPointerException.class, () -> new GenericPresenceRule("H", null));
        assertThrows(NullPointerException.class, () -> new Probe("H", "b", null, SingleTokenRule.Mode.EXACT));
        assertThrows(NullPointerException.class, () -> new Probe("H", "b", Set.of("a"), null));
    }

    @Test
    void upperCaseTokensAreRejectedWhereValuesAreLowerCased() {
        assertThrows(IllegalArgumentException.class,
                () -> new Probe("H", "b", Set.of("on", "Off"), SingleTokenRule.Mode.CASE_INSENSITIVE));
        assertThrows(IllegalArgumentException.class,
                () -> new Probe("H", "b", Set.of("Same-Origin"), SingleTokenRule.Mode.STRUCTURED_ITEM));
        assertDoesNotThrow(() -> new Probe("H", "b", Set.of("Same-Origin"), SingleTokenRule.Mode.EXACT));
    }

    @Test
    void emptyOrBlankTokensAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> new Probe("H", "b", Set.of(), SingleTokenRule.Mode.EXACT));
        assertThrows(IllegalArgumentException.class, () -> new Probe("H", "b", Set.of(" "), SingleTokenRule.Mode.EXACT));
    }

    @Test
    void tokenSetIsDefensivelyCopied() {
        Set<String> tokens = new HashSet<>(Set.of("on"));
        Probe rule = new Probe("H", "b", tokens, SingleTokenRule.Mode.CASE_INSENSITIVE);
        tokens.add("off");
        List<Finding> f = rule.evaluate(ResponseHeaders.of("H", "off"),
                EvaluationContext.of("https://example.com/", true, true, false));
        assertEquals(1, f.size(), f.toString());
        assertTrue(f.get(0).detail().contains("expected one of on)"), f.get(0).detail());
    }
}
