package io.github.ismailsanan.secheaderscout.engine;

import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/** Shared helpers for rule tests. */
final class RuleTestSupport {

    static final EvaluationContext HTML = EvaluationContext.of("https://example.com/", true, true, false);
    static final EvaluationContext HTML_HTTP = EvaluationContext.of("http://example.com/", false, true, false);
    static final EvaluationContext NON_HTML = EvaluationContext.of("https://example.com/app.js", true, false, false);
    static final EvaluationContext AUTH_JSON = EvaluationContext.of("https://example.com/data", true, false, true);
    static final EvaluationContext LOGOUT = EvaluationContext.of("https://example.com/logout", true, true, true);
    static final EvaluationContext LOGOUT_HTTP = EvaluationContext.of("http://example.com/logout", false, true, true);

    private RuleTestSupport() {
    }

    static List<Finding> eval(HeaderRule rule, EvaluationContext ctx, String... headers) {
        return rule.evaluate(ResponseHeaders.of(headers), ctx);
    }

    static Finding single(List<Finding> findings, FindingType type) {
        List<Finding> matching = findings.stream().filter(f -> f.type() == type).toList();
        if (matching.size() != 1) {
            fail("Expected exactly one " + type + " finding but got " + findings);
        }
        return matching.get(0);
    }

    static void assertNone(List<Finding> findings) {
        assertTrue(findings.isEmpty(), "Expected no findings but got " + findings);
    }

    static void assertSeverity(Finding f, Severity s, Confidence c) {
        assertEquals(s, f.severity(), f.toString());
        assertEquals(c, f.confidence(), f.toString());
    }
}
