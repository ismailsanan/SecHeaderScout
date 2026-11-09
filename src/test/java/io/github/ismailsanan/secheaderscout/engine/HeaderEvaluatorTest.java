package io.github.ismailsanan.secheaderscout.engine;

import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HeaderEvaluatorTest {

    private static final HeaderRule THROWING = new HeaderRule() {
        @Override
        public String header() {
            return "X-Broken";
        }

        @Override
        public boolean expectedOn(EvaluationContext context) {
            return true;
        }

        @Override
        public List<Finding> evaluate(ResponseHeaders headers, EvaluationContext context) {
            throw new IllegalStateException("bug");
        }
    };

    @Test
    void oneFailingRuleDoesNotSuppressOthers() {
        List<RuntimeException> errors = new ArrayList<>();
        List<HeaderRule> rules = new ArrayList<>(RuleSets.passiveRules());
        rules.add(0, THROWING);
        HeaderEvaluator evaluator = new HeaderEvaluator(rules, (rule, e) -> errors.add(e));

        HeaderEvaluator.Evaluation result = evaluator.evaluate(ResponseHeaders.empty(), RuleTestSupport.HTML);

        assertEquals(1, errors.size());
        assertTrue(result.findings().size() >= 6, "other rules still ran: " + result.findings());
        assertTrue(result.notes().stream().anyMatch(n -> n.contains("X-Broken")));
    }

    @Test
    void evaluatorIsSafeForConcurrentUse() throws Exception {
        HeaderEvaluator evaluator = new HeaderEvaluator(RuleSets.passiveRules(), (r, e) -> {
            throw e;
        });
        ResponseHeaders headers = ResponseHeaders.of("Referrer-Policy", "unsafe-url", "Permissions-Policy", "camera=*");
        int expected = evaluator.evaluate(headers, RuleTestSupport.HTML).findings().size();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int i = 0; i < 400; i++) {
                futures.add(pool.submit(() -> evaluator.evaluate(headers, RuleTestSupport.HTML).findings().size()));
            }
            for (Future<Integer> f : futures) {
                assertEquals(expected, f.get());
            }
        } finally {
            pool.shutdownNow();
        }
    }
}
