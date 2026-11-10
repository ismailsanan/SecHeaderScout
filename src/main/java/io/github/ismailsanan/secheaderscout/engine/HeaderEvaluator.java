package io.github.ismailsanan.secheaderscout.engine;

import io.github.ismailsanan.secheaderscout.headers.ResponseHeaders;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Runs a fixed set of {@link HeaderRule}s against one response. Immutable and
 * thread-safe.
 *
 * <p>Each rule runs in isolation: an unexpected exception in one rule (a
 * programming error) goes to the {@link RuleErrorHandler} and does not stop
 * the remaining rules.</p>
 */
public final class HeaderEvaluator {

    /** Receives unexpected exceptions thrown by a rule. */
    @FunctionalInterface
    public interface RuleErrorHandler {
        void onRuleError(HeaderRule rule, RuntimeException error);
    }

    /**
     * Findings plus transparency notes for one response.
     *
     * @param failedRules headers whose rule threw: the evaluation of those headers is
     *                    incomplete, so "no findings" must not be read as "clean"
     */
    public record Evaluation(List<Finding> findings, List<String> notes, List<String> failedRules) {
        public Evaluation {
            findings = List.copyOf(findings);
            notes = List.copyOf(notes);
            failedRules = List.copyOf(failedRules);
        }

        public boolean complete() {
            return failedRules.isEmpty();
        }
    }

    private final List<HeaderRule> rules;
    private final RuleErrorHandler errorHandler;

    public HeaderEvaluator(List<HeaderRule> rules, RuleErrorHandler errorHandler) {
        this.rules = List.copyOf(rules);
        this.errorHandler = Objects.requireNonNull(errorHandler, "errorHandler");
    }

    public Evaluation evaluate(ResponseHeaders headers, EvaluationContext context) {
        List<Finding> findings = new ArrayList<>();
        List<String> notes = new ArrayList<>();
        List<String> failed = new ArrayList<>();
        for (HeaderRule rule : rules) {
            try {
                findings.addAll(rule.evaluate(headers, context));
                notes.addAll(rule.notes(headers, context));
            } catch (RuntimeException e) {
                errorHandler.onRuleError(rule, e);
                failed.add(rule.header());
                notes.add("Internal error while evaluating " + rule.header()
                        + "; this header was NOT assessed. See the extension error log.");
            }
        }
        return new Evaluation(findings, notes, failed);
    }
}
