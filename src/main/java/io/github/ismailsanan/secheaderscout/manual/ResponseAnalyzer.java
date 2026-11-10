package io.github.ismailsanan.secheaderscout.manual;

import io.github.ismailsanan.secheaderscout.engine.EvaluationContext;
import io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator;
import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;
import io.github.ismailsanan.secheaderscout.model.ScanResult;

import java.util.ArrayList;
import java.util.List;

/** Turns a {@link ResponseSnapshot} into a {@link ScanResult}. Stateless. */
public final class ResponseAnalyzer {

    private ResponseAnalyzer() {
    }

    /** Fallback bookkeeping attached to a quick-scan result. */
    public record Fallback(Integer originalHttpsStatus, String reason) {
    }

    public static ScanResult analyze(String target, ResponseSnapshot snapshot, HeaderEvaluator evaluator,
                                     Fallback fallback) {
        EvaluationContext context = snapshot.toContext();
        HeaderEvaluator.Evaluation evaluation = evaluator.evaluate(snapshot.headers(), context);

        List<String> notes = new ArrayList<>();
        if (fallback != null) {
            notes.add("HTTP fallback: " + fallback.reason() + ". The findings describe the plain-HTTP response, "
                    + "not the HTTPS site.");
        }
        int status = snapshot.statusCode();
        if (status >= 300 && status < 400) {
            String location = snapshot.headers().first("Location").orElse("(no Location header)");
            notes.add("The response is a redirect (" + status + ") to " + location
                    + ". The headers of the redirect response itself were analysed; scan the destination "
                    + "separately to assess it.");
        }
        notes.addAll(evaluation.notes());

        return new ScanResult(target, snapshot.url(), snapshot.method(), status, snapshot.secure(),
                fallback != null,
                fallback == null ? null : fallback.originalHttpsStatus(),
                fallback == null ? null : fallback.reason(),
                null, context.urlType(), evaluation.findings(), notes, snapshot.headers().names(),
                !evaluation.complete());
    }
}
