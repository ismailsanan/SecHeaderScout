package io.github.ismailsanan.secheaderscout.scanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import io.github.ismailsanan.secheaderscout.burp.BurpMessages;
import io.github.ismailsanan.secheaderscout.engine.Finding;
import io.github.ismailsanan.secheaderscout.engine.HeaderEvaluator;
import io.github.ismailsanan.secheaderscout.model.ResponseSnapshot;
import io.github.ismailsanan.secheaderscout.util.Log;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Burp passive scan check for the security headers that Burp's built-in
 * scanner does not cover: COOP, COEP, CORP, Referrer-Policy,
 * Permissions-Policy, X-DNS-Prefetch-Control, X-Permitted-Cross-Domain-Policies
 * and Clear-Site-Data.
 *
 * <p><b>No network activity:</b> this class has no access to Burp's HTTP API.
 * It only inspects the request/response Burp passes in.</p>
 *
 * <p><b>De-duplication:</b>
 * <ul>
 *     <li>"header not set" findings for site-wide headers are reported once per
 *         origin (scheme, host and port); otherwise every URL of a site would get the
 *         same informational issue,</li>
 *     <li>all other findings are reported per URL, and {@link #consolidateIssues}
 *         keeps the existing issue when Burp sees the same issue for the same URL
 *         again.</li>
 * </ul>
 *
 * <p><b>Thread safety:</b> Burp calls {@link #doCheck} concurrently. The
 * evaluator is immutable and the de-duplication set is concurrent.</p>
 */
public final class SecurityHeadersPassiveCheck implements PassiveScanCheck {

    static final String CHECK_NAME = "SecHeaderScout security headers";

    /** Headers whose absence is specific to a URL (logout pages), not to a whole origin. */
    private static final Set<String> URL_SCOPED_MISSING = Set.of("clear-site-data");

    private final HeaderEvaluator evaluator;
    private final Log log;
    private final Set<String> reportedPerOrigin = ConcurrentHashMap.newKeySet();

    public SecurityHeadersPassiveCheck(HeaderEvaluator evaluator, Log log) {
        this.evaluator = Objects.requireNonNull(evaluator);
        this.log = Objects.requireNonNull(log);
    }

    @Override
    public String checkName() {
        return CHECK_NAME;
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
        try {
            return AuditResult.auditResult(findIssues(baseRequestResponse));
        } catch (RuntimeException e) {
            // never propagate into Burp's scanner; an exception here is a bug in this extension
            log.error("Passive check failed for " + Log.redact(safeUrl(baseRequestResponse)), e);
            return AuditResult.auditResult(List.of());
        }
    }

    List<AuditIssue> findIssues(HttpRequestResponse rr) {
        Optional<ResponseSnapshot> analysable = BurpMessages.analysableSnapshot(rr);
        if (analysable.isEmpty()) {
            return List.of(); // no response, or not a status line a browser would apply headers from
        }
        ResponseSnapshot snapshot = analysable.get();
        List<Finding> findings = evaluator.evaluate(snapshot.headers(), snapshot.toContext()).findings();
        if (findings.isEmpty()) {
            return List.of();
        }
        String origin = origin(rr);
        AuditIssueFactory.Evidence evidence = new AuditIssueFactory.Evidence(rr);

        // 1) build every candidate issue first: this may throw, and nothing has been claimed yet
        List<AuditIssue> candidates = new ArrayList<>();
        List<String> originKeys = new ArrayList<>();
        for (Finding finding : findings) {
            boolean perOrigin = finding.type().isMissing()
                    && !URL_SCOPED_MISSING.contains(finding.header().toLowerCase(Locale.ROOT));
            String key = perOrigin ? origin + "|" + finding.issueName() : null;
            if (key != null && reportedPerOrigin.contains(key)) {
                continue; // cheap pre-check; the atomic claim happens below
            }
            candidates.add(AuditIssueFactory.toAuditIssue(finding, evidence, snapshot.url(), perOrigin));
            originKeys.add(key);
        }
        // 2) claim per-origin keys; this cannot throw, so no claim ever needs rolling back
        List<AuditIssue> issues = new ArrayList<>();
        for (int i = 0; i < candidates.size(); i++) {
            String key = originKeys.get(i);
            if (key == null || reportedPerOrigin.add(key)) { // add() is atomic across scanner threads
                issues.add(candidates.get(i));
            }
        }
        return issues;
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
        if (Objects.equals(existingIssue.name(), newIssue.name())
                && Objects.equals(existingIssue.baseUrl(), newIssue.baseUrl())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    /** Forgets per-origin de-duplication state (called on unload). */
    public void reset() {
        reportedPerOrigin.clear();
    }

    int trackedOrigins() {
        return reportedPerOrigin.size();
    }

    private static String origin(HttpRequestResponse rr) {
        var service = rr.request().httpService();
        if (service == null) {
            return "unknown";
        }
        return (service.secure() ? "https://" : "http://") + service.host().toLowerCase(Locale.ROOT) + ":" + service.port();
    }

    private static String safeUrl(HttpRequestResponse rr) {
        try {
            return rr.request().url();
        } catch (RuntimeException e) {
            return "(unknown URL)";
        }
    }
}
